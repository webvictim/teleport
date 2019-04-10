/*
Copyright 2016 Gravitational, Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package reversetunnel

import (
	"context"
	"fmt"
	"net"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/gravitational/teleport"
	"github.com/gravitational/teleport/lib/auth"
	"github.com/gravitational/teleport/lib/defaults"
	"github.com/gravitational/teleport/lib/services"
	"github.com/gravitational/teleport/lib/srv/forward"
	"github.com/gravitational/teleport/lib/utils/proxy"

	"github.com/gravitational/trace"
	log "github.com/sirupsen/logrus"
)

func newlocalSite(srv *server, domainName string, client auth.ClientI) (*localSite, error) {
	accessPoint, err := srv.newAccessPoint(client, []string{"reverse", domainName})
	if err != nil {
		return nil, trace.Wrap(err)
	}

	// instantiate a cache of host certificates for the forwarding server. the
	// certificate cache is created in each site (instead of creating it in
	// reversetunnel.server and passing it along) so that the host certificate
	// is signed by the correct certificate authority.
	certificateCache, err := NewHostCertificateCache(srv.Config.KeyGen, client)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	return &localSite{
		srv:              srv,
		client:           client,
		accessPoint:      accessPoint,
		certificateCache: certificateCache,
		domainName:       domainName,
		remoteConns:      make(map[string]*remoteConn),
		log: log.WithFields(log.Fields{
			trace.Component: teleport.ComponentReverseTunnelServer,
			trace.ComponentFields: map[string]string{
				"cluster": domainName,
			},
		}),
	}, nil
}

// localSite allows to directly access the remote servers
// not using any tunnel, and using standard SSH
//
// it implements RemoteSite interface
type localSite struct {
	sync.Mutex

	authServer  string
	log         *log.Entry
	domainName  string
	connections []*remoteConn
	lastUsed    int
	srv         *server

	// client provides access to the Auth Server API of the local cluster.
	client auth.ClientI
	// accessPoint provides access to a cached subset of the Auth Server API of
	// the local cluster.
	accessPoint auth.AccessPoint

	// certificateCache caches host certificates for the forwarding server.
	certificateCache *certificateCache

	// remoteConns
	remoteConns map[string]*remoteConn

	closeContext context.Context
}

// GetTunnelsCount always returns 1 for local cluster
func (s *localSite) GetTunnelsCount() int {
	return 1
}

func (s *localSite) CachingAccessPoint() (auth.AccessPoint, error) {
	return s.accessPoint, nil
}

func (s *localSite) GetClient() (auth.ClientI, error) {
	return s.client, nil
}

func (s *localSite) String() string {
	return fmt.Sprintf("local(%v)", s.domainName)
}

func (s *localSite) GetStatus() string {
	return teleport.RemoteClusterStatusOnline
}

func (s *localSite) GetName() string {
	return s.domainName
}

func (s *localSite) GetLastConnected() time.Time {
	return time.Now()
}

func (s *localSite) DialAuthServer() (conn net.Conn, err error) {
	// get list of local auth servers
	authServers, err := s.client.GetAuthServers()
	if err != nil {
		return nil, trace.Wrap(err)
	}

	// try and dial to one of them, as soon as we are successful, return the net.Conn
	for _, authServer := range authServers {
		conn, err = net.DialTimeout("tcp", authServer.GetAddr(), defaults.DefaultDialTimeout)
		if err == nil {
			return conn, nil
		}
	}

	// return the last error
	return nil, trace.ConnectionProblem(err, "unable to connect to auth server")
}

func (s *localSite) Dial(params DialParams) (net.Conn, error) {
	err := params.CheckAndSetDefaults()
	if err != nil {
		return nil, trace.Wrap(err)
	}

	// If reverse tunnel use is requested (server heartbeat back indicating
	// that it connected via a reverse tunnel) then build a connection over the
	// reverse tunnel instead of dailing.
	if params.UseTunnel {
		return s.chanTransportConn(params.To.String())
	}

	clusterConfig, err := s.accessPoint.GetClusterConfig()
	if err != nil {
		return nil, trace.Wrap(err)
	}

	// if the proxy is in recording mode use the agent to dial and build a
	// in-memory forwarding server
	if clusterConfig.GetSessionRecording() == services.RecordAtProxy {
		if params.UserAgent == nil {
			return nil, trace.BadParameter("user agent missing")
		}
		return s.dialWithAgent(params)
	}

	return s.DialTCP(params.From, params.To)
}

func (s *localSite) DialTCP(from net.Addr, to net.Addr) (net.Conn, error) {
	s.log.Debugf("Dialing from %v to %v", from, to)

	dialer := proxy.DialerFromEnvironment(to.String())
	return dialer.DialTimeout(to.Network(), to.String(), defaults.DefaultDialTimeout)
}

func (s *localSite) dialWithAgent(params DialParams) (net.Conn, error) {
	s.log.Debugf("Dialing with an agent from %v to %v.", params.From, params.To)

	addr := params.Address
	host, _, err := net.SplitHostPort(params.To.String())
	if err != nil {
		return nil, trace.Wrap(err)
	}

	// Get a host certificate for the forwarding node from the cache.
	hostCertificate, err := s.certificateCache.GetHostCertificate(addr, []string{host})
	if err != nil {
		return nil, trace.Wrap(err)
	}

	// get a net.Conn to the target server
	targetConn, err := net.DialTimeout(params.To.Network(), params.To.String(), defaults.DefaultDialTimeout)
	if err != nil {
		return nil, err
	}

	// create a forwarding server that serves a single ssh connection on it. we
	// don't need to close this server it will close and release all resources
	// once conn is closed.
	serverConfig := forward.ServerConfig{
		AuthClient:      s.client,
		UserAgent:       params.UserAgent,
		TargetConn:      targetConn,
		SrcAddr:         params.From,
		DstAddr:         params.To,
		HostCertificate: hostCertificate,
		Ciphers:         s.srv.Config.Ciphers,
		KEXAlgorithms:   s.srv.Config.KEXAlgorithms,
		MACAlgorithms:   s.srv.Config.MACAlgorithms,
		DataDir:         s.srv.Config.DataDir,
	}
	remoteServer, err := forward.New(serverConfig)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	go remoteServer.Serve()

	// return a connection to the forwarding server
	conn, err := remoteServer.Dial()
	if err != nil {
		return nil, trace.Wrap(err)
	}

	return conn, nil
}

func (s *localSite) addConn(nodeID string, conn net.Conn, sconn ssh.Conn) (*remoteConn, error) {
	s.Lock()
	defer s.Unlock()

	rconn := newRemoteConn(&connConfig{
		conn:        conn,
		sconn:       sconn,
		accessPoint: s.accessPoint,
		tunnelID:    nodeID,
		tunnelType:  string(services.NodeTunnel),
		proxyName:   s.srv.ID,
		clusterName: s.domainName,
	})
	s.remoteConns[nodeID] = rconn

	return rconn, nil
}

func (s *localSite) registerHeartbeat(t time.Time) {
	// Creates a services.TunnelConnection that looks like: e53470b8-91bd-4ab4-a3c4-c2ec290f7d42-example.com
	// where "e53470b8-91bd-4ab4-a3c4-c2ec290f7d42-example.com" is the proxy.
	tunnelConn, err := services.NewTunnelConnection(
		fmt.Sprintf("%v-%v", s.srv.ID, s.domainName),
		services.TunnelConnectionSpecV2{
			Type:          services.NodeTunnel,
			ClusterName:   s.domainName,
			ProxyName:     s.srv.ID,
			LastHeartbeat: time.Now().UTC(),
		},
	)
	tunnelConn.SetLastHeartbeat(t)
	tunnelConn.SetExpiry(time.Now().Add(defaults.ReverseTunnelOfflineThreshold))

	err = s.accessPoint.UpsertTunnelConnection(tunnelConn)
	if err != nil {
		s.log.Warnf("Failed to register heartbeat: %v.", err)
	}
}

func (s *localSite) hasValidConnections() bool {
	s.Lock()
	defer s.Unlock()

	for _, rconn := range s.remoteConns {
		if !rconn.isInvalid() {
			return true
		}
	}
	return false
}

func (s *localSite) deleteConnectionRecord(clusterName string, proxyID string) error {
	err := s.accessPoint.DeleteTunnelConnection(clusterName, proxyID)
	if err != nil {
		return trace.Wrap(err)
	}

	return nil
}

// handleHearbeat receives heartbeat messages from the connected agent
// if the agent has missed several heartbeats in a row, Proxy marks
// the connection as invalid.
func (s *localSite) handleHeartbeat(rconn *remoteConn, ch ssh.Channel, reqC <-chan *ssh.Request) {
	defer func() {
		s.log.Infof("Cluster connection closed.")
		rconn.Close()
	}()

	for {
		select {
		case <-s.srv.ctx.Done():
			s.log.Infof("closing")
			return
		case req := <-reqC:
			if req == nil {
				s.log.Infof("Cluster agent disconnected.")
				rconn.markInvalid(trace.ConnectionProblem(nil, "agent disconnected"))

				if !s.hasValidConnections() {
					err := s.deleteConnectionRecord(s.domainName, s.srv.ID)
					if err != nil {
						s.log.Debugf("Failed to delete connection record: %v.", err)
					}
					s.log.Debugf("Deleted connection record.")
				}
				return
			}
			var timeSent time.Time
			var roundtrip time.Duration
			if req.Payload != nil {
				if err := timeSent.UnmarshalText(req.Payload); err == nil {
					roundtrip = s.srv.Clock.Now().Sub(timeSent)
				}
			}
			if roundtrip != 0 {
				s.log.WithFields(log.Fields{"latency": roundtrip}).Debugf("ping <- %v", rconn.conn.RemoteAddr())
			} else {
				log.Debugf("Ping <- %v.", rconn.conn.RemoteAddr())
			}
			tm := time.Now().UTC()
			rconn.setLastHeartbeat(tm)
			go s.registerHeartbeat(tm)
		// Since we block on select, time.After is re-created everytime we process
		// a request.
		case <-time.After(defaults.ReverseTunnelOfflineThreshold):
			rconn.markInvalid(trace.ConnectionProblem(nil, "no heartbeats for %v", defaults.ReverseTunnelOfflineThreshold))
		}
	}
}

func (s *localSite) chanTransportConn(addr string) (net.Conn, error) {
	s.log.Debugf("Connecting to %v through tunnel.", addr)

	fmt.Printf("--> chanTransportConn: s.remoteConns: %v.\n", s.remoteConns)
	//rconn, ok := s.remoteConns["server03"]
	rconn, ok := s.remoteConns[addr]
	if !ok {
		return nil, trace.BadParameter("no reverse tunnel for %v found", addr)
	}

	channel, err := rconn.OpenChannel(chanTransportNode, nil)
	if err != nil {
		rconn.markInvalid(err)
		return nil, trace.Wrap(err)
	}

	return rconn.ChannelConn(channel), nil
}

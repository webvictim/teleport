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
	"github.com/gravitational/teleport/lib/utils"
	"github.com/gravitational/teleport/lib/utils/proxy"

	"github.com/gravitational/trace"

	"github.com/jonboulle/clockwork"
	"github.com/sirupsen/logrus"
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
		clock:            clockwork.NewRealClock(),
		log: logrus.WithFields(logrus.Fields{
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

	log *logrus.Entry

	authServer  string
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

	remoteConns map[string]*remoteConn

	clock clockwork.Clock
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
	//err := params.CheckAndSetDefaults()
	//if err != nil {
	//	return nil, trace.Wrap(err)
	//}

	//clusterConfig, err := s.accessPoint.GetClusterConfig()
	//if err != nil {
	//	return nil, trace.Wrap(err)
	//}

	//// if the proxy is in recording mode use the agent to dial and build a
	//// in-memory forwarding server
	//if clusterConfig.GetSessionRecording() == services.RecordAtProxy {
	//	if params.UserAgent == nil {
	//		return nil, trace.BadParameter("user agent missing")
	//	}
	//	return s.dialWithAgent(params)
	//}

	//return s.DialTCP(params.From, params.To)
	return s.chanTransportConn("", "")
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

func (s *localSite) handleHeartbeat(conn net.Conn, sconn *ssh.ServerConn, newChannel ssh.NewChannel) {
	nodeID := sconn.Permissions.Extensions[extHost]

	rconn := s.addConn(nodeID, conn, sconn)

	_, reqs, err := newChannel.Accept()
	if err != nil {
		//log.Error(trace.Wrap(err))
		sconn.Close()
		return
	}

	for {
		select {
		case req := <-reqs:
			if req == nil {
				s.log.Infof("Cluster agent for %v disconnected.", rconn.domain)
				rconn.markInvalid(trace.ConnectionProblem(nil, "agent disconnected"))

				// Add back later.
				//if !s.hasValidConnections() {
				//	s.deleteConnectionRecord()
				//}
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
				logrus.WithFields(logrus.Fields{"latency": roundtrip}).Debugf("ping <- %v", rconn.conn.RemoteAddr())
			} else {
				s.log.Debugf("ping <- %v", rconn.conn.RemoteAddr())
			}
			go s.registerHeartbeat(nodeID, time.Now())

			//err := s.accessPoint.UpsertTunnelConnection(connInfo)
			//if err != nil {
			//	fmt.Printf("--> what: %v.\n", err)
			//}
		}
	}

}

func (s *localSite) registerHeartbeat(nodeID string, t time.Time) {
	connInfo, err := services.NewTunnelConnection(
		nodeID,
		services.TunnelConnectionSpecV2{
			ClusterName:   s.domainName,
			ProxyName:     s.srv.ID,
			LastHeartbeat: time.Now().UTC(),
		},
	)
	connInfo.SetLastHeartbeat(t)
	connInfo.SetExpiry(s.clock.Now().Add(defaults.ReverseTunnelOfflineThreshold))

	err = s.accessPoint.UpsertTunnelConnection(connInfo)
	if err != nil {
		s.log.Warnf("Failed to register heartbeat for %v: %v.", nodeID, err)
	}
}

func (s *localSite) addConn(nodeID string, conn net.Conn, sconn ssh.Conn) *remoteConn {
	s.Lock()
	defer s.Unlock()

	rconn := newRemoteConn(conn, sconn, s.accessPoint, nodeID, s.srv.ID)
	s.remoteConns[nodeID] = rconn

	return rconn
}

func (s *localSite) chanTransportConn(transportType string, addr string) (net.Conn, error) {
	rconn, ok := s.remoteConns["foo.example.com"]
	if !ok {
		return nil, trace.BadParameter("what?")
	}

	channel, err := rconn.OpenChannel("teleport-transport-node", nil)
	if err != nil {
		rconn.markInvalid(err)
		return nil, trace.Wrap(err)
	}

	// Send a special SSH out-of-band request called "teleport-transport"
	// the agent on the other side will create a new TCP/IP connection to
	// 'addr' on its network and will start proxying that connection over
	// this SSH channel.
	//var dialed bool
	_, err = channel.SendRequest(transportType, true, []byte(addr))
	if err != nil {
		return nil, trace.Wrap(err)
	}
	//stop = true
	//if !dialed {
	//	defer ch.Close()
	//	// pull the error message from the tunnel client (remote cluster)
	//	// passed to us via stderr:
	//	errMessage, _ := ioutil.ReadAll(ch.Stderr())
	//	if errMessage == nil {
	//		errMessage = []byte("failed connecting to " + addr)
	//	}
	//	return nil, stop, trace.Errorf(strings.TrimSpace(string(errMessage)))
	//}
	return utils.NewChConn(rconn.sconn, channel), nil
}

func findServer(addr string, servers []services.Server) (services.Server, error) {
	for i := range servers {
		srv := servers[i]
		_, port, err := net.SplitHostPort(srv.GetAddr())
		if err != nil {
			logrus.Warningf("server %v(%v) has incorrect address format (%v)",
				srv.GetAddr(), srv.GetHostname(), err.Error())
		} else {
			if (len(srv.GetHostname()) != 0) && (len(port) != 0) && (addr == srv.GetHostname()+":"+port || addr == srv.GetAddr()) {
				return srv, nil
			}
		}
	}
	return nil, trace.NotFound("server %v is unknown", addr)
}

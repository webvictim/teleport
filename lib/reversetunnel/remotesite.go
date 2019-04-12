/*
Copyright 2015 Gravitational, Inc.

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
	"github.com/gravitational/trace"

	"github.com/jonboulle/clockwork"
	log "github.com/sirupsen/logrus"
)

// remoteSite is a remote site that established the inbound connecton to
// the local reverse tunnel server, and now it can provide access to the
// cluster behind it.
type remoteSite struct {
	sync.RWMutex

	*log.Entry
	domainName  string
	connections []*remoteConn
	lastUsed    int
	srv         *server
	//transport   *http.Transport
	connInfo services.TunnelConnection
	// lastConnInfo is the last conn
	lastConnInfo services.TunnelConnection
	ctx          context.Context
	cancel       context.CancelFunc
	clock        clockwork.Clock

	// certificateCache caches host certificates for the forwarding server.
	certificateCache *certificateCache

	// localClient provides access to the Auth Server API of the cluster
	// within which reversetunnel.Server is running.
	localClient auth.ClientI
	// remoteClient provides access to the Auth Server API of the remote cluster that
	// this site belongs to.
	remoteClient auth.ClientI
	// localAccessPoint provides access to a cached subset of the Auth Server API of
	// the local cluster.
	localAccessPoint auth.AccessPoint
	// remoteAccessPoint provides access to a cached subset of the Auth Server API of
	// the remote cluster this site belongs to.
	remoteAccessPoint auth.AccessPoint

	// remoteCA is the last remote certificate authority recorded by the client.
	// It is used to detect CA rotation status changes. If the rotation
	// state has been changed, the tunnel will reconnect to re-create the client
	// with new settings.
	remoteCA services.CertAuthority
}

func (s *remoteSite) getRemoteClient() (auth.ClientI, bool, error) {
	// check if all cert authorities are initiated and if everything is OK
	ca, err := s.srv.localAccessPoint.GetCertAuthority(services.CertAuthID{Type: services.HostCA, DomainName: s.domainName}, false)
	if err != nil {
		return nil, false, trace.Wrap(err)
	}
	keys := ca.GetTLSKeyPairs()

	// The fact that cluster has keys to remote CA means that the key exchange
	// has completed.
	if len(keys) != 0 {
		s.Debugf("Using TLS client to remote cluster.")
		pool, err := services.CertPool(ca)
		if err != nil {
			return nil, false, trace.Wrap(err)
		}
		tlsConfig := s.srv.ClientTLS.Clone()
		tlsConfig.RootCAs = pool
		// encode the name of this cluster to identify this cluster,
		// connecting to the remote one (it is used to find the right certificate
		// authority to verify)
		tlsConfig.ServerName = auth.EncodeClusterName(s.srv.ClusterName)
		clt, err := auth.NewTLSClientWithDialer(s.authServerContextDialer, tlsConfig)
		if err != nil {
			return nil, false, trace.Wrap(err)
		}
		return clt, false, nil
	}

	return nil, false, trace.BadParameter("no TLS keys found")
}

func (s *remoteSite) authServerContextDialer(ctx context.Context, network, address string) (net.Conn, error) {
	return s.DialAuthServer()
}

// GetTunnelsCount always returns 0 for local cluster
func (s *remoteSite) GetTunnelsCount() int {
	return s.connectionCount()
}

func (s *remoteSite) CachingAccessPoint() (auth.AccessPoint, error) {
	return s.remoteAccessPoint, nil
}

func (s *remoteSite) GetClient() (auth.ClientI, error) {
	return s.remoteClient, nil
}

func (s *remoteSite) String() string {
	return fmt.Sprintf("remoteSite(%v)", s.domainName)
}

func (s *remoteSite) connectionCount() int {
	s.RLock()
	defer s.RUnlock()
	return len(s.connections)
}

func (s *remoteSite) hasValidConnections() bool {
	s.RLock()
	defer s.RUnlock()

	for _, conn := range s.connections {
		if !conn.isInvalid() {
			return true
		}
	}
	return false
}

// Clos closes remote cluster connections
func (s *remoteSite) Close() error {
	s.Lock()
	defer s.Unlock()

	s.cancel()
	for i := range s.connections {
		s.connections[i].Close()
	}
	s.connections = []*remoteConn{}
	return nil
}

// nextConn returns next connection that is ready
// and has not been marked as invalid
// it will close connections marked as invalid
func (s *remoteSite) nextConn() (*remoteConn, error) {
	s.Lock()
	defer s.Unlock()

	s.removeInvalidConns()

	for i := 0; i < len(s.connections); i++ {
		s.lastUsed = (s.lastUsed + 1) % len(s.connections)
		remoteConn := s.connections[s.lastUsed]
		// connection could have been initated, but agent
		// on the other side is not ready yet.
		// Proxy assumes that connection is ready to serve when
		// it has received a first heartbeat, otherwise
		// it could attempt to use it before the agent
		// had a chance to start handling connection requests,
		// what could lead to proxy marking the connection
		// as invalid without a good reason.
		if remoteConn.isReady() {
			return remoteConn, nil
		}
	}

	return nil, trace.NotFound("%v is offline: no active tunnels to %v found", s.GetName(), s.srv.ClusterName)
}

// removeInvalidConns removes connections marked as invalid,
// it should be called only under write lock
func (s *remoteSite) removeInvalidConns() {
	// for first pass, do nothing if no connections are marked
	count := 0
	for _, conn := range s.connections {
		if conn.isInvalid() {
			count++
		}
	}
	if count == 0 {
		return
	}
	s.lastUsed = 0
	conns := make([]*remoteConn, 0, len(s.connections)-count)
	for i := range s.connections {
		if !s.connections[i].isInvalid() {
			conns = append(conns, s.connections[i])
		} else {
			go s.connections[i].Close()
		}
	}
	s.connections = conns
}

// addConn helper adds a new active remote cluster connection to the list
// of such connections
func (s *remoteSite) addConn(conn net.Conn, sconn ssh.Conn) (*remoteConn, error) {
	s.Lock()
	defer s.Unlock()

	rconn := newRemoteConn(&connConfig{
		conn:        conn,
		sconn:       sconn,
		accessPoint: s.localAccessPoint,
		tunnelID:    s.domainName,
		tunnelType:  string(services.ProxyTunnel),
		proxyName:   s.connInfo.GetProxyName(),
		clusterName: s.domainName,
	})

	s.connections = append(s.connections, rconn)
	s.lastUsed = 0
	return rconn, nil
}

func (s *remoteSite) GetStatus() string {
	connInfo, err := s.getLastConnInfo()
	if err != nil {
		return teleport.RemoteClusterStatusOffline
	}
	return services.TunnelConnectionStatus(s.clock, connInfo)
}

func (s *remoteSite) copyConnInfo() services.TunnelConnection {
	s.RLock()
	defer s.RUnlock()
	return s.connInfo.Clone()
}

func (s *remoteSite) setLastConnInfo(connInfo services.TunnelConnection) {
	s.Lock()
	defer s.Unlock()
	s.lastConnInfo = connInfo.Clone()
}

func (s *remoteSite) getLastConnInfo() (services.TunnelConnection, error) {
	s.RLock()
	defer s.RUnlock()
	if s.lastConnInfo == nil {
		return nil, trace.NotFound("no last connection found")
	}
	return s.lastConnInfo.Clone(), nil
}

func (s *remoteSite) registerHeartbeat(t time.Time) {
	connInfo := s.copyConnInfo()
	connInfo.SetLastHeartbeat(t)
	connInfo.SetExpiry(s.clock.Now().Add(defaults.ReverseTunnelOfflineThreshold))
	s.setLastConnInfo(connInfo)
	err := s.localAccessPoint.UpsertTunnelConnection(connInfo)
	if err != nil {
		s.Warningf("Failed to register heartbeat: %v.", err)
	}
}

// deleteConnectionRecord deletes connection record to let know peer proxies
// that this node lost the connection and needs to be discovered
func (s *remoteSite) deleteConnectionRecord() {
	s.localAccessPoint.DeleteTunnelConnection(s.connInfo.GetClusterName(), s.connInfo.GetName())
}

// handleHearbeat receives heartbeat messages from the connected agent
// if the agent has missed several heartbeats in a row, Proxy marks
// the connection as invalid.
func (s *remoteSite) handleHeartbeat(conn *remoteConn, ch ssh.Channel, reqC <-chan *ssh.Request) {
	defer func() {
		s.Infof("Cluster connection closed.")
		conn.Close()
	}()
	for {
		select {
		case <-s.ctx.Done():
			s.Infof("closing")
			return
		case req := <-reqC:
			if req == nil {
				s.Infof("Cluster agent disconnected.")
				conn.markInvalid(trace.ConnectionProblem(nil, "agent disconnected"))
				if !s.hasValidConnections() {
					s.Debugf("Deleting connection record.")
					s.deleteConnectionRecord()
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
				s.WithFields(log.Fields{"latency": roundtrip}).Debugf("ping <- %v", conn.conn.RemoteAddr())
			} else {
				s.Debugf("Ping <- %v.", conn.conn.RemoteAddr())
			}
			tm := time.Now().UTC()
			conn.setLastHeartbeat(tm)
			go s.registerHeartbeat(tm)
		// since we block on select, time.After is re-created everytime we process a request.
		case <-time.After(defaults.ReverseTunnelOfflineThreshold):
			conn.markInvalid(trace.ConnectionProblem(nil, "no heartbeats for %v", defaults.ReverseTunnelOfflineThreshold))
		}
	}
}

func (s *remoteSite) GetName() string {
	return s.domainName
}

func (s *remoteSite) GetLastConnected() time.Time {
	connInfo, err := s.getLastConnInfo()
	if err != nil {
		return time.Time{}
	}
	return connInfo.GetLastHeartbeat()
}

func (s *remoteSite) compareAndSwapCertAuthority(ca services.CertAuthority) error {
	s.Lock()
	defer s.Unlock()

	if s.remoteCA == nil {
		s.remoteCA = ca
		return nil
	}

	rotation := s.remoteCA.GetRotation()
	if rotation.Matches(ca.GetRotation()) {
		s.remoteCA = ca
		return nil
	}
	s.remoteCA = ca
	return trace.CompareFailed("remote certificate authority rotation has been updated")
}

// updateCertAuthorities updates local and remote cert authorities
func (s *remoteSite) updateCertAuthorities() error {
	// update main cluster cert authorities on the remote side
	// remote side makes sure that only relevant fields
	// are updated
	hostCA, err := s.localClient.GetCertAuthority(services.CertAuthID{
		Type:       services.HostCA,
		DomainName: s.srv.ClusterName,
	}, false)
	if err != nil {
		return trace.Wrap(err)
	}
	err = s.remoteClient.RotateExternalCertAuthority(hostCA)
	if err != nil {
		return trace.Wrap(err)
	}

	userCA, err := s.localClient.GetCertAuthority(services.CertAuthID{
		Type:       services.UserCA,
		DomainName: s.srv.ClusterName,
	}, false)
	if err != nil {
		return trace.Wrap(err)
	}
	err = s.remoteClient.RotateExternalCertAuthority(userCA)
	if err != nil {
		return trace.Wrap(err)
	}

	// update remote cluster's host cert authoritiy on a local cluster
	// local proxy is authorized to perform this operation only for
	// host authorities of remote clusters.
	remoteCA, err := s.remoteClient.GetCertAuthority(services.CertAuthID{
		Type:       services.HostCA,
		DomainName: s.domainName,
	}, false)
	if err != nil {
		return trace.Wrap(err)
	}

	if remoteCA.GetClusterName() != s.domainName {
		return trace.BadParameter(
			"remote cluster sent different cluster name %v instead of expected one %v",
			remoteCA.GetClusterName(), s.domainName)
	}
	err = s.localClient.UpsertCertAuthority(remoteCA)
	if err != nil {
		return trace.Wrap(err)
	}

	return s.compareAndSwapCertAuthority(remoteCA)
}

func (s *remoteSite) periodicUpdateCertAuthorities() {
	s.Debugf("Ticking with period %v", s.srv.PollingPeriod)
	ticker := time.NewTicker(s.srv.PollingPeriod)
	defer ticker.Stop()
	for {
		select {
		case <-s.ctx.Done():
			s.Debugf("Context is closing.")
			return
		case <-ticker.C:
			err := s.updateCertAuthorities()
			if err != nil {
				switch {
				case trace.IsNotFound(err):
					s.Debugf("Remote cluster %v does not support cert authorities rotation yet.", s.domainName)
				case trace.IsCompareFailed(err):
					s.Infof("Remote cluster has updated certificate authorities, going to force reconnect.")
					s.srv.RemoveSite(s.domainName)
					s.Close()
					return
				case trace.IsConnectionProblem(err):
					s.Debugf("Remote cluster %v is offline.", s.domainName)
				default:
					s.Warningf("Could not perform cert authorities updated: %v.", trace.DebugReport(err))
				}
			}
		}
	}
}

func (s *remoteSite) DialAuthServer() (conn net.Conn, err error) {
	return s.connThroughTunnel(RemoteAuthServer)
}

// Dial is used to connect a requesting client (say, tsh) to an SSH server
// located in a remote connected site, the connection goes through the
// reverse proxy tunnel.
func (s *remoteSite) Dial(params DialParams) (net.Conn, error) {
	err := params.CheckAndSetDefaults()
	if err != nil {
		return nil, trace.Wrap(err)
	}

	clusterConfig, err := s.localAccessPoint.GetClusterConfig()
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

func (s *remoteSite) DialTCP(from, to net.Addr) (net.Conn, error) {
	s.Debugf("Dialing from %v to %v", from, to)

	conn, err := s.connThroughTunnel(to.String())
	if err != nil {
		return nil, trace.Wrap(err)
	}

	return conn, nil
}

func (s *remoteSite) dialWithAgent(params DialParams) (net.Conn, error) {
	s.Debugf("Dialing with an agent from %v to %v.", params.From, params.To)

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

	targetConn, err := s.connThroughTunnel(params.To.String())
	if err != nil {
		return nil, trace.Wrap(err)
	}

	// create a forwarding server that serves a single ssh connection on it. we
	// don't need to close this server it will close and release all resources
	// once conn is closed.
	//
	// note, a localClient is passed to the forwarding server, that's to make
	// sure that the session gets recorded in the local cluster instead of the
	// remote cluster.
	serverConfig := forward.ServerConfig{
		AuthClient:      s.localClient,
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

func (s *remoteSite) connThroughTunnel(addr string) (conn net.Conn, err error) {
	var stop bool

	s.Debugf("Requesting connection to remote site with payload: %v.", addr)

	// loop through existing TCP/IP connections (reverse tunnels) and try
	// to establish an inbound connection-over-ssh-channel to the remote
	// cluster (AKA "remotetunnel agent"):
	for i := 0; i < s.connectionCount() && !stop; i++ {
		conn, stop, err = s.chanTransportConn(addr)
		if err == nil {
			return conn, nil
		}
		s.Warnf("Request for connection to remote site failed: %v.", err)
	}
	// didn't connect and no error? this means we didn't have any connected
	// tunnels to try
	if err == nil {
		err = trace.ConnectionProblem(nil, "%v is offline", s.GetName())
	}
	return nil, err
}

func (s *remoteSite) chanTransportConn(addr string) (net.Conn, bool, error) {
	rconn, err := s.nextConn()
	if err != nil {
		return nil, false, trace.Wrap(err)
	}

	return connectProxyTransport(rconn, addr)
}

package reversetunnel

import (
	"context"
	"net"
	"sync"
	"time"

	"github.com/gravitational/teleport"
	"github.com/gravitational/teleport/lib/auth"
	"github.com/gravitational/teleport/lib/services"

	"github.com/gravitational/trace"

	"github.com/jonboulle/clockwork"
	"github.com/sirupsen/logrus"
)

type discoveryConfig struct {
	Clock        clockwork.Clock
	ConnInfo     services.NewTunnelConnection
	AccessPoint  auth.AccessPoint
	RemoteDomain string
}

type discoveryServer struct {
	*discoveryConfig

	log *logrus.Entry
	mu  sync.RWMutex

	closeContext context.Context

	// connections is a list of connections to remote hosts.
	connections []*remoteConn

	// lastUsed is the index of the last used remote connection.
	lastUsed int

	connInfo services.TunnelConnection
	// lastConnInfo is the last conn
	//lastConnInfo services.TunnelConnection

}

func newDiscoveryServer(config *discoveryConfig) (*discoveryServer, error) {
	return &discoveryServer{
		discoveryConfig: config,
		log: logrus.WithFields(logrus.Fields{
			trace.Component: "discovery",
		}),
	}, nil
}

func (s *discoveryServer) Start() {
	go s.periodicSendDiscoveryRequests()
}

func (s *discoveryServer) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	var errs []error
	for i := range s.connections {
		err := s.connections[i].Close()
		if err != nil {
			errs = append(errs, err)
		}
	}
	s.connections = []*remoteConn{}

	return trace.NewAggregate(errs...)
}

// ConnThroughTunnel
func (s *discoveryServer) ConnThroughTunnel(transportType string, data string) (conn net.Conn, err error) {
	var stop bool

	s.log.Debugf("Requesting %v connection to remote site with payload: %v.", transportType, data)

	// Loop through existing connections (reverse tunnels) and try to establish an
	// inbound connection-over-ssh-channel to the remote cluster.
	for i := 0; i < s.connectionCount() && !stop; i++ {
		conn, stop, err = s.chanTransportConn(transportType, data)
		if err == nil {
			return conn, nil
		}
		s.log.Warnf("Request for %v connection to remote site failed: %v", transportType, err)
	}
	// didn't connect and no error? this means we didn't have any connected
	// tunnels to try
	if err == nil {
		err = trace.ConnectionProblem(nil, "%v is offline", s.GetName())
	}
	return nil, err
}

func (s *discoveryServer) chanTransportConn(transportType string, addr string) (net.Conn, bool, error) {
	var stop bool

	remoteConn, err := s.nextConn()
	if err != nil {
		return nil, stop, trace.Wrap(err)
	}
	var ch ssh.Channel
	ch, _, err = remoteConn.sshConn.OpenChannel(chanTransport, nil)
	if err != nil {
		remoteConn.markInvalid(err)
		return nil, stop, trace.Wrap(err)
	}
	// send a special SSH out-of-band request called "teleport-transport"
	// the agent on the other side will create a new TCP/IP connection to
	// 'addr' on its network and will start proxying that connection over
	// this SSH channel:
	var dialed bool
	dialed, err = ch.SendRequest(transportType, true, []byte(addr))
	if err != nil {
		return nil, stop, trace.Wrap(err)
	}
	stop = true
	if !dialed {
		defer ch.Close()
		// pull the error message from the tunnel client (remote cluster)
		// passed to us via stderr:
		errMessage, _ := ioutil.ReadAll(ch.Stderr())
		if errMessage == nil {
			errMessage = []byte("failed connecting to " + addr)
		}
		return nil, stop, trace.Errorf(strings.TrimSpace(string(errMessage)))
	}
	return utils.NewChConn(remoteConn.sshConn, ch), stop, nil
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

func (s *remoteSite) GetStatus() string {
	connInfo, err := s.getLastConnInfo()
	if err != nil {
		return teleport.RemoteClusterStatusOffline
	}
	return services.TunnelConnectionStatus(s.clock, connInfo)
}

// addConn helper adds a new active remote cluster connection to the list
// of such connections
func (s *discoveryServer) addConn(conn net.Conn, sshConn ssh.Conn) (*remoteConn, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	rc := &remoteConn{
		sshConn: sshConn,
		conn:    conn,
		log:     s.Entry,
	}
	s.connections = append(s.connections, rc)
	s.lastUsed = 0

	return rc, nil
}

// nextConn returns a connection to the remote proxy. Uses round robin
// algorithm to loop over all connections.
func (s *discoveryServer) nextConn() (*remoteConn, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	for {
		if len(s.connections) == 0 {
			return nil, trace.NotFound("no active tunnels to cluster %v", s.GetName())
		}

		// Get next connection to server and loop around upon hitting the end.
		s.lastUsed = (s.lastUsed + 1) % len(s.connections)
		remoteConn := s.connections[s.lastUsed]

		// If the connective is valid (no errors have occured while sending data
		// on it), return it right away.
		if !remoteConn.isInvalid() {
			return remoteConn, nil
		}

		// If the connection is invalid (errors have occured while attempting to
		// send data on it), remove it from the list of connections.
		s.connections = append(s.connections[:s.lastUsed], s.connections[s.lastUsed+1:]...)
		s.lastUsed = 0

		go remoteConn.Close()
	}
}

func (s *discoveryServer) connectionCount() int {
	s.mu.RLock()
	defer s.mu.RUnlock()

	return len(s.connections)
}

func (s *discoveryServer) periodicSendDiscoveryRequests() {
	ticker := time.NewTicker(defaults.ReverseTunnelAgentHeartbeatPeriod)
	defer ticker.Stop()

	if err := s.findAndSend(); err != nil {
		s.log.Warnf("Failed to send discovery request: %v.", trace.DebugReport(err))
	}

	for {
		select {
		case <-ticker.C:
			err := s.findAndSend()
			if err != nil {
				s.log.Warnf("Failed to send discovery request: %v.", trace.DebugReport(err))
			}
		case <-s.closeContext.Done():
			s.log.Debugf("closing")
			return
		}
	}
}

// sendDiscovery requests sends special "Discovery Requests"
// back to the connected agent.
// Discovery request consists of the proxies that are part
// of the cluster, but did not receive the connection from the agent.
// Agent will act on a discovery request attempting
// to establish connection to the proxies that were not discovered.
// See package documentation for more details.
func (s *discoveryServer) findAndSend() error {
	// Find all proxies that don't have a connection to a remote agent. If all
	// proxies have connections, return right away.
	disconnectedProxies, err := s.findDisconnectedProxies()
	if err != nil {
		return trace.Wrap(err)
	}
	if len(disconnectedProxies) == 0 {
		return nil
	}

	// Get the local cluster name.
	clusterName, err := s.AccessPoint.GetDomainName()
	if err != nil {
		return trace.Wrap(err)
	}
	s.log.Debugf("Proxy %v sending discovery requests for: %v", s.Local.ConnInfo().GetProxyName(), Proxies(disconnectedProxies))

	// Create the discovery request and send it all connected severs.
	req := discoveryRequest{
		ClusterName: clusterName,
		Proxies:     disconnectedProxies,
	}
	err := s.sendDiscoveryRequests(req)
	if err != nil {
		return trace.Wrap(err)
	}

	return nil
}

// findDisconnectedProxies finds proxies that do not have inbound reverse tunnel
// connections
func (s *discoveryServer) findDisconnectedProxies() ([]services.Server, error) {
	// Find all proxies that have connection from the remote domain.
	conns, err := s.AccessPoint.GetTunnelConnections(s.RemoteDomain, services.SkipValidation())
	if err != nil {
		return nil, trace.Wrap(err)
	}
	connected := make(map[string]bool)
	for _, conn := range conns {
		if s.isOnline(conn) {
			connected[conn.GetProxyName()] = true
		}
	}

	// Build a list of local proxies that do not have a remote connection to them.
	var missing []services.Server
	proxies, err := s.AccessPoint.GetProxies()
	if err != nil {
		return nil, trace.Wrap(err)
	}
	for i := range proxies {
		proxy := proxies[i]
		// do not add this proxy to the list of disconnected proxies
		if !connected[proxy.GetName()] && proxy.GetName() != connInfo.GetProxyName() {
			missing = append(missing, proxy)
		}
	}
	return missing, nil
}

// sendDiscoveryRequests sends a discovery request to all connected proxies.
func (s *discoveryServer) sendDiscoveryRequests(req *discoveryRequest) error {
	// Loop over all servers that have established a connection and send a
	// discovery request.
	for i := 0; i < s.Remote.nextConnCount(); i++ {
		// Get a connection to the remote server.
		remoteConn, err := s.Remote.nextConn()
		if err != nil {
			return trace.Wrap(err)
		}

		// Open a channel (from server to client) over which to send the
		// "discovery request".
		discoveryCh, err := remoteConn.openDiscoveryChannel()
		if err != nil {
			return trace.Wrap(err)
		}

		// Marshal and send the request. If the connection failed, mark the
		// connection as invalid so it will be removed later.
		payload, err := marshalDiscoveryRequest(req)
		if err != nil {
			return trace.Wrap(err)
		}
		_, err = discoveryCh.SendRequest("discovery", false, payload)
		if err != nil {
			remoteConn.markInvalid(err)
			s.log.Errorf("Disconnecting connection to %v: %v.", remoteConn.conn.RemoteAddr(), err)

			return trace.Wrap(err)
		}

	}
	return nil
}

func (s *discoveryServer) isOnline(conn services.TunnelConnection) bool {
	return services.TunnelConnectionStatus(s.Clock, conn) == teleport.RemoteClusterStatusOnline
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
		s.Warningf("failed to register heartbeat: %v", err)
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
		s.Infof("cluster connection closed")
		conn.Close()
	}()
	for {
		select {
		case <-s.ctx.Done():
			s.Infof("closing")
			return
		case req := <-reqC:
			if req == nil {
				s.Infof("cluster agent disconnected")
				conn.markInvalid(trace.ConnectionProblem(nil, "agent disconnected"))
				if !s.hasValidConnections() {
					s.Debugf("deleting connection record")
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
				s.Debugf("ping <- %v", conn.conn.RemoteAddr())
			}
			go s.registerHeartbeat(time.Now())
		// since we block on select, time.After is re-created everytime we process a request.
		case <-time.After(defaults.ReverseTunnelOfflineThreshold):
			conn.markInvalid(trace.ConnectionProblem(nil, "no heartbeats for %v", defaults.ReverseTunnelOfflineThreshold))
		}
	}
}

// dialAccessPoint establishes a connection from the proxy (reverse tunnel server)
// back into the client using previously established tunnel.
func (s *remoteSite) dialAccessPoint(network, addr string) (net.Conn, error) {
	try := func() (net.Conn, error) {
		remoteConn, err := s.nextConn()
		if err != nil {
			return nil, trace.Wrap(err)
		}
		ch, _, err := remoteConn.sshConn.OpenChannel(chanAccessPoint, nil)
		if err != nil {
			remoteConn.markInvalid(err)
			s.Errorf("disconnecting cluster on %v, err: %v",
				remoteConn.conn.RemoteAddr(),
				err)
			return nil, trace.Wrap(err)
		}
		s.Debugf("success dialing to cluster")
		return utils.NewChConn(remoteConn.sshConn, ch), nil
	}

	for {
		conn, err := try()
		if err != nil {
			if trace.IsNotFound(err) {
				return nil, trace.Wrap(err)
			}
			continue
		}
		return conn, nil
	}
}

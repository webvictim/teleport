/*
Copyright 2015-2019 Gravitational, Inc.

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

// Package reversetunnel sets up persistent reverse tunnel
// between remote site and teleport proxy, when site agents
// dial to teleport proxy's socket and teleport proxy can connect
// to any server through this tunnel.
package reversetunnel

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"github.com/gravitational/teleport"
	"github.com/gravitational/teleport/lib/auth"
	"github.com/gravitational/teleport/lib/defaults"
	"github.com/gravitational/teleport/lib/services"
	"github.com/gravitational/teleport/lib/sshutils"
	"github.com/gravitational/teleport/lib/utils"
	"github.com/gravitational/teleport/lib/utils/proxy"

	"github.com/gravitational/trace"
	"github.com/jonboulle/clockwork"
	log "github.com/sirupsen/logrus"
	"golang.org/x/crypto/ssh"
)

const (
	// agentStateConnecting is when agent is connecting to the target
	// without particular purpose
	agentStateConnecting = "connecting"
	// agentStateDiscovering is when agent is created with a goal
	// to discover one or many proxies
	agentStateDiscovering = "discovering"
	// agentStateConnected means that agent has connected to instance
	agentStateConnected = "connected"
	// agentStateDiscovered means that agent has discovered the right proxy
	agentStateDiscovered = "discovered"
	// agentStateDisconnected means that the agent has disconnected from the
	// proxy and this agent and be removed from the pool.
	agentStateDisconnected = "disconnected"
)

// AgentConfig holds configuration for agent
type AgentConfig struct {
	// Addr is target address to dial
	Addr utils.NetAddr
	// ClusterName is the name of the cluster the tunnel is connected to.
	ClusterName string
	// Signers contains authentication signers
	Signers []ssh.Signer
	// TLSConfig
	TLSConfig *tls.Config
	// Client is a client to the local auth servers
	Client auth.ClientI
	// AccessPoint is a caching access point to the local auth servers
	AccessPoint auth.AccessPoint
	// Context is a parent context
	Context context.Context
	// DiscoveryC is a channel that receives discovery requests
	// from reverse tunnel server
	DiscoveryC chan *discoveryRequest
	// Username is the name of this client used to authenticate on SSH
	Username string
	// DiscoverProxies is set when the agent is created in discovery mode
	// and is set to connect to one of the target proxies from the list
	DiscoverProxies []services.Server
	// Clock is a clock passed in tests, if not set wall clock
	// will be used
	Clock clockwork.Clock
	// EventsC is an optional events channel, used for testing purposes
	EventsC chan string
	// KubeDialAddr is a dial address for kubernetes proxy
	KubeDialAddr utils.NetAddr
	// Server
	Server ServerHandler
}

// CheckAndSetDefaults checks parameters and sets default values
func (a *AgentConfig) CheckAndSetDefaults() error {
	if a.Addr.IsEmpty() {
		return trace.BadParameter("missing parameter Addr")
	}
	if a.Context == nil {
		return trace.BadParameter("missing parameter Context")
	}
	if a.Client == nil {
		return trace.BadParameter("missing parameter Client")
	}
	if a.AccessPoint == nil {
		return trace.BadParameter("missing parameter AccessPoint")
	}
	if len(a.Signers) == 0 {
		return trace.BadParameter("missing parameter Signers")
	}
	if len(a.Username) == 0 {
		return trace.BadParameter("missing parameter Username")
	}
	if a.Clock == nil {
		a.Clock = clockwork.NewRealClock()
	}
	return nil
}

// Agent is a reverse tunnel agent running as a part of teleport Proxies
// to establish outbound reverse tunnels to remote proxies.
//
// There are two operation modes for agents:
// * Standard agent attempts to establish connection
// to any available proxy. Standard agent transitions between
// "connecting" -> "connected states.
// * Discovering agent attempts to establish connection to a subset
// of remote proxies (specified in the config via DiscoverProxies parameter.)
// Discovering agent transitions between "discovering" -> "discovered" states.
type Agent struct {
	sync.RWMutex
	*log.Entry
	AgentConfig
	ctx             context.Context
	cancel          context.CancelFunc
	hostKeyCallback ssh.HostKeyCallback
	authMethods     []ssh.AuthMethod
	// state is the state of this agent
	state string
	// stateChange records last time the state was changed
	stateChange time.Time
	// principals is the list of principals of the server this agent
	// is currently connected to
	principals []string
}

// NewAgent returns a new reverse tunnel agent
func NewAgent(cfg AgentConfig) (*Agent, error) {
	if err := cfg.CheckAndSetDefaults(); err != nil {
		return nil, trace.Wrap(err)
	}
	ctx, cancel := context.WithCancel(cfg.Context)
	a := &Agent{
		AgentConfig: cfg,
		ctx:         ctx,
		cancel:      cancel,
		authMethods: []ssh.AuthMethod{ssh.PublicKeys(cfg.Signers...)},
	}
	if len(cfg.DiscoverProxies) == 0 {
		a.state = agentStateConnecting
	} else {
		a.state = agentStateDiscovering
	}
	a.Entry = log.WithFields(log.Fields{
		trace.Component: teleport.ComponentReverseTunnelAgent,
		trace.ComponentFields: log.Fields{
			"target": cfg.Addr.String(),
		},
	})
	a.hostKeyCallback = a.checkHostSignature
	return a, nil
}

func (a *Agent) String() string {
	if len(a.DiscoverProxies) == 0 {
		return fmt.Sprintf("agent(%v) -> %v:%v", a.getState(), a.ClusterName, a.Addr.String())
	}
	return fmt.Sprintf("agent(%v) -> %v:%v, discover %v", a.getState(), a.ClusterName, a.Addr.String(), Proxies(a.DiscoverProxies))
}

func (a *Agent) getLastStateChange() time.Time {
	a.RLock()
	defer a.RUnlock()
	return a.stateChange
}

func (a *Agent) setStateAndPrincipals(state string, principals []string) {
	a.Lock()
	defer a.Unlock()
	prev := a.state
	a.Debugf("Changing state %v -> %v.", prev, state)
	a.state = state
	a.stateChange = a.Clock.Now().UTC()
	a.principals = principals
}
func (a *Agent) setState(state string) {
	a.Lock()
	defer a.Unlock()
	prev := a.state
	a.Debugf("Changing state %v -> %v.", prev, state)
	a.state = state
	a.stateChange = a.Clock.Now().UTC()
}

func (a *Agent) getState() string {
	a.RLock()
	defer a.RUnlock()
	return a.state
}

// Close signals to close all connections and operations
func (a *Agent) Close() error {
	a.cancel()
	return nil
}

// Start starts agent that attempts to connect to remote server
func (a *Agent) Start() {
	go a.run()
}

// Wait waits until all outstanding operations are completed
func (a *Agent) Wait() error {
	return nil
}

// connectedTo returns true if connected services.Server passed in.
func (a *Agent) connectedTo(proxy services.Server) bool {
	principals := a.getPrincipals()
	proxyID := fmt.Sprintf("%v.%v", proxy.GetName(), a.ClusterName)
	if _, ok := principals[proxyID]; ok {
		return true
	}
	return false
}

// connectedToRightProxy returns true if it connected to a proxy in the
// discover list.
func (a *Agent) connectedToRightProxy() bool {
	for _, proxy := range a.DiscoverProxies {
		if a.connectedTo(proxy) {
			return true
		}
	}
	return false
}

func (a *Agent) setPrincipals(principals []string) {
	a.Lock()
	defer a.Unlock()
	a.principals = principals
}

func (a *Agent) getPrincipalsList() []string {
	a.RLock()
	defer a.RUnlock()
	out := make([]string, len(a.principals))
	copy(out, a.principals)
	return out
}

func (a *Agent) getPrincipals() map[string]struct{} {
	a.RLock()
	defer a.RUnlock()
	out := make(map[string]struct{}, len(a.principals))
	for _, p := range a.principals {
		out[p] = struct{}{}
	}
	return out
}

func (a *Agent) checkHostSignature(hostport string, remote net.Addr, key ssh.PublicKey) error {
	cert, ok := key.(*ssh.Certificate)
	if !ok {
		return trace.BadParameter("expected certificate")
	}
	cas, err := a.AccessPoint.GetCertAuthorities(services.HostCA, false)
	if err != nil {
		return trace.Wrap(err, "failed to fetch remote certs")
	}
	for _, ca := range cas {
		checkers, err := ca.Checkers()
		if err != nil {
			return trace.BadParameter("error parsing key: %v", err)
		}
		for _, checker := range checkers {
			if sshutils.KeysEqual(checker, cert.SignatureKey) {
				a.setPrincipals(cert.ValidPrincipals)
				return nil
			}
		}
	}
	return trace.NotFound(
		"no matching keys found when checking server's host signature")
}

func (a *Agent) proxyNodeTransport(sconn ssh.Conn, channel ssh.Channel, reqCh <-chan *ssh.Request) {
	defer channel.Close()

	// Hand connection off to the SSH server.
	a.AgentConfig.Server.HandleConnection(utils.NewChConn(sconn, channel))
}

func (a *Agent) connect() (conn *ssh.Client, err error) {
	for _, authMethod := range a.authMethods {
		// if http_proxy is set, dial through the proxy
		dialer := proxy.DialerFromEnvironment(a.Addr.Addr)
		conn, err = dialer.Dial(a.Addr.AddrNetwork, a.Addr.Addr, &ssh.ClientConfig{
			User:            a.Username,
			Auth:            []ssh.AuthMethod{authMethod},
			HostKeyCallback: a.hostKeyCallback,
			Timeout:         defaults.DefaultDialTimeout,
		})
		if conn != nil {
			break
		}
	}
	return conn, err
}

// proxyTransport runs as a goroutine running inside a reverse tunnel client
// and it establishes and maintains the following remote connection:
//
// tsh -> proxy(also reverse-tunnel-server) -> reverse-tunnel-agent
//
// ch   : SSH channel which received "teleport-transport" out-of-band request
// reqC : request payload
func (a *Agent) proxyTransport(ch ssh.Channel, reqC <-chan *ssh.Request) {
	a.Debugf("proxyTransport")
	defer ch.Close()

	// always push space into stderr to make sure the caller can always
	// safely call read(stderr) without blocking. this stderr is only used
	// to request proxying of TCP/IP via reverse tunnel.
	fmt.Fprint(ch.Stderr(), " ")

	var req *ssh.Request
	select {
	case <-a.ctx.Done():
		a.Infof("is closed, returning")
		return
	case req = <-reqC:
		if req == nil {
			a.Infof("connection closed, returning")
			return
		}
	case <-time.After(defaults.DefaultDialTimeout):
		a.Warningf("timeout waiting for dial")
		return
	}

	server := string(req.Payload)
	var servers []string

	// if the request is for the special string @remote-auth-server, then get the
	// list of auth servers and return that. otherwise try and connect to the
	// passed in server.
	switch server {
	case RemoteAuthServer:
		authServers, err := a.Client.GetAuthServers()
		if err != nil {
			a.Warningf("Unable retrieve list of remote Auth Servers: %v.", err)
			return
		}
		if len(authServers) == 0 {
			a.Warningf("No remote Auth Servers returned by client.")
			return
		}
		for _, as := range authServers {
			servers = append(servers, as.GetAddr())
		}
	case RemoteKubeProxy:
		// kubernetes is not configured, reject the connection
		if a.KubeDialAddr.IsEmpty() {
			req.Reply(false, []byte("connection rejected: configure kubernetes proxy for this cluster."))
			return
		}
		servers = append(servers, a.KubeDialAddr.Addr)
	default:
		servers = append(servers, server)
	}

	a.Debugf("Received out-of-band proxy transport request: %v", servers)

	var conn net.Conn
	var err error

	// loop over all servers and try and connect to one of them
	for _, s := range servers {
		conn, err = net.Dial("tcp", s)
		if err == nil {
			break
		}

		// log the reason we were not able to connect
		a.Debugf(trace.DebugReport(err))
	}

	// if we were not able to connect to any server, write the last connection
	// error to stderr of the caller (via SSH channel) so the error will be
	// propagated all the way back to the client (most likely tsh)
	if err != nil {
		fmt.Fprint(ch.Stderr(), err.Error())
		req.Reply(false, []byte(err.Error()))
		return
	}

	if conn == nil {
		a.Warningf("No error, but conn is nil: %v", conn)
	}

	// successfully dialed
	req.Reply(true, []byte("connected"))
	a.Debugf("Successfully dialed to %v, start proxying.", server)

	wg := sync.WaitGroup{}
	wg.Add(2)

	go func() {
		defer wg.Done()
		// make sure that we close the client connection on a channel
		// close, otherwise the other goroutine would never know
		// as it will block on read from the connection
		defer conn.Close()
		io.Copy(conn, ch)
	}()

	go func() {
		defer wg.Done()
		io.Copy(ch, conn)
	}()

	wg.Wait()
}

// run is the main agent loop. It tries to establish a connection to the
// remote proxy and then process requests that come over the tunnel.
//
// Once run connects to a proxy it starts processing requests from the proxy
// via SSH channels opened by the remote Proxy.
//
// Agent sends periodic heartbeats back to the Proxy and that is how Proxy
// determines disconnects.
func (a *Agent) run() {
	defer a.setState(agentStateDisconnected)

	if len(a.DiscoverProxies) != 0 {
		a.setStateAndPrincipals(agentStateDiscovering, nil)
	} else {
		a.setStateAndPrincipals(agentStateConnecting, nil)
	}

	// Try and connect to remote cluster.
	conn, err := a.connect()
	if err != nil || conn == nil {
		a.Warningf("Failed to create remote tunnel: %v, conn: %v.", err, conn)
		return
	}

	// Successfully connected to remote cluster.
	a.Infof("Connected to %s", conn.RemoteAddr())
	if len(a.DiscoverProxies) != 0 {
		// If not connected to a proxy in the discover list (which means we
		// connected to a proxy we already have a connection to), try again.
		if !a.connectedToRightProxy() {
			a.Debugf("Missed, connected to %v instead of %v.", a.getPrincipalsList(), Proxies(a.DiscoverProxies))

			conn.Close()
			return
		}
		a.setState(agentStateDiscovered)
	} else {
		a.setState(agentStateConnected)
	}

	// Notify waiters that the agent has connected.
	if a.EventsC != nil {
		select {
		case a.EventsC <- ConnectedEvent:
		case <-a.ctx.Done():
			a.Debug("Context is closing.")
			return
		default:
		}
	}

	// A connection has been established start processing requests. Note that
	// this function blocks while the connection is up. It will unblock when
	// the connection is closed either due to intermittent connectivity issues
	// or permanent loss of a proxy.
	err = a.processRequests(conn)
	if err != nil {
		a.Warnf("Unable to continue processesing requests: %v.", err)
		return
	}
}

// ConnectedEvent is used to indicate that reverse tunnel has connected
const ConnectedEvent = "connected"

// processRequests is a blocking function which runs in a loop sending heartbeats
// to the given SSH connection and processes inbound requests from the
// remote proxy
func (a *Agent) processRequests(conn *ssh.Client) error {
	defer conn.Close()
	ticker := time.NewTicker(defaults.ReverseTunnelAgentHeartbeatPeriod)
	defer ticker.Stop()

	hb, reqC, err := conn.OpenChannel(chanHeartbeat, nil)
	if err != nil {
		return trace.Wrap(err)
	}

	//go func() {
	//	authDialer := func(in context.Context, network, addr string) (net.Conn, error) {
	//		authCh, _, err := conn.OpenChannel("auth", nil)
	//		if err != nil {
	//			return nil, trace.Wrap(err)
	//		}
	//		return utils.NewChConn(conn.Conn, authCh), nil
	//	}

	//	for i := 0; i < 10; i++ {
	//		// check if all cert authorities are initiated and if everything is OK
	//		ca, err := a.AccessPoint.GetCertAuthority(services.CertAuthID{
	//			Type:       services.HostCA,
	//			DomainName: a.ClusterName,
	//		}, false)
	//		if err != nil {
	//			fmt.Printf("--> NEW: 0 err: %v.\n", err)
	//			continue
	//		}
	//		pool, err := services.CertPool(ca)
	//		if err != nil {
	//			fmt.Printf("--> NEW: 1 err: %v.\n", err)
	//			continue
	//		}
	//		tlsConfig := a.TLSConfig.Clone()
	//		tlsConfig.RootCAs = pool
	//		tlsConfig.ServerName = auth.EncodeClusterName("example.com")
	//		clt, err := auth.NewTLSClientWithDialer(authDialer, tlsConfig)
	//		if err != nil {
	//			fmt.Printf("--> NEW: 2 err: %v.\n", err)
	//			continue
	//		}
	//		clusterConfig, err := clt.GetClusterConfig()
	//		if err != nil {
	//			fmt.Printf("--> NEW: 3 err: %v.\n", err)
	//			continue
	//		}
	//		fmt.Printf("--> NEW!! clusterConfig=%v.\n", clusterConfig)
	//		time.Sleep(2 * time.Second)
	//	}
	//}()

	newTransportC := conn.HandleChannelOpen(chanTransport)
	newDiscoveryC := conn.HandleChannelOpen(chanDiscovery)
	newNodeTransportCh := conn.HandleChannelOpen(chanTransportNode)

	// send first ping right away, then start a ping timer:
	hb.SendRequest("ping", false, nil)

	for {
		select {
		// need to exit:
		case <-a.ctx.Done():
			return trace.ConnectionProblem(nil, "heartbeat: agent is stopped")
		// ssh channel closed:
		case req := <-reqC:
			if req == nil {
				return trace.ConnectionProblem(nil, "heartbeat: connection closed")
			}
		// time to ping:
		case <-ticker.C:
			bytes, _ := a.Clock.Now().UTC().MarshalText()
			_, err := hb.SendRequest("ping", false, bytes)
			if err != nil {
				a.Error(err)
				return trace.Wrap(err)
			}
			a.Debugf("Ping -> %v.", conn.RemoteAddr())
		// new transport request:
		case nch := <-newTransportC:
			if nch == nil {
				continue
			}
			a.Debugf("Transport request: %v.", nch.ChannelType())
			ch, req, err := nch.Accept()
			if err != nil {
				a.Warningf("Failed to accept request: %v.", err)
				continue
			}
			go a.proxyTransport(ch, req)
		// Node transport request.
		case nch := <-newNodeTransportCh:
			if nch == nil {
				continue
			}
			a.Debugf("Node transport request: %v.", nch.ChannelType())
			ch, req, err := nch.Accept()
			if err != nil {
				a.Warnf("Failed to accept %v request: %v", nch.ChannelType(), err)
				continue
			}
			go a.proxyNodeTransport(conn.Conn, ch, req)
		// new discovery request
		case nch := <-newDiscoveryC:
			if nch == nil {
				continue
			}
			a.Debugf("discovery request: %v", nch.ChannelType())
			ch, req, err := nch.Accept()
			if err != nil {
				a.Warningf("failed to accept request: %v", err)
				continue
			}
			go a.handleDiscovery(ch, req)
		}
	}
}

// handleDisovery receives discovery requests from the reverse tunnel
// server, that informs agent about proxies registered in the remote
// cluster and the reverse tunnels already established
//
// ch   : SSH channel which received "teleport-transport" out-of-band request
// reqC : request payload
func (a *Agent) handleDiscovery(ch ssh.Channel, reqC <-chan *ssh.Request) {
	a.Debugf("handleDiscovery")
	defer ch.Close()

	for {
		var req *ssh.Request
		select {
		case <-a.ctx.Done():
			a.Infof("is closed, returning")
			return
		case req = <-reqC:
			if req == nil {
				a.Infof("connection closed, returning")
				return
			}
			r, err := unmarshalDiscoveryRequest(req.Payload)
			if err != nil {
				a.Warningf("bad payload: %v", err)
				return
			}
			r.ClusterAddr = a.Addr
			select {
			case a.DiscoveryC <- r:
			case <-a.ctx.Done():
				a.Infof("is closed, returning")
				return
			default:
			}
		}
	}
}

const (
	chanHeartbeat = "teleport-heartbeat"
	//chanAccessPoint      = "teleport-access-point"
	chanTransport        = "teleport-transport"
	chanTransportNode    = "teleport-transport-node"
	chanTransportDialReq = "teleport-transport-dial"
	chanDiscovery        = "teleport-discovery"
)

const (
	// RemoteAuthServer is a special non-resolvable address that indicates client
	// requests a connection to the remote auth server.
	RemoteAuthServer = "@remote-auth-server"
	// RemoteKubeProxy is a special non-resolvable address that indicates that clients
	// requests a connection to the remote kubernetes proxy.
	// This has to be a valid domain name, so it lacks @
	RemoteKubeProxy = "remote.kube.proxy.teleport.cluster.local"
)

package trusttunnel

import (
	"context"
	stdTLS "crypto/tls"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"runtime"
	"time"

	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/auth"
	"github.com/sagernet/sing/common/baderror"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/common/ntp"
	"github.com/sagernet/sing/common/tls"

	"golang.org/x/net/http2"
)

type RoundTripper interface {
	http.RoundTripper
	CloseIdleConnections()
}

type keepSessionKey struct{}

func ContextWithKeepSession(ctx context.Context) context.Context {
	return context.WithValue(ctx, (*keepSessionKey)(nil), true)
}

func keepSessionFromContext(ctx context.Context) bool {
	keep, _ := ctx.Value((*keepSessionKey)(nil)).(bool)
	return keep
}

type ClientOptions struct {
	Ctx                   context.Context
	Detour                N.Dialer
	Server                M.Socksaddr
	Auth                  auth.User
	TLSConfig             tls.Config
	QUIC                  bool
	QUICCongestionControl string
	HealthCheck           bool
	// UserAgents is a collection of the user agent you want to show.
	// Due to they may be used for discriminatory use, we are consider not to upload it.
	UserAgents ClientUserAgents
	// ResolveFunc is the function to resolve FQDN for packet conn.
	// If not set, the packet conn will reject FQDN when writing.
	ResolveFunc func(fqdn string) (netip.Addr, error)
}

type ClientUserAgents struct {
	AppName              string
	TCPUserAgent         string
	UDPUserAgent         string
	ICMPUserAgent        string
	HealthCheckUserAgent string
}

func NewUserAgentFromAppName(name string) ClientUserAgents {
	name = truncateAppName(name)
	return ClientUserAgents{
		AppName:              name,
		TCPUserAgent:         runtime.GOOS + " " + name + "/" + Version,
		UDPUserAgent:         runtime.GOOS + " " + UDPMagicAddress,
		ICMPUserAgent:        runtime.GOOS + " " + ICMPMagicAddress,
		HealthCheckUserAgent: runtime.GOOS,
	}
}

type Client struct {
	ctx          context.Context
	detour       N.Dialer
	server       M.Socksaddr
	auth         string
	roundTripper RoundTripper
	idle         *idleManager
	healthCheck  *healthCheckScheduler
	wrapError    func(error) error
	userAgents   ClientUserAgents
	timeFunc     func() time.Time
	resolveFunc  func(fqdn string) (netip.Addr, error)
	connTracker  *connTracker
}

func NewClient(options ClientOptions) (client *Client, err error) {
	options.UserAgents.AppName = truncateAppName(options.UserAgents.AppName)
	client = &Client{
		ctx:         options.Ctx,
		detour:      options.Detour,
		server:      options.Server,
		auth:        buildAuth(options.Auth),
		userAgents:  options.UserAgents,
		resolveFunc: options.ResolveFunc,
	}
	nextProtos := options.TLSConfig.NextProtos()
	if options.QUIC {
		if len(nextProtos) == 0 {
			nextProtos = []string{"h3"}
			options.TLSConfig.SetNextProtos(nextProtos)
		} else if !common.Contains(nextProtos, "h3") {
			return nil, E.New("require alpn h3")
		}
		err = client.quicRoundTripper(options.TLSConfig, options.QUICCongestionControl)
		if err != nil {
			return nil, err
		}
		client.timeFunc = ntp.TimeFuncFromContext(options.Ctx)
		if client.timeFunc == nil {
			client.timeFunc = time.Now
		}
	} else {
		if len(nextProtos) == 0 {
			nextProtos = []string{http2.NextProtoTLS}
			options.TLSConfig.SetNextProtos(nextProtos)
		} else if !common.Contains(nextProtos, http2.NextProtoTLS) {
			return nil, E.New("require alpn h2")
		}
		client.h2RoundTripper(options.TLSConfig)
	}
	client.idle = newIdleManager(client)
	client.healthCheck = newHealthCheckScheduler(client, options.HealthCheck)
	return client, nil
}

func (c *Client) h2RoundTripper(tlsConfig tls.Config) {
	c.connTracker = newConnTracker()
	c.roundTripper = &http2.Transport{
		DialTLSContext: func(ctx context.Context, network, addr string, cfg *stdTLS.Config) (net.Conn, error) {
			conn, err := c.detour.DialContext(ctx, N.NetworkTCP, c.server)
			if err != nil {
				return nil, err
			}
			tlsConn, err := tlsConfig.Client(conn)
			if err != nil {
				_ = conn.Close()
				return nil, err
			}
			return c.connTracker.track(tlsConn), nil
		},
		AllowHTTP:       false,
		IdleConnTimeout: DefaultSessionTimeout,
	}
	c.wrapError = baderror.WrapH2
}

func newRequest(serverAddr, host string, body io.ReadCloser) *http.Request {
	return &http.Request{
		Method: http.MethodConnect,
		URL: &url.URL{
			Scheme: "https",
			Host:   serverAddr, // HTTP/2 reuse connection based on URL.Host
		},
		Header: make(http.Header),
		Body:   body,
		Host:   host,
	}
}

func (c *Client) openStream(host string, userAgent string, conn *httpConn, keepSession bool) {
	pipeReader, pipeWriter := io.Pipe()
	conn.writer = pipeWriter
	conn.wrapError = c.wrapError
	conn.created = make(chan struct{})
	request := newRequest(c.server.String(), host, pipeReader)
	request.Header.Add("User-Agent", userAgent)
	request.Header.Add("Proxy-Authorization", c.auth)
	ctx, cancel := context.WithCancel(c.ctx)
	release := c.idle.AddStream(keepSession)
	conn.closeHook = func() {
		cancel()
		release()
	}
	go func() {
		timeoutTimer := time.AfterFunc(DefaultSessionTimeout, cancel)
		defer timeoutTimer.Stop()
		response, err := c.roundTripper.RoundTrip(request.WithContext(ctx))
		if err != nil {
			err = c.wrapError(err)
		} else if response.StatusCode != http.StatusOK {
			_ = response.Body.Close()
			err = E.New("unexpected status code: ", response.StatusCode)
		}
		if err != nil {
			_ = pipeWriter.CloseWithError(err)
			_ = pipeReader.CloseWithError(err)
			conn.setUp(nil, err)
			release()
			return
		}
		c.healthCheck.Postpone()
		conn.setUp(response.Body, nil)
	}()
}

func (c *Client) Dial(ctx context.Context, destination M.Socksaddr) (net.Conn, error) {
	conn := new(tcpConn)
	c.openStream(destination.String(), c.userAgents.TCPUserAgent, &conn.httpConn, keepSessionFromContext(ctx))
	return conn, nil
}

func (c *Client) ListenPacket(ctx context.Context) (net.PacketConn, error) {
	conn := &clientUDPConn{
		udpConn: udpConn{
			resolveFunc: c.resolveFunc,
		},
		appName: c.userAgents.AppName,
	}
	c.openStream(UDPMagicAddress, c.userAgents.UDPUserAgent, &conn.httpConn, keepSessionFromContext(ctx))
	return conn, nil
}

func (c *Client) ListenICMP(ctx context.Context) (*IcmpConn, error) {
	conn := new(IcmpConn)
	c.openStream(ICMPMagicAddress, c.userAgents.ICMPUserAgent, &conn.httpConn, keepSessionFromContext(ctx))
	return conn, nil
}

func (c *Client) Close() error {
	c.healthCheck.Stop()
	c.forceCloseAllConnections()
	if closer, isCloser := c.roundTripper.(io.Closer); isCloser {
		// HTTP/3 Transport
		_ = closer.Close()
	}
	return nil
}

func (c *Client) ResetConnections() {
	c.forceCloseAllConnections()
	c.healthCheck.Postpone()
}

func (c *Client) SetKeepIdleConnections(keep bool) {
	c.idle.SetKeep(keep)
	if keep {
		c.healthCheck.Start()
		return
	}
	c.healthCheck.Stop()
	c.idle.CloseIdle()
}

func (c *Client) CloseIdleConnections() {
	c.idle.CloseIdle()
}

func (c *Client) HealthCheck(ctx context.Context) error {
	release := c.idle.AddStream(false)
	defer release()
	defer c.healthCheck.Postpone()
	request := &http.Request{
		Method: http.MethodConnect,
		URL: &url.URL{
			Scheme: "https",
			Host:   HealthCheckMagicAddress,
		},
		Header: make(http.Header),
		Host:   HealthCheckMagicAddress,
	}
	request.Header.Add("User-Agent", c.userAgents.HealthCheckUserAgent)
	request.Header.Add("Proxy-Authorization", c.auth)
	response, err := c.roundTripper.RoundTrip(request.WithContext(ctx))
	if err != nil {
		return c.wrapError(err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return E.New("unexpected status code: ", response.StatusCode)
	}
	return nil
}

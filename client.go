package trusttunnel

import (
	"context"
	stdTLS "crypto/tls"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
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

type ClientOptions struct {
	Ctx                   context.Context
	Detour                N.Dialer
	Server                M.Socksaddr
	Auth                  auth.User
	TLSConfig             tls.Config
	QUIC                  bool
	QUICCongestionControl string
	HealthCheck           bool
	// ResolveFunc is the function to resolve FQDN for packet conn.
	// If not set, the packet conn will reject FQDN when writing.
	ResolveFunc func(fqdn string) (netip.Addr, error)
}

type Client struct {
	ctx              context.Context
	detour           N.Dialer
	server           M.Socksaddr
	auth             string
	roundTripper     RoundTripper
	healthCheckTimer *time.Timer
	wrapError        func(error) error
	timeFunc         func() time.Time
	resolveFunc      func(fqdn string) (netip.Addr, error)
}

func NewClient(options ClientOptions) (client *Client, err error) {
	client = &Client{
		ctx:         options.Ctx,
		detour:      options.Detour,
		server:      options.Server,
		auth:        buildAuth(options.Auth),
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
	if options.HealthCheck {
		client.healthCheckTimer = new(time.Timer)
	}
	return client, nil
}

func (c *Client) h2RoundTripper(tlsConfig tls.Config) {
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
			return tlsConn, nil
		},
		AllowHTTP:       false,
		IdleConnTimeout: DefaultSessionTimeout,
	}
	c.wrapError = baderror.WrapH2
}

func (c *Client) resolveServer() (M.Socksaddr, error) {
	if !c.server.IsDomain() {
		return c.server, nil
	}
	if c.resolveFunc == nil {
		return M.Socksaddr{}, E.New("resolve server without resolveFunc")
	}
	ip, err := c.resolveFunc(c.server.Fqdn)
	if err != nil {
		return M.Socksaddr{}, E.Cause(err, "resolve server")
	}
	return M.Socksaddr{
		Addr: ip,
		Port: c.server.Port,
	}, nil
}

func (c *Client) Start() error {
	if c.healthCheckTimer != nil {
		c.healthCheckTimer = time.NewTimer(DefaultHealthCheckTimeout)
		go c.loopHealthCheck()
	}
	return nil
}

func (c *Client) loopHealthCheck() {
	for {
		select {
		case <-c.healthCheckTimer.C:
		case <-c.ctx.Done():
			c.healthCheckTimer.Stop()
			return
		}
		ctx, cancel := context.WithTimeout(c.ctx, DefaultHealthCheckTimeout)
		_ = c.HealthCheck(ctx)
		cancel()
	}
}

func (c *Client) resetHealthCheckTimer() {
	if c.healthCheckTimer == nil {
		return
	}
	c.healthCheckTimer.Reset(DefaultHealthCheckTimeout)
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

func (c *Client) Dial(ctx context.Context, destination M.Socksaddr) (net.Conn, error) {
	pipeReader, pipeWriter := io.Pipe()
	host := destination.String()
	request := newRequest(c.server.String(), host, pipeReader)
	request.Header.Add("User-Agent", TCPUserAgent)
	request.Header.Add("Proxy-Authorization", c.auth)
	conn := &tcpConn{
		httpConn: httpConn{
			writer:    pipeWriter,
			wrapError: c.wrapError,
			created:   make(chan struct{}),
		},
	}
	requestCtx, cancel := context.WithCancel(c.ctx)
	conn.closeHook = cancel
	go func() {
		timeout := time.AfterFunc(DefaultSessionTimeout, cancel)
		defer timeout.Stop()
		response, err := c.roundTripper.RoundTrip(request.WithContext(requestCtx))
		if err != nil {
			err = c.wrapError(err)
			_ = pipeWriter.CloseWithError(err)
			_ = pipeReader.CloseWithError(err)
			conn.setUp(nil, err)
		} else if response.StatusCode != http.StatusOK {
			_ = response.Body.Close()
			err = E.New("unexpected status code: ", response.StatusCode)
			_ = pipeWriter.CloseWithError(err)
			_ = pipeReader.CloseWithError(err)
			conn.setUp(nil, err)
		} else {
			c.resetHealthCheckTimer()
			conn.setUp(response.Body, nil)
		}
	}()
	return conn, nil
}

func (c *Client) ListenPacket(ctx context.Context) (net.PacketConn, error) {
	pipeReader, pipeWriter := io.Pipe()
	request := newRequest(c.server.String(), UDPMagicAddress, pipeReader)
	request.Header.Add("User-Agent", UDPUserAgent)
	request.Header.Add("Proxy-Authorization", c.auth)
	conn := &clientPacketConn{
		packetConn: packetConn{
			httpConn: httpConn{
				writer:    pipeWriter,
				wrapError: c.wrapError,
				created:   make(chan struct{}),
			},
			resolveFunc: c.resolveFunc,
		},
	}
	requestCtx, cancel := context.WithCancel(c.ctx)
	conn.closeHook = cancel
	go func() {
		timeout := time.AfterFunc(DefaultSessionTimeout, cancel)
		defer timeout.Stop()
		response, err := c.roundTripper.RoundTrip(request.WithContext(requestCtx))
		if err != nil {
			err = c.wrapError(err)
			_ = pipeWriter.CloseWithError(err)
			_ = pipeReader.CloseWithError(err)
			conn.setUp(nil, err)
		} else if response.StatusCode != http.StatusOK {
			_ = response.Body.Close()
			err = E.New("unexpected status code: ", response.StatusCode)
			_ = pipeWriter.CloseWithError(err)
			_ = pipeReader.CloseWithError(err)
			conn.setUp(nil, err)
		} else {
			c.resetHealthCheckTimer()
			conn.setUp(response.Body, nil)
		}
	}()
	return conn, nil
}

func (c *Client) ListenICMP(ctx context.Context) (*IcmpConn, error) {
	pipeReader, pipeWriter := io.Pipe()
	request := newRequest(c.server.String(), ICMPMagicAddress, pipeReader)
	request.Header.Add("User-Agent", ICMPUserAgent)
	request.Header.Add("Proxy-Authorization", c.auth)
	conn := &IcmpConn{
		httpConn{
			writer:    pipeWriter,
			wrapError: c.wrapError,
			created:   make(chan struct{}),
		},
	}
	requestCtx, cancel := context.WithCancel(c.ctx)
	conn.closeHook = cancel
	go func() {
		timeoutTimer := time.AfterFunc(DefaultSessionTimeout, cancel)
		defer timeoutTimer.Stop()
		response, err := c.roundTripper.RoundTrip(request.WithContext(requestCtx))
		if err != nil {
			err = c.wrapError(err)
			_ = pipeWriter.CloseWithError(err)
			_ = pipeReader.CloseWithError(err)
			conn.setUp(nil, err)
		} else if response.StatusCode != http.StatusOK {
			_ = response.Body.Close()
			err = E.New("unexpected status code: ", response.StatusCode)
			_ = pipeWriter.CloseWithError(err)
			_ = pipeReader.CloseWithError(err)
			conn.setUp(nil, err)
		} else {
			c.resetHealthCheckTimer()
			conn.setUp(response.Body, nil)
		}
	}()
	return conn, nil
}

func (c *Client) Close() error {
	forceCloseAllConnections(c.roundTripper)
	if c.healthCheckTimer != nil {
		c.healthCheckTimer.Stop()
	}
	return nil
}

func (c *Client) ResetConnections() {
	forceCloseAllConnections(c.roundTripper)
	c.resetHealthCheckTimer()
}

func (c *Client) HealthCheck(ctx context.Context) error {
	defer c.resetHealthCheckTimer()
	request := &http.Request{
		Method: http.MethodConnect,
		URL: &url.URL{
			Scheme: "https",
			Host:   HealthCheckMagicAddress,
		},
		Header: make(http.Header),
		Host:   HealthCheckMagicAddress,
	}
	request.Header.Add("User-Agent", HealthCheckUserAgent)
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

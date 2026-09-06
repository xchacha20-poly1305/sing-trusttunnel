package trusttunnel

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptrace"
	"net/netip"
	"net/url"
	"runtime"
	"sync"
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
	cancel       context.CancelFunc
}

func NewClient(options ClientOptions) (client *Client, err error) {
	options.UserAgents.AppName = truncateAppName(options.UserAgents.AppName)
	client = &Client{
		detour:      options.Detour,
		server:      options.Server,
		auth:        buildAuth(options.Auth),
		userAgents:  options.UserAgents,
		resolveFunc: options.ResolveFunc,
	}
	client.ctx, client.cancel = context.WithCancel(options.Ctx)
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
	c.connTracker = newConnTracker(c.ctx)
	protocols := new(http.Protocols)
	protocols.SetHTTP1(false)
	protocols.SetHTTP2(true)
	protocols.SetUnencryptedHTTP2(true) // Before go 1.27, ConnectionState() is not recognized.
	c.roundTripper = &http.Transport{
		DialTLSContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return c.dialTLS(ctx, tlsConfig)
		},
		Protocols:       protocols,
		IdleConnTimeout: DefaultSessionTimeout,
	}
	c.wrapError = baderror.WrapH2
}

func (c *Client) dialTLS(ctx context.Context, tlsConfig tls.Config) (net.Conn, error) {
	dial := c.connTracker.BeginDial(ctx)
	defer dial.Cancel()
	ctx = dial.Context()
	conn, err := c.detour.DialContext(ctx, N.NetworkTCP, c.server)
	if err != nil {
		return nil, err
	}
	tracked, err := dial.Track(conn)
	if err != nil {
		return nil, err
	}
	tlsConn, err := tls.ClientHandshake(ctx, tracked, tlsConfig)
	if err != nil {
		_ = tracked.Close()
		return nil, err
	}
	if alpn := tlsConn.ConnectionState().NegotiatedProtocol; alpn != http2.NextProtoTLS {
		_ = tlsConn.Close()
		return nil, E.New("unexpected negotiated protocol: ", alpn)
	}
	return tlsConn, nil
}

func (c *Client) buildRequest(host, userAgent string, body io.ReadCloser) *http.Request {
	header := make(http.Header)
	header.Add("User-Agent", userAgent)
	header.Add("Proxy-Authorization", c.auth)
	return &http.Request{
		Method: http.MethodConnect,
		URL: &url.URL{
			Scheme: "https",
			Host:   c.server.String(), // HTTP/2 reuse connection based on URL.Host
		},
		Header: header,
		Body:   body,
		Host:   host,
	}
}

// openStream opens a new stream based on h2/h3. ctx is only for controlling cancel.
func (c *Client) openStream(ctx context.Context, host string, userAgent string, conn *httpConn) error {
	pipeReader, pipeWriter := io.Pipe()
	conn.writer = pipeWriter
	conn.wrapError = c.wrapError
	conn.created = make(chan struct{})
	request := c.buildRequest(host, userAgent, pipeReader)
	requestCtx, cancel := context.WithCancel(c.ctx)
	release := c.idle.AddStream(keepSessionFromContext(ctx))
	finish := sync.OnceFunc(func() {
		cancel()
		release()
	})
	conn.closeHook = finish
	established := make(chan error, 1)
	reportEstablished := func(err error) {
		select {
		case established <- err:
		default:
		}
	}
	requestCtx = httptrace.WithClientTrace(requestCtx, &httptrace.ClientTrace{
		GotConn: func(_ httptrace.GotConnInfo) {
			reportEstablished(nil)
		},
	})
	go func() {
		response, err := c.roundTripper.RoundTrip(request.WithContext(requestCtx))
		if err != nil {
			err = c.wrapError(err)
		} else if response.StatusCode != http.StatusOK {
			_ = response.Body.Close()
			err = E.New("unexpected status code: ", response.StatusCode)
		}
		reportEstablished(err)
		if err != nil {
			_ = pipeWriter.CloseWithError(err)
			_ = pipeReader.CloseWithError(err)
			conn.setUp(nil, err)
			finish()
			return
		}
		c.healthCheck.Postpone()
		conn.setUp(response.Body, nil)
	}()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case err := <-established:
		return err
	}
}

func (c *Client) Dial(ctx context.Context, destination M.Socksaddr) (net.Conn, error) {
	conn := new(tcpConn)
	err := c.openStream(ctx, destination.String(), c.userAgents.TCPUserAgent, &conn.httpConn)
	if err != nil {
		_ = conn.Close()
		return nil, err
	}
	return conn, nil
}

func (c *Client) ListenPacket(ctx context.Context) (net.PacketConn, error) {
	conn := &clientUDPConn{
		udpConn: udpConn{
			resolveFunc: c.resolveFunc,
		},
		appName: c.userAgents.AppName,
	}
	err := c.openStream(ctx, UDPMagicAddress, c.userAgents.UDPUserAgent, &conn.httpConn)
	if err != nil {
		_ = conn.Close()
		return nil, err
	}
	return conn, nil
}

func (c *Client) ListenICMP(ctx context.Context) (*IcmpConn, error) {
	conn := new(IcmpConn)
	err := c.openStream(ctx, ICMPMagicAddress, c.userAgents.ICMPUserAgent, &conn.httpConn)
	if err != nil {
		_ = conn.Close()
		return nil, err
	}
	return conn, nil
}

func (c *Client) Close() error {
	c.cancel()
	c.healthCheck.Stop()
	var errs []error
	if err := c.forceCloseAllConnections(); err != nil {
		errs = append(errs, err)
	}
	if closer, isCloser := c.roundTripper.(io.Closer); isCloser {
		// HTTP/3 Transport
		if err := closer.Close(); err != nil {
			errs = append(errs, err)
		}
	}
	return E.Errors(errs...)
}

func (c *Client) ResetConnections() {
	_ = c.forceCloseAllConnections()
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
	request := c.buildRequest(HealthCheckMagicAddress, c.userAgents.HealthCheckUserAgent, nil)
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

package trusttunnel

import (
	"context"
	"net"
	"net/http/httptrace"
	"os"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"github.com/sagernet/sing/common"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
	"github.com/sagernet/sing/common/tls"

	"github.com/stretchr/testify/require"
)

type failingDialer struct {
	err error
}

func (d *failingDialer) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	return nil, d.err
}

func (d *failingDialer) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	return nil, d.err
}

type blockingDialer struct {
	dialCtx chan context.Context
}

func newBlockingDialer() *blockingDialer {
	return &blockingDialer{dialCtx: make(chan context.Context, 1)}
}

func (d *blockingDialer) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	select {
	case d.dialCtx <- ctx:
	default:
	}
	<-ctx.Done()
	return nil, ctx.Err()
}

func (d *blockingDialer) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	return nil, ctx.Err()
}

func streamCount(client *Client) int {
	client.idle.access.Lock()
	defer client.idle.access.Unlock()
	return client.idle.streamCount
}

func TestDialReportsDialFailure(t *testing.T) {
	t.Parallel()

	dialErr := E.New("dial refused")
	for name, dial := range map[string]func(ctx context.Context, client *Client) error{
		"TCP": func(ctx context.Context, client *Client) error {
			_, err := client.Dial(ctx, M.ParseSocksaddr("example.com:80"))
			return err
		},
		"UDP": func(ctx context.Context, client *Client) error {
			_, err := client.ListenPacket(ctx)
			return err
		},
		"ICMP": func(ctx context.Context, client *Client) error {
			_, err := client.ListenICMP(ctx)
			return err
		},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			serverStd, clientStd := generateTestTLSPair(t)
			s := newTestSetupWith(t, &testServerTLSConfig{config: serverStd}, &testClientTLSConfig{config: clientStd}, &failingDialer{err: dialErr})
			err := dial(t.Context(), s.client)
			require.ErrorIs(t, err, dialErr)
			require.Equal(t, 0, streamCount(s.client))
		})
	}
}

func TestDialRespectsContext(t *testing.T) {
	t.Parallel()

	dialer := newBlockingDialer()
	serverStd, clientStd := generateTestTLSPair(t)
	s := newTestSetupWith(t, &testServerTLSConfig{config: serverStd}, &testClientTLSConfig{config: clientStd}, dialer)

	ctx, cancel := context.WithTimeout(t.Context(), 100*time.Millisecond)
	defer cancel()
	_, err := s.client.Dial(ctx, M.ParseSocksaddr("example.com:80"))
	require.ErrorIs(t, err, context.DeadlineExceeded)
	require.Equal(t, 0, streamCount(s.client))

	select {
	case <-dialer.dialCtx:
	default:
		t.Fatal("detour was never dialed")
	}
}

// TestRoundTripperReportsGotConn guards the assumption openStream relies on:
// the round tripper reports GotConn as soon as the connection to the server is
// usable. Without it openStream would silently fall back to waiting for the
// whole response, losing the ability to write before the server replies.
func TestRoundTripperReportsGotConn(t *testing.T) {
	t.Parallel()
	s := newTestSetup(t)

	gotConn := make(chan struct{}, 1)
	ctx := httptrace.WithClientTrace(t.Context(), &httptrace.ClientTrace{
		GotConn: func(httptrace.GotConnInfo) {
			select {
			case gotConn <- struct{}{}:
			default:
			}
		},
	})
	require.NoError(t, s.client.HealthCheck(ctx))
	select {
	case <-gotConn:
	default:
		t.Fatal("GotConn was never reported")
	}
}

// pipeDialer hands out connections nothing ever reads from, enough for a fake
// TLS handshake that performs no I/O.
type pipeDialer struct {
	access sync.Mutex
	remote []net.Conn
}

func (d *pipeDialer) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	local, remote := net.Pipe()
	d.access.Lock()
	d.remote = append(d.remote, remote)
	d.access.Unlock()
	return local, nil
}

func (d *pipeDialer) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	return nil, os.ErrInvalid
}

func (d *pipeDialer) Close() error {
	d.access.Lock()
	defer d.access.Unlock()
	return common.Close(common.Map(d.remote, func(it net.Conn) any { return it })...)
}

// TestDialRejectsUnexpectedALPN covers the check dialTLS has to make itself:
// http.Transport silently downgrades to HTTP/1.1 when the connection state
// says anything but h2, even with HTTP/1.1 left out of Protocols.
func TestDialRejectsUnexpectedALPN(t *testing.T) {
	t.Parallel()

	dialer := new(pipeDialer)
	t.Cleanup(func() { _ = dialer.Close() })
	client, err := NewClient(ClientOptions{
		Ctx:       t.Context(),
		Detour:    dialer,
		Server:    M.ParseSocksaddr("127.0.0.1:443"),
		TLSConfig: &fakeTLSConfig{negotiatedProtocol: "http/1.1"},
	})
	require.NoError(t, err)
	t.Cleanup(func() { _ = client.Close() })

	_, err = client.Dial(t.Context(), M.ParseSocksaddr("example.com:80"))
	require.ErrorContains(t, err, "unexpected negotiated protocol: http/1.1")
}

func TestSharedDialLifecycle(t *testing.T) {
	t.Parallel()
	testSharedDialLifecycle(t, false)
}

func testSharedDialLifecycle(t *testing.T, useQUIC bool) {
	t.Helper()
	for _, action := range []string{"close", "cancel client", "reset"} {
		t.Run(action, func(t *testing.T) {
			t.Parallel()
			clientCtx, cancelClient := context.WithCancel(t.Context())
			defer cancelClient()
			dialer := newBlockingDialer()
			client, err := NewClient(ClientOptions{
				Ctx: clientCtx, Detour: dialer,
				Server: M.ParseSocksaddr("127.0.0.1:443"), TLSConfig: new(fakeTLSConfig), QUIC: useQUIC,
			})
			require.NoError(t, err)
			t.Cleanup(func() { _ = client.Close() })
			client.SetKeepIdleConnections(true)

			requestCtx, cancelRequest := context.WithCancel(t.Context())
			defer cancelRequest()
			result := make(chan error, 1)
			go func() {
				_, err := client.Dial(requestCtx, M.ParseSocksaddr("example.com:80"))
				result <- err
			}()
			dialCtx := receiveDialContext(t, dialer)
			if !useQUIC {
				// Not checked over QUIC: the HTTP/3 client pool answers the next
				// request from the entry a canceled requester leaves behind, which
				// would hide the new dial the reset case looks for below.
				// TestBeginDialIgnoresRequesterCancellation covers the dial itself.
				cancelRequest()
				select {
				case err := <-result:
					require.ErrorIs(t, err, context.Canceled)
				case <-time.After(2 * time.Second):
					t.Fatal("request cancellation did not end Dial")
				}
				require.NoError(t, dialCtx.Err(), "shared dial must survive cancellation of its requester")
			}

			switch action {
			case "close":
				require.NoError(t, client.Close())
			case "cancel client":
				cancelClient()
			case "reset":
				client.ResetConnections()
			}
			select {
			case <-dialCtx.Done():
			case <-time.After(2 * time.Second):
				t.Fatal("client lifecycle change did not cancel shared dial")
			}
			if useQUIC {
				select {
				case err := <-result:
					require.Error(t, err)
				case <-time.After(2 * time.Second):
					t.Fatal("client lifecycle change did not end Dial")
				}
			}

			if action == "reset" {
				go func() {
					_, err := client.Dial(t.Context(), M.ParseSocksaddr("example.com:80"))
					result <- err
				}()
				newCtx := receiveDialContext(t, dialer)
				require.NoError(t, newCtx.Err(), "reset must allow new dials")
				require.NoError(t, client.Close())
				select {
				case err := <-result:
					require.Error(t, err)
				case <-time.After(2 * time.Second):
					t.Fatal("Close did not end the new Dial")
				}
			}
		})
	}
}

func receiveDialContext(t *testing.T, dialer *blockingDialer) context.Context {
	t.Helper()
	select {
	case ctx := <-dialer.dialCtx:
		return ctx
	case <-time.After(2 * time.Second):
		t.Fatal("detour was not dialed")
		return nil
	}
}

type delayedPipeDialer struct {
	pipeDialer
}

func (d *delayedPipeDialer) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	time.Sleep(10 * time.Second)
	return d.pipeDialer.DialContext(ctx, network, destination)
}

type blockingHandshakeConfig struct {
	fakeTLSConfig
	timeout time.Duration
}

func (c *blockingHandshakeConfig) HandshakeTimeout() time.Duration { return c.timeout }

func (c *blockingHandshakeConfig) Client(conn net.Conn) (tls.Conn, error) {
	return &blockingHandshakeConn{fakeTLSConn: fakeTLSConn{Conn: conn}}, nil
}

type blockingHandshakeConn struct {
	fakeTLSConn
}

func (c *blockingHandshakeConn) HandshakeContext(ctx context.Context) error {
	<-ctx.Done()
	return ctx.Err()
}

// The only deadline dialTLS honors comes from the caller: the TLS config here,
// and the request context in TestSharedDialLifecycle.
func TestDialTLSHandshakeTimeout(t *testing.T) {
	t.Parallel()
	synctest.Test(t, func(t *testing.T) {
		dialer := new(delayedPipeDialer)
		defer dialer.Close()
		config := &blockingHandshakeConfig{timeout: 5 * time.Second}
		client, err := NewClient(ClientOptions{Ctx: t.Context(), Detour: dialer, TLSConfig: config})
		require.NoError(t, err)
		defer client.Close()
		start := time.Now()
		_, err = client.dialTLS(t.Context(), config)
		require.ErrorIs(t, err, context.DeadlineExceeded)
		require.Equal(t, 10*time.Second+config.timeout, time.Since(start))
		require.Zero(t, trackerLen(client.connTracker))
	})
}

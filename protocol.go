// Package trusttunnel implements the TrustTunnel protocol.
package trusttunnel

import (
	"bytes"
	"encoding/base64"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"sync"
	"time"

	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/auth"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
)

const (
	Version                 = "v0.3.2"
	UDPMagicAddress         = "_udp2"
	ICMPMagicAddress        = "_icmp"
	HealthCheckMagicAddress = "_check"

	AppName = "sing-trusttunnel"

	DefaultQuicStreamReceiveWindow = 131072 // Chrome's default
	DefaultHealthCheckTimeout      = 7 * time.Second
	DefaultSessionTimeout          = 30 * time.Second
	DefaultQuicMaxIdleTimeout      = 2 * (DefaultSessionTimeout + DefaultHealthCheckTimeout)
)

var ErrQUICNotIncluded = E.New("QUIC is not included")

func buildAuth(user auth.User) string {
	return "Basic " + base64.StdEncoding.EncodeToString([]byte(user.Username+":"+user.Password))
}

func parse16BytesIP(buffer [16]byte) netip.Addr {
	var zeroPrefix [12]byte
	isIPv4 := bytes.HasPrefix(buffer[:], zeroPrefix[:])
	// Special: check ::1
	isIPv4 = isIPv4 && !(buffer[12] == 0 && buffer[13] == 0 && buffer[14] == 0 && buffer[15] == 1)
	if isIPv4 {
		return netip.AddrFrom4([4]byte(buffer[12:16]))
	}
	return netip.AddrFrom16(buffer)
}

func buildPaddingIP(addr netip.Addr) (buffer [16]byte) {
	if addr.Is6() {
		return addr.As16()
	}
	ipv4 := addr.As4()
	copy(buffer[12:16], ipv4[:])
	return buffer
}

type httpConn struct {
	writer    io.Writer
	flusher   http.Flusher
	wrapError func(error) error
	closeHook func()
	created   chan struct{}

	// access guards that body arrives only when the stream is set up, which may happen after Closing.
	access    sync.Mutex
	closed    bool
	body      io.ReadCloser
	createErr error
}

func (h *httpConn) setUp(body io.ReadCloser, err error) {
	h.access.Lock()
	closed := h.closed
	if !closed {
		h.body = body
	} else if err == nil {
		err = net.ErrClosed
	}
	h.createErr = err
	h.access.Unlock()
	close(h.created)
	if closed {
		_ = common.Close(body)
	}
}

func (h *httpConn) waitCreated() error {
	<-h.created
	return h.createErr
}

func (h *httpConn) Close() error {
	if h.closeHook != nil {
		h.closeHook()
	}
	h.access.Lock()
	h.closed = true
	body := h.body
	h.access.Unlock()
	return common.Close(
		h.writer,
		body,
	)
}

func (h *httpConn) writeFlush(p []byte) (n int, err error) {
	n, err = h.writer.Write(p)
	if h.flusher != nil {
		h.flusher.Flush()
	}
	return n, h.wrapError(err)
}

func (h *httpConn) LocalAddr() net.Addr {
	return M.Socksaddr{}
}

func (h *httpConn) RemoteAddr() net.Addr {
	return M.Socksaddr{}
}

func (h *httpConn) SetDeadline(t time.Time) error {
	return os.ErrInvalid
}

func (h *httpConn) SetReadDeadline(t time.Time) error {
	return os.ErrInvalid
}

func (h *httpConn) SetWriteDeadline(t time.Time) error {
	return os.ErrInvalid
}

var _ net.Conn = (*tcpConn)(nil)

type tcpConn struct {
	httpConn
}

func (t *tcpConn) Read(b []byte) (n int, err error) {
	err = t.waitCreated()
	if err != nil {
		return 0, err
	}
	n, err = t.body.Read(b)
	err = t.wrapError(err)
	return
}

func (t *tcpConn) Write(b []byte) (int, error) {
	return t.writeFlush(b)
}

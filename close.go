package trusttunnel

import (
	"context"
	"net"
	"sync"
	"sync/atomic"

	"github.com/sagernet/sing/common"
	E "github.com/sagernet/sing/common/exceptions"
	N "github.com/sagernet/sing/common/network"
)

func (c *Client) forceCloseAllConnections() error {
	c.roundTripper.CloseIdleConnections()
	return c.connTracker.Close()
}

type connTracker struct {
	parent context.Context

	access sync.Mutex
	conns  map[trackedConn]struct{}
	// derivedContext is canceled by Close to abort the dials it started. Close then
	// opens a new one, so dials started afterward are not born canceled.
	derivedContext context.Context
	cancel         context.CancelFunc
}

func newConnTracker(ctx context.Context) *connTracker {
	tracker := &connTracker{
		parent: ctx,
		conns:  make(map[trackedConn]struct{}),
	}
	tracker.derivedContext, tracker.cancel = context.WithCancel(ctx)
	return tracker
}

func (c *connTracker) BeginDial(ctx context.Context) *trackedDial {
	c.access.Lock()
	derivedContext := c.derivedContext
	c.access.Unlock()
	dial := &trackedDial{tracker: c, derivedContext: derivedContext}
	dial.ctx, dial.cancel = context.WithCancel(context.WithoutCancel(ctx))
	dial.stopCancel = context.AfterFunc(derivedContext, dial.cancel)
	return dial
}

func (c *connTracker) Close() error {
	c.access.Lock()
	c.cancel()
	c.derivedContext, c.cancel = context.WithCancel(c.parent)
	conns := make([]trackedConn, 0, len(c.conns))
	for conn := range c.conns {
		conns = append(conns, conn)
	}
	clear(c.conns)
	c.access.Unlock()
	var errs []error
	for _, conn := range conns {
		err := conn.closeFromTracker()
		if err != nil {
			errs = append(errs, err)
		}
	}
	return E.Errors(errs...)
}

func (c *connTracker) Untrack(conn trackedConn) {
	c.access.Lock()
	defer c.access.Unlock()
	delete(c.conns, conn)
}

type trackedDial struct {
	tracker        *connTracker
	derivedContext context.Context
	ctx            context.Context
	cancel         context.CancelFunc
	stopCancel     func() bool
}

func (d *trackedDial) Context() context.Context {
	return d.ctx
}

func (d *trackedDial) Track(conn net.Conn) (trackedConn, error) {
	tracker := d.tracker
	tracker.access.Lock()
	err := d.derivedContext.Err()
	if err != nil {
		tracker.access.Unlock()
		_ = conn.Close()
		return nil, err
	}
	tracked := &trackedCommonConn{Conn: conn, tracker: tracker}
	tracker.conns[tracked] = struct{}{}
	tracker.access.Unlock()
	return tracked, nil
}

func (d *trackedDial) Cancel() {
	d.stopCancel()
	d.cancel()
}

type trackedConn interface {
	net.Conn
	closeFromTracker() error
}

var (
	_ trackedConn = (*trackedCommonConn)(nil)

	// Expose underlying syscall conn wrapper for quic-go
	_ common.WithUpstream  = (*trackedCommonConn)(nil)
	_ N.ReaderWithUpstream = (*trackedCommonConn)(nil)
	_ N.WriterWithUpstream = (*trackedCommonConn)(nil)
)

type trackedCommonConn struct {
	net.Conn
	closed  atomic.Bool
	tracker *connTracker
}

func (t *trackedCommonConn) Close() error {
	if t.closed.Swap(true) {
		return net.ErrClosed
	}
	t.tracker.Untrack(t)
	return t.Conn.Close()
}

func (t *trackedCommonConn) closeFromTracker() error {
	t.closed.Store(true)
	return t.Conn.Close()
}

func (t *trackedCommonConn) WriterReplaceable() bool {
	return true
}

func (t *trackedCommonConn) ReaderReplaceable() bool {
	return true
}

func (t *trackedCommonConn) Upstream() any {
	return t.Conn
}

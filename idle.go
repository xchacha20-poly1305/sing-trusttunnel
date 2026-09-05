package trusttunnel

import (
	"sync"
)

type idleManager struct {
	client *Client

	access      sync.Mutex
	keep        bool
	streamCount int
}

func newIdleManager(client *Client) *idleManager {
	return &idleManager{client: client}
}

func (m *idleManager) SetKeep(keep bool) {
	m.access.Lock()
	defer m.access.Unlock()
	m.keep = keep
}

func (m *idleManager) AddStream(keepSession bool) (release func()) {
	m.access.Lock()
	m.streamCount++
	m.access.Unlock()
	return sync.OnceFunc(func() {
		m.releaseStream(keepSession)
	})
}

func (m *idleManager) releaseStream(keepSession bool) {
	m.access.Lock()
	defer m.access.Unlock()
	m.streamCount--
	if m.streamCount > 0 || m.keep || keepSession {
		return
	}
	m.closeIdleLocked()
}

func (m *idleManager) CloseIdle() {
	m.access.Lock()
	defer m.access.Unlock()
	m.closeIdleLocked()
}

func (m *idleManager) closeIdleLocked() {
	if m.streamCount > 0 {
		m.client.roundTripper.CloseIdleConnections()
		return
	}
	m.client.forceCloseAllConnections()
}

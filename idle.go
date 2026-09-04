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

func newIdleManager(client *Client, keep bool) *idleManager {
	return &idleManager{
		client: client,
		keep:   keep,
	}
}

func (m *idleManager) Keeping() bool {
	m.access.Lock()
	defer m.access.Unlock()
	return m.keep
}

func (m *idleManager) SetKeep(keep bool) (changed bool) {
	m.access.Lock()
	defer m.access.Unlock()
	if m.keep == keep {
		return false
	}
	m.keep = keep
	return true
}

func (m *idleManager) AddStream() (release func()) {
	m.access.Lock()
	m.streamCount++
	m.access.Unlock()
	return sync.OnceFunc(m.releaseStream)
}

func (m *idleManager) releaseStream() {
	m.access.Lock()
	defer m.access.Unlock()
	m.streamCount--
	if m.streamCount > 0 || m.keep {
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

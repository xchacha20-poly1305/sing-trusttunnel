package trusttunnel

import (
	"context"
	"sync"
	"time"
)

type idleManager struct {
	client      *Client
	healthCheck bool

	access      sync.Mutex
	keep        bool
	streamCount int
	timer       *time.Timer

	done      chan struct{}
	closeOnce sync.Once
}

func newIdleController(client *Client, healthCheck bool) *idleManager {
	return &idleManager{
		client:      client,
		healthCheck: healthCheck,
		keep:        true,
		done:        make(chan struct{}),
	}
}

func (m *idleManager) Start() {
	if !m.healthCheck {
		return
	}
	m.access.Lock()
	defer m.access.Unlock()
	m.timer = time.NewTimer(DefaultHealthCheckTimeout)
	go m.loopHealthCheck()
}

func (m *idleManager) loopHealthCheck() {
	for {
		select {
		case <-m.done:
			return
		case <-m.client.ctx.Done():
			m.StopTimer()
			return
		case <-m.timer.C:
		}
		if !m.isKeeping() {
			// No keep means no health check, too.
			continue
		}
		ctx, cancel := context.WithTimeout(m.client.ctx, DefaultHealthCheckTimeout)
		_ = m.client.HealthCheck(ctx)
		cancel()
	}
}

func (m *idleManager) isKeeping() bool {
	m.access.Lock()
	defer m.access.Unlock()
	return m.keep
}

func (m *idleManager) SetKeep(keep bool) {
	m.access.Lock()
	defer m.access.Unlock()
	if m.keep == keep {
		return
	}
	m.keep = keep
	if keep {
		m.resetTimerLocked()
		return
	}
	m.stopTimerLocked()
	m.closeIdleLocked()
}

func (m *idleManager) Activize() {
	m.access.Lock()
	defer m.access.Unlock()
	if !m.keep {
		return
	}
	m.resetTimerLocked()
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

func (m *idleManager) resetTimerLocked() {
	if m.timer == nil {
		return
	}
	m.timer.Reset(DefaultHealthCheckTimeout)
}

func (m *idleManager) Close() {
	m.closeOnce.Do(func() {
		close(m.done)
	})
	m.StopTimer()
}

func (m *idleManager) StopTimer() {
	m.access.Lock()
	defer m.access.Unlock()
	m.stopTimerLocked()
}

func (m *idleManager) stopTimerLocked() {
	if m.timer == nil {
		return
	}
	m.timer.Stop()
}

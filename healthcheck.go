package trusttunnel

import (
	"context"
	"sync"
	"time"
)

type healthCheckScheduler struct {
	client *Client

	access  sync.Mutex
	started bool
	timer   *time.Timer
}

func newHealthCheckScheduler(client *Client, enabled bool) *healthCheckScheduler {
	if !enabled {
		return nil
	}
	return &healthCheckScheduler{client: client}
}

func (h *healthCheckScheduler) Start() {
	if h == nil {
		return
	}
	h.access.Lock()
	defer h.access.Unlock()
	h.started = true
	h.resetTimerLocked()
}

// Postpone resets timer to postpone next health check. Invoke it after new stream established because a new stream is an alternative of health check.
func (h *healthCheckScheduler) Postpone() {
	if h == nil {
		return
	}
	h.access.Lock()
	defer h.access.Unlock()
	if !h.started {
		return
	}
	h.resetTimerLocked()
}

func (h *healthCheckScheduler) Stop() {
	if h == nil {
		return
	}
	h.access.Lock()
	defer h.access.Unlock()
	h.started = false
	if h.timer != nil {
		h.timer.Stop()
	}
}

func (h *healthCheckScheduler) resetTimerLocked() {
	if h.timer == nil {
		h.timer = time.AfterFunc(DefaultHealthCheckTimeout, h.healthCheck)
		return
	}
	h.timer.Reset(DefaultHealthCheckTimeout)
}

func (h *healthCheckScheduler) healthCheck() {
	h.access.Lock()
	started := h.started
	h.access.Unlock()
	if !started {
		return
	}
	ctx, cancel := context.WithTimeout(h.client.ctx, DefaultHealthCheckTimeout)
	defer cancel()
	_ = h.client.HealthCheck(ctx)
	if h.client.ctx.Err() != nil {
		h.Stop()
		return
	}
	h.Postpone()
}

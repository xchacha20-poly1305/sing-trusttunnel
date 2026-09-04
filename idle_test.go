package trusttunnel

import (
	"io"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestSetKeepIdleConnectionsClosesAfterLastStream(t *testing.T) {
	t.Parallel()

	dialer := newTrackingDialer()
	serverStd, clientStd := generateTestTLSPair(t)
	s := newTestSetupWith(t, false, &testServerTLSConfig{config: serverStd}, &testClientTLSConfig{config: clientStd}, dialer)

	stream := openLiveTCP(t, s.client, []byte("keep"))
	require.Equal(t, 1, dialer.liveCount())

	// A stream is still open, so the connection must survive.
	s.client.SetKeepIdleConnections(false)
	require.Equal(t, 1, dialer.liveCount())
	assertStreamsStillLive(t, []io.Closer{stream})

	require.NoError(t, stream.Close())
	require.Equal(t, 0, dialer.liveCount(), "the last stream going away must close the connection")
	require.Equal(t, 0, trackerLen(s.client.connTracker))
}

func TestSetKeepIdleConnectionsClosesIdleConnection(t *testing.T) {
	t.Parallel()

	dialer := newTrackingDialer()
	serverStd, clientStd := generateTestTLSPair(t)
	s := newTestSetupWith(t, true, &testServerTLSConfig{config: serverStd}, &testClientTLSConfig{config: clientStd}, dialer)

	stream := openLiveTCP(t, s.client, []byte("idle"))
	require.NoError(t, stream.Close())
	// Keeping is still enabled, so the idle connection is held open.
	require.Equal(t, 1, dialer.liveCount())

	s.client.SetKeepIdleConnections(false)
	require.Equal(t, 0, dialer.liveCount())
	require.Equal(t, 0, trackerLen(s.client.connTracker))
}

func TestKeepIdleConnectionsResumed(t *testing.T) {
	t.Parallel()

	dialer := newTrackingDialer()
	serverStd, clientStd := generateTestTLSPair(t)
	s := newTestSetupWith(t, false, &testServerTLSConfig{config: serverStd}, &testClientTLSConfig{config: clientStd}, dialer)

	s.client.SetKeepIdleConnections(false)
	stream := openLiveTCP(t, s.client, []byte("suspended"))
	require.NoError(t, stream.Close())
	require.Equal(t, 0, dialer.liveCount(), "a suspended client must not keep the connection it just dialed")

	s.client.SetKeepIdleConnections(true)
	resumed := openLiveTCP(t, s.client, []byte("resumed"))
	require.NoError(t, resumed.Close())
	require.Equal(t, 1, dialer.liveCount(), "the connection must be kept again after resuming")
}

func TestSetKeepIdleConnectionsSuspendsHealthCheck(t *testing.T) {
	t.Parallel()

	s := newTestSetup(t)
	controller := newIdleController(s.client, true, true)
	controller.Start()
	require.True(t, controller.timer.Stop(), "the health check timer should be armed")
	controller.timer.Reset(DefaultHealthCheckTimeout)

	controller.SetKeep(false)
	require.False(t, controller.timer.Stop(), "suspending must stop the health check timer")

	controller.SetKeep(true)
	require.True(t, controller.timer.Stop(), "resuming must arm the health check timer again")
}

func TestIdleControllerDoubleRelease(t *testing.T) {
	t.Parallel()

	s := newTestSetup(t)
	controller := newIdleController(s.client, false, true)
	release := controller.AddStream()
	release()
	release()
	controller.access.Lock()
	defer controller.access.Unlock()
	require.Zero(t, controller.streamCount)
}

func TestNewClientDefaultDoesNotKeepConnections(t *testing.T) {
	t.Parallel()

	dialer := newTrackingDialer()
	serverStd, clientStd := generateTestTLSPair(t)
	s := newTestSetupWith(t, false, &testServerTLSConfig{config: serverStd}, &testClientTLSConfig{config: clientStd}, dialer)

	stream := openLiveTCP(t, s.client, []byte("no-keep"))
	require.Equal(t, 1, dialer.liveCount())

	require.NoError(t, stream.Close())
	require.Equal(t, 0, dialer.liveCount(), "default client must not keep connections after the last stream closes")
	require.Equal(t, 0, trackerLen(s.client.connTracker))
}

func TestNewClientWithKeepSessionKeepsConnections(t *testing.T) {
	t.Parallel()

	dialer := newTrackingDialer()
	serverStd, clientStd := generateTestTLSPair(t)
	s := newTestSetupWith(t, true, &testServerTLSConfig{config: serverStd}, &testClientTLSConfig{config: clientStd}, dialer)

	stream := openLiveTCP(t, s.client, []byte("keep"))
	require.NoError(t, stream.Close())
	require.Equal(t, 1, dialer.liveCount(), "client with ContextWithKeepSession must keep connections after the last stream closes")
}

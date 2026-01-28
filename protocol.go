package trusttunnel

import (
	"bytes"
	"encoding/base64"
	"net/netip"
	"runtime"
	"time"

	"github.com/sagernet/sing/common/auth"
	E "github.com/sagernet/sing/common/exceptions"
)

const (
	Version = "v0.0.0"

	UDPMagicAddress  = "_udp2"
	ICMPMagicAddress = "_icmp"

	DefaultQuicStreamReceiveWindow = 131072 // Chrome's default
	DefaultConnectionTimeout       = 30 * time.Second
	DefaultHealthCheckTimeout      = 7 * time.Second
	DefaultQuicMaxIdleTimeout      = 2 * (DefaultConnectionTimeout + DefaultHealthCheckTimeout)
)

var (
	AppName = "sing-trusttunnel"

	// TCPUserAgent is user-agent for TCP connections.
	// Format: <platform> <app_name>
	TCPUserAgent = runtime.GOOS + " " + AppName + "/" + Version

	// UDPUserAgent is user-agent for UDP multiplexing.
	// Format: <platform> _udp2
	UDPUserAgent = runtime.GOOS + " " + UDPMagicAddress

	// ICMPUserAgent is user-agent for ICMP multiplexing.
	// Format: <platform> _icmp
	ICMPUserAgent = runtime.GOOS + " " + ICMPMagicAddress
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

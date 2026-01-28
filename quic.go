//go:build with_quic

package trusttunnel

import (
	"context"
	stdTLS "crypto/tls"
	"runtime"

	"github.com/sagernet/quic-go"
	"github.com/sagernet/quic-go/congestion"
	"github.com/sagernet/quic-go/http3"
	"github.com/sagernet/sing/common/baderror"
	"github.com/sagernet/sing/common/tls"
)

func (c *Client) quicRoundTripper(tlsConfig tls.Config, congestionControlName string) error {
	stdConfig, err := tlsConfig.STDConfig()
	if err != nil {
		return err
	}
	c.roundTripper = &http3.Transport{
		TLSClientConfig: stdConfig,
		QUICConfig: &quic.Config{
			Versions:                   []quic.Version{quic.Version1},
			MaxIdleTimeout:             DefaultQuicMaxIdleTimeout,
			InitialStreamReceiveWindow: DefaultQuicStreamReceiveWindow,
			DisablePathMTUDiscovery:    !(runtime.GOOS == "windows" || runtime.GOOS == "linux" || runtime.GOOS == "android" || runtime.GOOS == "darwin"),
			Allow0RTT:                  false,
		},
		Dial: func(ctx context.Context, addr string, tlsCfg *stdTLS.Config, cfg *quic.Config) (*quic.Conn, error) {
			packetConn, err := c.detour.ListenPacket(ctx, c.server)
			if err != nil {
				return nil, err
			}
			quicConn, err := quic.DialEarly(ctx, packetConn, c.server, tlsCfg, cfg)
			if err != nil {
				_ = packetConn.Close()
				return nil, err
			}
			if SetCongestionControl != nil {
				SetCongestionControl(ctx, quicConn, congestionControlName)
			}
			return quicConn, nil
		},
	}
	if WrapH3Error == nil {
		//goland:noinspection GoDeprecation
		c.wrapError = baderror.WrapQUIC
	} else {
		c.wrapError = WrapH3Error
	}
	return nil
}

var SetCongestionControl func(ctx context.Context, conn *quic.Conn, name string) congestion.CongestionControl

var WrapH3Error func(err error) error

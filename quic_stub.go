//go:build !with_quic

package trusttunnel

func (c *Client) quicRoundTripper() error {
	return ErrQUICNotIncluded
}

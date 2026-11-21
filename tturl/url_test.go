package tturl

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"io"
	"net/netip"
	"strings"
	"testing"

	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/buf"
	F "github.com/sagernet/sing/common/format"
	M "github.com/sagernet/sing/common/metadata"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRoundTrip_MinimalConfig(t *testing.T) {
	t.Parallel()
	original := URL{
		Hostname:  "vpn.example.com",
		Addresses: []M.Socksaddr{{Addr: netip.MustParseAddr("1.2.3.4"), Port: 443}},
		Username:  "alice",
		Password:  "secret123",
	}

	link, err := original.Build()
	require.NoError(t, err)
	require.True(t, strings.HasPrefix(link, "tt://?"))

	parsed, err := Parse(link)
	require.NoError(t, err)
	require.Equal(t, original.Hostname, parsed.Hostname)
	assertAddressesEqual(t, parsed.Addresses, original.Addresses)
	require.Equal(t, original.Username, parsed.Username)
	require.Equal(t, original.Password, parsed.Password)
	require.EqualValues(t, UpstreamProtocolHTTP2, parsed.UpstreamProtocol)
	require.False(t, parsed.AntiDPI)
}

func TestRoundTrip_MaximalConfig(t *testing.T) {
	t.Parallel()
	original := URL{
		Hostname: "secure.vpn.example.com",
		Addresses: []M.Socksaddr{
			{Addr: netip.MustParseAddr("192.168.1.1"), Port: 8443},
			{Addr: netip.MustParseAddr("10.0.0.0"), Port: 8443},
		},
		CustomSNI:          "cdn.example.org",
		Username:           "premium_user",
		Password:           "very_secret_password_123",
		ClientRandomPrefix: ClientRandomPrefix{Prefix: []byte{0xaa, 0xbb, 0xcc}},
		SkipVerification:   true,
		Certificate:        []byte{0x30, 0x82, 0x01, 0x23},
		UpstreamProtocol:   UpstreamProtocolHTTP3,
		AntiDPI:            true,
		Name:               "My VPN Server",
		DNSUpstreams: []string{
			"1.1.1.1",
			"tls://dns.example.com",
			"https://dns.example.com/dns-query",
		},
	}

	link, err := original.Build()
	require.NoError(t, err)

	parsed, err := Parse(link)
	require.NoError(t, err)

	require.Equal(t, original.Hostname, parsed.Hostname)
	assertAddressesEqual(t, parsed.Addresses, original.Addresses)
	require.Equal(t, original.CustomSNI, parsed.CustomSNI)
	require.Equal(t, original.Username, parsed.Username)
	require.Equal(t, original.Password, parsed.Password)
	require.Equal(t, original.ClientRandomPrefix, parsed.ClientRandomPrefix)
	require.Equal(t, original.SkipVerification, parsed.SkipVerification)
	require.Equal(t, original.Certificate, parsed.Certificate)
	require.Equal(t, original.UpstreamProtocol, parsed.UpstreamProtocol)
	require.Equal(t, original.AntiDPI, parsed.AntiDPI)
	require.Equal(t, original.Name, parsed.Name)
	require.Equal(t, original.DNSUpstreams, parsed.DNSUpstreams)
}

func TestRoundTrip_MultipleAddresses(t *testing.T) {
	t.Parallel()
	original := URL{
		Hostname: "multi.vpn.com",
		Addresses: []M.Socksaddr{
			{Addr: netip.MustParseAddr("1.1.1.1"), Port: 443},
			{Addr: netip.MustParseAddr("8.8.8.8"), Port: 8443},
			{Addr: netip.MustParseAddr("9.9.9.9"), Port: 9443},
		},
		Username: "multiaddr",
		Password: "test123",
	}
	link, err := original.Build()
	require.NoError(t, err)

	parsed, err := Parse(link)
	require.NoError(t, err)

	assertAddressesEqual(t, parsed.Addresses, original.Addresses)
}

func TestRoundTrip_LongValues(t *testing.T) {
	t.Parallel()
	longPassword := strings.Repeat("a", 200)
	longHostname := strings.Repeat("sub", 50) + ".vpn.example.com"
	original := URL{
		Hostname:  longHostname,
		Addresses: []M.Socksaddr{{Addr: netip.MustParseAddr("1.2.3.4"), Port: 443}},
		Username:  "user",
		Password:  longPassword,
	}

	link, err := original.Build()
	require.NoError(t, err)

	parsed, err := Parse(link)
	require.NoError(t, err)

	require.Equal(t, longHostname, parsed.Hostname)
	require.Equal(t, longPassword, parsed.Password)
}

func TestRoundTrip_SpecialCharacters(t *testing.T) {
	t.Parallel()
	original := URL{
		Hostname:  "vpn.example.com",
		Addresses: []M.Socksaddr{{Addr: netip.MustParseAddr("1.2.3.4"), Port: 443}},
		CustomSNI: "cdn-123.example.org",
		Username:  "user@example.com",
		Password:  "p@ss!w0rd#123",
	}
	link, err := original.Build()
	require.NoError(t, err)

	parsed, err := Parse(link)
	require.NoError(t, err)

	require.Equal(t, original.Username, parsed.Username)
	require.Equal(t, original.Password, parsed.Password)
	require.Equal(t, original.CustomSNI, parsed.CustomSNI)
}

func TestRoundTrip_IPv6Addresses(t *testing.T) {
	t.Parallel()
	original := URL{
		Hostname: "vpn6.example.com",
		Addresses: []M.Socksaddr{
			{Addr: netip.MustParseAddr("2001:db8::1"), Port: 443},
			{Addr: netip.MustParseAddr("::1"), Port: 8443},
		},
		Username: "ipv6user",
		Password: "ipv6pass",
	}
	link, err := original.Build()
	require.NoError(t, err)

	parsed, err := Parse(link)
	require.NoError(t, err)

	assertAddressesEqual(t, parsed.Addresses, original.Addresses)
}

func TestParse_DefaultUpstreamProtocolHTTP2(t *testing.T) {
	t.Parallel()
	builder := bytes.NewBuffer(nil)
	common.Must(writeTLV(builder, TagVersion, Version1))
	common.Must(writeTLV(builder, TagHostname, "example.com"))
	common.Must(writeTLV(builder, TagAddresses, "1.2.3.4:443"))
	common.Must(writeTLV(builder, TagUsername, "user"))
	common.Must(writeTLV(builder, TagPassword, "pass"))

	link := Schema + "://?" + base64.RawURLEncoding.EncodeToString(builder.Bytes())
	parsed, err := Parse(link)
	require.NoError(t, err)
	require.EqualValues(t, UpstreamProtocolHTTP2, parsed.UpstreamProtocol)
}

func TestParse_Draft2FormatWithQuestionMark(t *testing.T) {
	t.Parallel()
	builder := bytes.NewBuffer(nil)
	common.Must(writeTLV(builder, TagVersion, Version1))
	common.Must(writeTLV(builder, TagHostname, "example.com"))
	common.Must(writeTLV(builder, TagAddresses, "1.2.3.4:443"))
	common.Must(writeTLV(builder, TagUsername, "user"))
	common.Must(writeTLV(builder, TagPassword, "pass"))

	link := Schema + "://?" + base64.RawURLEncoding.EncodeToString(builder.Bytes())
	parsed, err := Parse(link)
	require.NoError(t, err)
	require.Equal(t, "example.com", parsed.Hostname)
	require.Equal(t, "user", parsed.Username)
	require.Equal(t, "pass", parsed.Password)
}

func TestParse_AcceptsSupportedVersions(t *testing.T) {
	t.Parallel()
	testCases := []struct {
		name    string
		version byte
	}{
		{name: "version 0", version: Version0},
		{name: "version 1", version: Version1},
		{name: "version 2", version: Version2},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			builder := bytes.NewBuffer(nil)
			common.Must(writeTLV(builder, TagVersion, testCase.version))
			common.Must(writeTLV(builder, TagHostname, "vpn.example.com"))
			common.Must(writeTLV(builder, TagAddresses, "1.2.3.4:443"))
			common.Must(writeTLV(builder, TagUsername, "alice"))
			common.Must(writeTLV(builder, TagPassword, "secret"))

			link := Schema + "://?" + base64.RawURLEncoding.EncodeToString(builder.Bytes())
			parsed, err := Parse(link)
			require.NoError(t, err)
			require.Equal(t, "vpn.example.com", parsed.Hostname)
			require.Equal(t, "alice", parsed.Username)
			require.Equal(t, "secret", parsed.Password)
		})
	}
}

func TestParse_IgnoreUnknownTag(t *testing.T) {
	t.Parallel()
	builder := bytes.NewBuffer(nil)
	common.Must(writeTLV(builder, TagVersion, Version1))
	common.Must(writeTLV(builder, TagHostname, "example.com"))
	common.Must(writeTLV(builder, TagAddresses, "1.2.3.4:443"))
	common.Must(writeTLV(builder, TagUsername, "user"))
	common.Must(writeTLV(builder, TagPassword, "pass"))
	common.Must(writeTLV(builder, 0xFF, []byte{0x01, 0x02, 0x03}))

	link := Schema + "://?" + base64.RawURLEncoding.EncodeToString(builder.Bytes())
	parsed, err := Parse(link)
	require.NoError(t, err)
	require.Equal(t, "user", parsed.Username)
	require.Empty(t, parsed.Name)
	require.Empty(t, parsed.ClientRandomAuthKey)
	require.Empty(t, parsed.TLSProfile)
}

func TestParse_IgnoreMultibyteUnknownTag(t *testing.T) {
	t.Parallel()
	builder := bytes.NewBuffer(nil)
	common.Must(writeTLV(builder, TagVersion, Version1))
	common.Must(writeTLV(builder, TagHostname, "example.com"))
	common.Must(writeTLV(builder, TagAddresses, "1.2.3.4:443"))
	common.Must(writeTLV(builder, TagUsername, "user"))
	common.Must(writeTLV(builder, TagPassword, "pass"))
	// Tag 0x110 encodes as two-byte varint 0x41 0x10, whose low byte matches TagTLSProfile (0x10).
	common.Must(writeTLV(builder, 0x110, "safari"))
	require.True(t, bytes.Contains(builder.Bytes(), []byte{0x41, 0x10}))

	link := Schema + "://?" + base64.RawURLEncoding.EncodeToString(builder.Bytes())
	parsed, err := Parse(link)
	require.NoError(t, err)
	require.Equal(t, "user", parsed.Username)
	require.Empty(t, parsed.TLSProfile)
}

func TestParse_InvalidScheme(t *testing.T) {
	t.Parallel()
	_, err := Parse("http://example.com")
	require.Error(t, err)
}

func TestParse_RejectLengthExceedingRemainingBuffer(t *testing.T) {
	t.Parallel()
	builder := bytes.NewBuffer(nil)
	common.Must(writeVarint(builder, TagHostname))
	common.Must(writeVarint(builder, 5))
	_, err := builder.WriteString("abc")
	require.NoError(t, err)

	link := Schema + "://?" + base64.RawURLEncoding.EncodeToString(builder.Bytes())
	_, err = Parse(link)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid length of tag")
}

func TestBuild_DefaultUpstreamProtocolTagOmitted(t *testing.T) {
	t.Parallel()
	url := URL{
		Hostname:  "example.com",
		Addresses: []M.Socksaddr{{Addr: netip.MustParseAddr("1.2.3.4"), Port: 443}},
		Username:  "user",
		Password:  "pass",
	}
	link, err := url.Build()
	require.NoError(t, err)
	tags := decodeTLVTags(t, link)
	assert.NotContains(t, tags, TagUpstreamProtocol)
}

func TestBuild_HTTP3UpstreamProtocolTagIncluded(t *testing.T) {
	t.Parallel()
	url := URL{
		Hostname:         "example.com",
		Addresses:        []M.Socksaddr{{Addr: netip.MustParseAddr("1.2.3.4"), Port: 443}},
		Username:         "user",
		Password:         "pass",
		UpstreamProtocol: UpstreamProtocolHTTP3,
	}
	link, err := url.Build()
	require.NoError(t, err)
	tags := decodeTLVTags(t, link)
	assert.Contains(t, tags, TagUpstreamProtocol)
}

func TestRoundTrip_Name(t *testing.T) {
	t.Parallel()
	original := URL{
		Hostname:  "vpn.example.com",
		Addresses: []M.Socksaddr{{Addr: netip.MustParseAddr("1.2.3.4"), Port: 443}},
		Username:  "user",
		Password:  "pass",
		Name:      "My VPN Server",
	}

	link, err := original.Build()
	require.NoError(t, err)

	parsed, err := Parse(link)
	require.NoError(t, err)
	require.Equal(t, original.Name, parsed.Name)
}

func TestRoundTrip_DNSUpstreams(t *testing.T) {
	t.Parallel()
	original := URL{
		Hostname:  "vpn.example.com",
		Addresses: []M.Socksaddr{{Addr: netip.MustParseAddr("1.2.3.4"), Port: 443}},
		Username:  "user",
		Password:  "pass",
		DNSUpstreams: []string{
			"1.1.1.1",
			"tls://dns.example.com",
			"https://dns.example.com/dns-query",
		},
	}

	link, err := original.Build()
	require.NoError(t, err)

	parsed, err := Parse(link)
	require.NoError(t, err)
	require.Equal(t, original.DNSUpstreams, parsed.DNSUpstreams)
}

func TestBuild_DNSUpstreamsEncodedAsSingleStringArrayTLV(t *testing.T) {
	t.Parallel()
	url := URL{
		Hostname:  "vpn.example.com",
		Addresses: []M.Socksaddr{{Addr: netip.MustParseAddr("1.2.3.4"), Port: 443}},
		Username:  "user",
		Password:  "pass",
		DNSUpstreams: []string{
			"1.1.1.1",
			"8.8.8.8",
		},
	}

	link, err := url.Build()
	require.NoError(t, err)

	payload := decodeTLVPayload(t, link)
	dnsValues := decodeTLVValues(t, payload, TagDNSUpstreams)
	require.Len(t, dnsValues, 1)

	reader := buf.As(dnsValues[0])
	firstLength, err := readVarint(reader)
	require.NoError(t, err)
	require.EqualValues(t, len("1.1.1.1"), firstLength)

	first := make([]byte, int(firstLength))
	_, err = io.ReadFull(reader, first)
	require.NoError(t, err)
	require.Equal(t, "1.1.1.1", string(first))

	secondLength, err := readVarint(reader)
	require.NoError(t, err)
	require.EqualValues(t, len("8.8.8.8"), secondLength)

	second := make([]byte, int(secondLength))
	_, err = io.ReadFull(reader, second)
	require.NoError(t, err)
	require.Equal(t, "8.8.8.8", string(second))
	require.Zero(t, reader.Len())
}

func TestParse_DNSUpstreamsFromSingleStringArrayTLV(t *testing.T) {
	t.Parallel()
	builder := bytes.NewBuffer(nil)
	common.Must(writeTLV(builder, TagVersion, Version1))
	common.Must(writeTLV(builder, TagHostname, "vpn.example.com"))
	common.Must(writeTLV(builder, TagAddresses, "1.2.3.4:443"))
	common.Must(writeTLV(builder, TagUsername, "user"))
	common.Must(writeTLV(builder, TagPassword, "pass"))

	dnsUpstreamsBuffer := bytes.NewBuffer(nil)
	common.Must(writeVarint(dnsUpstreamsBuffer, uint64(len("1.1.1.1"))))
	_, err := io.WriteString(dnsUpstreamsBuffer, "1.1.1.1")
	require.NoError(t, err)
	common.Must(writeVarint(dnsUpstreamsBuffer, uint64(len("tls://dns.example.com"))))
	_, err = io.WriteString(dnsUpstreamsBuffer, "tls://dns.example.com")
	require.NoError(t, err)
	common.Must(writeTLV(builder, TagDNSUpstreams, dnsUpstreamsBuffer.Bytes()))

	link := Schema + "://?" + base64.RawURLEncoding.EncodeToString(builder.Bytes())
	parsed, err := Parse(link)
	require.NoError(t, err)
	require.Equal(t, []string{"1.1.1.1", "tls://dns.example.com"}, parsed.DNSUpstreams)
}

func TestRoundTrip_WithoutNewOptionalFields(t *testing.T) {
	t.Parallel()
	original := URL{
		Hostname:  "vpn.example.com",
		Addresses: []M.Socksaddr{{Addr: netip.MustParseAddr("1.2.3.4"), Port: 443}},
		Username:  "user",
		Password:  "pass",
	}

	link, err := original.Build()
	require.NoError(t, err)

	parsed, err := Parse(link)
	require.NoError(t, err)
	require.Empty(t, parsed.Name)
	require.Empty(t, parsed.DNSUpstreams)
}

func TestParse_UnsupportedVersionRejected(t *testing.T) {
	t.Parallel()
	builder := bytes.NewBuffer(nil)
	common.Must(writeVarint(builder, TagVersion))
	common.Must(writeVarint(builder, 1))
	_, err := builder.Write([]byte{99})
	require.NoError(t, err)
	common.Must(writeTLV(builder, TagHostname, "vpn"))

	link := Schema + "://?" + base64.RawURLEncoding.EncodeToString(builder.Bytes())
	_, err = Parse(link)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unexpected version: 99")
}

func TestBuild_WithCertificateRoundTrip(t *testing.T) {
	t.Parallel()
	url := URL{
		Hostname:    "example.com",
		Addresses:   []M.Socksaddr{{Addr: netip.MustParseAddr("1.2.3.4"), Port: 443}},
		Username:    "user",
		Password:    "pass",
		Certificate: []byte{0x01, 0x02, 0x03, 0x04},
	}

	link, err := url.Build()
	require.NoError(t, err)

	parsed, err := Parse(link)
	require.NoError(t, err)
	require.NotEmpty(t, parsed.Certificate)
	require.Equal(t, url.Certificate, parsed.Certificate)
	require.EqualValues(t, UpstreamProtocolHTTP2, parsed.UpstreamProtocol)
}

func TestParse_LegacyFormatWithoutQuestionMark(t *testing.T) {
	t.Parallel()
	// Old format tt://Base64 should still be parsed successfully
	original := URL{
		Hostname:  "vpn.example.com",
		Addresses: []M.Socksaddr{{Addr: netip.MustParseAddr("1.2.3.4"), Port: 443}},
		Username:  "alice",
		Password:  "secret",
	}

	link, err := original.Build()
	require.NoError(t, err)

	// Build now produces new format with ?
	require.True(t, strings.HasPrefix(link, Schema+"://?"))

	// New format with ? should parse
	parsed, err := Parse(link)
	require.NoError(t, err)
	require.Equal(t, "vpn.example.com", parsed.Hostname)
	require.Equal(t, "alice", parsed.Username)

	// Legacy format without ? should also parse
	legacyLink := strings.Replace(link, Schema+"://?", Schema+"://", 1)
	parsed2, err := Parse(legacyLink)
	require.NoError(t, err)
	require.Equal(t, "vpn.example.com", parsed2.Hostname)
	require.Equal(t, "alice", parsed2.Username)
}

func assertAddressesEqual(t *testing.T, got []M.Socksaddr, want []M.Socksaddr) {
	t.Helper()
	require.Len(t, got, len(want))
	for i := range want {
		require.Equal(t, want[i].String(), got[i].String())
	}
}

func decodeTLVTags(t *testing.T, link string) []uint64 {
	t.Helper()
	reader := buf.As(decodeTLVPayload(t, link))
	tags := make([]uint64, 0, 8)
	for {
		tag, err := readVarint(reader)
		if err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			require.NoError(t, err)
		}

		length, err := readVarint(reader)
		require.NoError(t, err)

		tags = append(tags, tag)
		reader.Advance(int(length))
	}

	return tags
}

func decodeTLVPayload(t *testing.T, link string) []byte {
	t.Helper()
	encoded, found := strings.CutPrefix(link, Schema+"://")
	require.True(t, found)
	encoded = strings.TrimPrefix(encoded, "?")

	payload, err := base64.RawURLEncoding.DecodeString(encoded)
	require.NoError(t, err)
	return payload
}

func decodeTLVValues(t *testing.T, payload []byte, targetTag uint64) [][]byte {
	t.Helper()
	reader := buf.As(payload)
	var values [][]byte
	for {
		tag, err := readVarint(reader)
		if err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			require.NoError(t, err)
		}

		length, err := readVarint(reader)
		require.NoError(t, err)

		value := make([]byte, int(length))
		_, err = io.ReadFull(reader, value)
		require.NoError(t, err)

		if tag == targetTag {
			values = append(values, value)
		}
	}
	return values
}

func TestBuild_ValidationErrors(t *testing.T) {
	t.Parallel()
	addr := M.Socksaddr{Addr: netip.MustParseAddr("1.2.3.4"), Port: 443}
	testCases := []struct {
		name    string
		url     URL
		wantErr string
	}{
		{
			name:    "missing hostname",
			url:     URL{Addresses: []M.Socksaddr{addr}, Username: "user", Password: "pass"},
			wantErr: "missing hostname",
		},
		{
			name:    "missing addresses",
			url:     URL{Hostname: "example.com", Username: "user", Password: "pass"},
			wantErr: "missing addresses",
		},
		{
			name:    "missing username",
			url:     URL{Hostname: "example.com", Addresses: []M.Socksaddr{addr}, Password: "pass"},
			wantErr: "missing username",
		},
		{
			name:    "missing password",
			url:     URL{Hostname: "example.com", Addresses: []M.Socksaddr{addr}, Username: "user"},
			wantErr: "missing password",
		},
		{
			name:    "invalid upstream protocol",
			url:     URL{Hostname: "example.com", Addresses: []M.Socksaddr{addr}, Username: "user", Password: "pass", UpstreamProtocol: 0xFF},
			wantErr: "invalid upstream protocol",
		},
		{
			name:    "unsupported version",
			url:     URL{Version: 3, Hostname: "example.com", Addresses: []M.Socksaddr{addr}, Username: "user", Password: "pass"},
			wantErr: "unexpected version: 3",
		},
		{
			name:    "non-https subscription url",
			url:     URL{SubscriptionURL: "http://vpn.example.com/subscription"},
			wantErr: "subscription URL must start with https://",
		},
		{
			name:    "non-https subscription url with static fields",
			url:     URL{Hostname: "vpn.example.com", Addresses: []M.Socksaddr{addr}, Username: "alice", Password: "s3cret", SubscriptionURL: "http://vpn.example.com/subscription"},
			wantErr: "subscription URL must start with https://",
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			_, err := tc.url.Build()
			require.Error(t, err)
			assert.Contains(t, err.Error(), tc.wantErr)
		})
	}
}

func TestParse_ErrorCases(t *testing.T) {
	t.Parallel()

	buildLink := func(extra ...func(*bytes.Buffer)) string {
		b := bytes.NewBuffer(nil)
		for _, fn := range extra {
			fn(b)
		}
		return Schema + "://?" + base64.RawURLEncoding.EncodeToString(b.Bytes())
	}
	withVersion := func(b *bytes.Buffer) { common.Must(writeTLV(b, TagVersion, Version1)) }
	withHostname := func(b *bytes.Buffer) { common.Must(writeTLV(b, TagHostname, "example.com")) }
	withAddress := func(b *bytes.Buffer) { common.Must(writeTLV(b, TagAddresses, "1.2.3.4:443")) }
	withUsername := func(b *bytes.Buffer) { common.Must(writeTLV(b, TagUsername, "user")) }
	withPassword := func(b *bytes.Buffer) { common.Must(writeTLV(b, TagPassword, "pass")) }

	testCases := []struct {
		name    string
		link    string
		wantErr string
	}{
		{
			name:    "missing hostname",
			link:    buildLink(withVersion, withAddress, withUsername, withPassword),
			wantErr: "missing hostname",
		},
		{
			name:    "missing addresses",
			link:    buildLink(withVersion, withHostname, withUsername, withPassword),
			wantErr: "missing addresses",
		},
		{
			name:    "missing username",
			link:    buildLink(withVersion, withHostname, withAddress, withPassword),
			wantErr: "missing username",
		},
		{
			name:    "missing password",
			link:    buildLink(withVersion, withHostname, withAddress, withUsername),
			wantErr: "missing password",
		},
		{
			name: "invalid address port zero",
			link: buildLink(withVersion, withHostname, func(b *bytes.Buffer) {
				common.Must(writeTLV(b, TagAddresses, "1.2.3.4:0"))
			}, withUsername, withPassword),
			wantErr: "invalid address",
		},
		{
			name: "invalid upstream protocol",
			link: buildLink(withVersion, withHostname, withAddress, withUsername, withPassword, func(b *bytes.Buffer) {
				common.Must(writeTLV(b, TagUpstreamProtocol, byte(0xFF)))
			}),
			wantErr: "invalid upstream protocol",
		},
		{
			name: "non-https subscription url",
			link: buildLink(func(b *bytes.Buffer) { common.Must(writeTLV(b, TagVersion, Version2)) }, func(b *bytes.Buffer) {
				common.Must(writeTLV(b, TagSubscriptionURL, "http://vpn.example.com/subscription"))
			}),
			wantErr: "subscription URL must start with https://",
		},
		{
			name: "unsupported version 3",
			link: buildLink(func(b *bytes.Buffer) { common.Must(writeTLV(b, TagVersion, byte(3))) }, func(b *bytes.Buffer) {
				common.Must(writeTLV(b, TagSubscriptionURL, "https://vpn.example.com/subscription"))
			}),
			wantErr: "unexpected version: 3",
		},
		{
			name:    "invalid base64",
			link:    Schema + "://?not!valid!base64!!",
			wantErr: "",
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			_, err := Parse(tc.link)
			require.Error(t, err)
			if tc.wantErr != "" {
				assert.Contains(t, err.Error(), tc.wantErr)
			}
		})
	}
}

func TestIsValidVersion(t *testing.T) {
	t.Parallel()
	testCases := []struct {
		version byte
		valid   bool
	}{
		{Version0, true},
		{Version1, true},
		{Version2, true},
		{3, false},
		{0xFF, false},
	}
	for _, tc := range testCases {
		t.Run(F.ToString(tc.version), func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tc.valid, IsValidVersion(tc.version))
		})
	}
}

func TestUpstreamProtocol_IsValid(t *testing.T) {
	t.Parallel()
	testCases := []struct {
		protocol UpstreamProtocol
		valid    bool
	}{
		{UpstreamProtocolHTTP2, true},
		{UpstreamProtocolHTTP3, true},
		{0x00, false},
		{0xFF, false},
	}
	for _, tc := range testCases {
		t.Run(F.ToString(byte(tc.protocol)), func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tc.valid, tc.protocol.IsValid())
		})
	}
}

func TestParse_TruncatedVarint(t *testing.T) {
	t.Parallel()
	_, err := Parse(Schema + "://?" + base64.RawURLEncoding.EncodeToString([]byte{0x80, 0x00}))
	require.ErrorIs(t, err, io.ErrUnexpectedEOF)
}

const testSubscriptionURL = "https://alice:s3cret@vpn.example.com/subscription"

func TestBuild_VersionRaisedByFeatures(t *testing.T) {
	t.Parallel()
	addr := M.Socksaddr{Addr: netip.MustParseAddr("1.2.3.4"), Port: 443}
	base := URL{Hostname: "vpn.example.com", Addresses: []M.Socksaddr{addr}, Username: "alice", Password: "s3cret"}
	testCases := []struct {
		name    string
		modify  func(*URL)
		version byte
	}{
		{name: "draft fields only", modify: func(*URL) {}, version: Version1},
		{name: "name", modify: func(u *URL) { u.Name = "Acme VPN" }, version: Version1},
		{name: "dns upstreams", modify: func(u *URL) { u.DNSUpstreams = []string{"1.1.1.1"} }, version: Version1},
		{name: "subscription url", modify: func(u *URL) { u.SubscriptionURL = testSubscriptionURL }, version: Version2},
		{name: "subscription url with name", modify: func(u *URL) { u.Name = "Acme VPN"; u.SubscriptionURL = testSubscriptionURL }, version: Version2},
		{name: "tls profile", modify: func(u *URL) { u.TLSProfile = common.Ptr(TLSProfileChrome) }, version: Version2},
		{name: "explicit version kept", modify: func(u *URL) { u.Version = Version2 }, version: Version2},
		{name: "explicit version raised", modify: func(u *URL) { u.Version = Version1; u.SubscriptionURL = testSubscriptionURL }, version: Version2},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			url := base
			tc.modify(&url)
			link, err := url.Build()
			require.NoError(t, err)
			require.Equal(t, [][]byte{{tc.version}}, decodeTLVValues(t, decodeTLVPayload(t, link), TagVersion))

			parsed, err := Parse(link)
			require.NoError(t, err)
			require.Equal(t, tc.version, parsed.Version)
		})
	}
}

func TestParse_SubscriptionOnlyV2(t *testing.T) {
	t.Parallel()
	builder := bytes.NewBuffer(nil)
	common.Must(writeTLV(builder, TagVersion, Version2))
	common.Must(writeTLV(builder, TagSubscriptionURL, testSubscriptionURL))

	parsed, err := Parse(Schema + "://?" + base64.RawURLEncoding.EncodeToString(builder.Bytes()))
	require.NoError(t, err)
	require.Equal(t, testSubscriptionURL, parsed.SubscriptionURL)
	require.Empty(t, parsed.Hostname)
	require.Empty(t, parsed.Addresses)
	require.Empty(t, parsed.Username)
	require.Empty(t, parsed.Password)
}

func TestParse_V1LinkWithRequiredFieldsAccepted(t *testing.T) {
	t.Parallel()
	builder := bytes.NewBuffer(nil)
	common.Must(writeTLV(builder, TagVersion, Version1))
	common.Must(writeTLV(builder, TagHostname, "vpn.example.com"))
	common.Must(writeTLV(builder, TagAddresses, "1.2.3.4:443"))
	common.Must(writeTLV(builder, TagUsername, "alice"))
	common.Must(writeTLV(builder, TagPassword, "s3cret"))

	parsed, err := Parse(Schema + "://?" + base64.RawURLEncoding.EncodeToString(builder.Bytes()))
	require.NoError(t, err)
	require.Equal(t, "vpn.example.com", parsed.Hostname)
	require.Empty(t, parsed.SubscriptionURL)
}

func TestBuild_SubscriptionOnly(t *testing.T) {
	t.Parallel()
	url := URL{SubscriptionURL: testSubscriptionURL}
	link, err := url.Build()
	require.NoError(t, err)

	payload := decodeTLVPayload(t, link)
	// Version-2 TLV (tag 0x00, len 1, value 2) comes first.
	require.Equal(t, []byte{0x00, 0x01, 0x02}, payload[:3])
	// The whole payload is exactly these two TLVs; anything appended
	// afterwards (e.g. a new default-emitted field) fails here.
	require.Equal(t, []uint64{TagVersion, TagSubscriptionURL}, decodeTLVTags(t, link))

	parsed, err := Parse(link)
	require.NoError(t, err)
	require.Equal(t, testSubscriptionURL, parsed.SubscriptionURL)
	require.Empty(t, parsed.Hostname)
}

func TestRoundTrip_FullConfigWithSubscriptionURL(t *testing.T) {
	t.Parallel()
	original := URL{
		Hostname:        "vpn.example.com",
		Addresses:       []M.Socksaddr{{Addr: netip.MustParseAddr("1.2.3.4"), Port: 443}},
		Username:        "alice",
		Password:        "s3cret",
		Name:            "Acme VPN",
		DNSUpstreams:    []string{"tls://1.1.1.1"},
		SubscriptionURL: testSubscriptionURL,
	}

	link, err := original.Build()
	require.NoError(t, err)
	parsed, err := Parse(link)
	require.NoError(t, err)

	// Subscription URL and all static fallback fields survive the roundtrip.
	expected := original
	expected.Version = Version2
	expected.UpstreamProtocol = UpstreamProtocolHTTP2
	require.Equal(t, &expected, parsed)
}

func TestRoundTrip_SubscriptionOnly(t *testing.T) {
	t.Parallel()
	original := URL{SubscriptionURL: testSubscriptionURL}

	link, err := original.Build()
	require.NoError(t, err)
	parsed, err := Parse(link)
	require.NoError(t, err)

	require.Equal(t, testSubscriptionURL, parsed.SubscriptionURL)
	require.Empty(t, parsed.Hostname)
	require.Empty(t, parsed.Addresses)
	require.Empty(t, parsed.Username)
	require.Empty(t, parsed.Password)
	require.Empty(t, parsed.Name)
	require.Empty(t, parsed.DNSUpstreams)
	// Defaults still apply.
	require.EqualValues(t, UpstreamProtocolHTTP2, parsed.UpstreamProtocol)
}

func TestRoundTrip_ClientRandomAuthKey(t *testing.T) {
	t.Parallel()
	original := URL{
		Hostname:            "vpn.example.com",
		Addresses:           []M.Socksaddr{{Addr: netip.MustParseAddr("1.2.3.4"), Port: 443}},
		Username:            "alice",
		Password:            "secret",
		ClientRandomAuthKey: []byte{0xaa, 0xbb, 0xcc, 0xdd},
	}

	link, err := original.Build()
	require.NoError(t, err)

	payload := decodeTLVPayload(t, link)
	require.Equal(t, [][]byte{[]byte("aabbccdd")}, decodeTLVValues(t, payload, TagClientRandomAuthKey))

	parsed, err := Parse(link)
	require.NoError(t, err)
	require.Equal(t, original.ClientRandomAuthKey, parsed.ClientRandomAuthKey)
}

func TestRoundTrip_ClientRandomAuthKeyLengths(t *testing.T) {
	t.Parallel()
	// Empty keys are omitted and decode as absent, so only non-empty keys
	// (1 to 16 bytes, matching the upstream hex strategy) are round-tripped.
	for length := 1; length <= 16; length++ {
		t.Run(F.ToString(length), func(t *testing.T) {
			t.Parallel()
			key := bytes.Repeat([]byte{0xab}, length)
			original := URL{
				Hostname:            "vpn.example.com",
				Addresses:           []M.Socksaddr{{Addr: netip.MustParseAddr("1.2.3.4"), Port: 443}},
				Username:            "alice",
				Password:            "secret",
				ClientRandomAuthKey: key,
			}

			link, err := original.Build()
			require.NoError(t, err)
			parsed, err := Parse(link)
			require.NoError(t, err)
			require.Equal(t, key, parsed.ClientRandomAuthKey)
			require.Equal(t, [][]byte{[]byte(hex.EncodeToString(key))}, decodeTLVValues(t, decodeTLVPayload(t, link), TagClientRandomAuthKey))
		})
	}
}

func TestBuild_ClientRandomAuthKeyOmittedWhenEmpty(t *testing.T) {
	t.Parallel()
	original := URL{
		Hostname:  "vpn.example.com",
		Addresses: []M.Socksaddr{{Addr: netip.MustParseAddr("1.2.3.4"), Port: 443}},
		Username:  "alice",
		Password:  "secret",
	}

	link, err := original.Build()
	require.NoError(t, err)
	assert.NotContains(t, decodeTLVTags(t, link), TagClientRandomAuthKey)

	parsed, err := Parse(link)
	require.NoError(t, err)
	require.Empty(t, parsed.ClientRandomAuthKey)
}

func TestParse_ClientRandomAuthKeyInvalidHex(t *testing.T) {
	t.Parallel()
	testCases := []string{"nothexx", "not-hex"}
	for _, raw := range testCases {
		t.Run(raw, func(t *testing.T) {
			t.Parallel()
			builder := bytes.NewBuffer(nil)
			common.Must(writeTLV(builder, TagVersion, Version1))
			common.Must(writeTLV(builder, TagHostname, "vpn.example.com"))
			common.Must(writeTLV(builder, TagAddresses, "1.2.3.4:443"))
			common.Must(writeTLV(builder, TagUsername, "alice"))
			common.Must(writeTLV(builder, TagPassword, "secret"))
			common.Must(writeTLV(builder, TagClientRandomAuthKey, raw))

			_, err := Parse(Schema + "://?" + base64.RawURLEncoding.EncodeToString(builder.Bytes()))
			require.Error(t, err)
			assert.Contains(t, err.Error(), "client random auth key is not hex")
		})
	}
}

func TestRoundTrip_EmptyPrefixAndAuthKeyOmitted(t *testing.T) {
	t.Parallel()
	original := URL{
		Hostname:            "vpn.example.com",
		Addresses:           []M.Socksaddr{{Addr: netip.MustParseAddr("1.2.3.4"), Port: 443}},
		Username:            "alice",
		Password:            "secret",
		ClientRandomAuthKey: []byte{},
	}

	link, err := original.Build()
	require.NoError(t, err)
	tags := decodeTLVTags(t, link)
	// Empty prefix and auth key are skipped, so decode returns them empty.
	assert.NotContains(t, tags, TagClientRandomPrefix)
	assert.NotContains(t, tags, TagClientRandomAuthKey)
	assert.NotContains(t, tags, TagTLSProfile)

	parsed, err := Parse(link)
	require.NoError(t, err)
	require.Empty(t, parsed.ClientRandomPrefix)
	require.Empty(t, parsed.ClientRandomAuthKey)
	require.Empty(t, parsed.TLSProfile)
}

func TestRoundTrip_TLSProfile(t *testing.T) {
	t.Parallel()
	testCases := []struct {
		name    string
		profile TLSProfile
		wire    byte
	}{
		{"chrome", TLSProfileChrome, 0x00},
		{"chrome_canary", TLSProfileChromeCanary, 0x01},
		{"safari", TLSProfileSafari, 0x02},
		{"firefox", TLSProfileFirefox, 0x03},
		{"okhttp", TLSProfileOkHTTP, 0x04},
		{"openssl", TLSProfileOpenSSL, 0x05},
		{"boringssl", TLSProfileBoringSSL, 0x06},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			original := URL{
				Hostname:   "vpn.example.com",
				Addresses:  []M.Socksaddr{{Addr: netip.MustParseAddr("1.2.3.4"), Port: 443}},
				Username:   "alice",
				Password:   "secret",
				TLSProfile: common.Ptr(tc.profile),
			}

			link, err := original.Build()
			require.NoError(t, err)

			payload := decodeTLVPayload(t, link)
			require.Equal(t, [][]byte{{tc.wire}}, decodeTLVValues(t, payload, TagTLSProfile))

			parsed, err := Parse(link)
			require.NoError(t, err)
			require.Equal(t, original.TLSProfile, parsed.TLSProfile)
		})
	}
}

func TestBuild_TLSProfileOmittedWhenUnset(t *testing.T) {
	t.Parallel()
	original := URL{
		Hostname:  "vpn.example.com",
		Addresses: []M.Socksaddr{{Addr: netip.MustParseAddr("1.2.3.4"), Port: 443}},
		Username:  "alice",
		Password:  "secret",
	}

	link, err := original.Build()
	require.NoError(t, err)
	assert.NotContains(t, decodeTLVTags(t, link), TagTLSProfile)

	parsed, err := Parse(link)
	require.NoError(t, err)
	require.Nil(t, parsed.TLSProfile)
}

func TestParse_InvalidTLSProfile(t *testing.T) {
	t.Parallel()
	link, err := (URL{SubscriptionURL: testSubscriptionURL}).Build()
	require.NoError(t, err)
	payload := decodeTLVPayload(t, link)
	testCases := []struct {
		name  string
		value []byte
	}{
		{"empty", nil},
		{"multiple bytes", []byte{0x00, 0x01}},
		{"withdrawn string format", []byte("firefox")},
		{"unknown identifier", []byte{0x07}},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			builder := bytes.NewBuffer(bytes.Clone(payload))
			require.NoError(t, writeTLV(builder, TagTLSProfile, tc.value))
			_, err := Parse(Schema + "://?" + base64.RawURLEncoding.EncodeToString(builder.Bytes()))
			require.Error(t, err)
		})
	}
}

func TestBuild_InvalidTLSProfile(t *testing.T) {
	t.Parallel()
	_, err := (URL{
		SubscriptionURL: testSubscriptionURL,
		TLSProfile:      common.Ptr(TLSProfile(0x07)),
	}).Build()
	require.Error(t, err)
}

func TestParse_ClientRandomAuthKeyEmptyIsAllowed(t *testing.T) {
	t.Parallel()
	builder := bytes.NewBuffer(nil)
	common.Must(writeTLV(builder, TagVersion, Version1))
	common.Must(writeTLV(builder, TagHostname, "vpn.example.com"))
	common.Must(writeTLV(builder, TagAddresses, "1.2.3.4:443"))
	common.Must(writeTLV(builder, TagUsername, "alice"))
	common.Must(writeTLV(builder, TagPassword, "secret"))
	common.Must(writeTLV(builder, TagClientRandomAuthKey, ""))

	parsed, err := Parse(Schema + "://?" + base64.RawURLEncoding.EncodeToString(builder.Bytes()))
	require.NoError(t, err)
	require.Empty(t, parsed.ClientRandomAuthKey)
}

func BenchmarkBuild(b *testing.B) {
	url := URL{
		Hostname:           "vpn.example.com",
		Addresses:          []M.Socksaddr{{Addr: netip.MustParseAddr("1.2.3.4"), Port: 443}},
		CustomSNI:          "sni.example.com",
		Username:           "user",
		Password:           "pass",
		SkipVerification:   true,
		Certificate:        make([]byte, 1024),
		UpstreamProtocol:   UpstreamProtocolHTTP3,
		AntiDPI:            true,
		ClientRandomPrefix: ClientRandomPrefix{Prefix: []byte{0xaa, 0xbb, 0xcc}},
		Name:               "name",
		DNSUpstreams:       []string{"1.1.1.1", "tls://dns.example.com"},
	}
	b.ReportAllocs()
	for b.Loop() {
		_, err := url.Build()
		if err != nil {
			b.Fatal(err)
		}
	}
}

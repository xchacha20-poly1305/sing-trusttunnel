// Package tturl parses and builds TrustTunnel URLs.
package tturl

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"io"
	"slices"
	"strings"

	"github.com/sagernet/sing/common/buf"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
	"github.com/sagernet/sing/common/rw"
)

const (
	Schema        = "tt"
	Version0 byte = 0
	Version1 byte = 1
	Version2 byte = 2
)

func IsValidVersion(version byte) bool {
	switch version {
	case Version0, Version1, Version2:
		return true
	default:
		return false
	}
}

const (
	TagVersion             uint64 = 0x00
	TagHostname            uint64 = 0x01
	TagAddresses           uint64 = 0x02
	TagCustomSNI           uint64 = 0x03
	TagHasIPv6             uint64 = 0x04 // Always true in original implementation
	TagUsername            uint64 = 0x05
	TagPassword            uint64 = 0x06
	TagSkipVerification    uint64 = 0x07
	TagCertificate         uint64 = 0x08
	TagUpstreamProtocol    uint64 = 0x09
	TagAntiDPI             uint64 = 0x0A
	TagClientRandomPrefix  uint64 = 0x0B
	TagName                uint64 = 0x0C
	TagDNSUpstreams        uint64 = 0x0D
	TagSubscriptionURL     uint64 = 0x0E
	TagClientRandomAuthKey uint64 = 0x0F
	TagTLSProfile          uint64 = 0x10
)

type UpstreamProtocol byte

const (
	UpstreamProtocolHTTP2 = 0x01
	UpstreamProtocolHTTP3 = 0x02
)

func (u UpstreamProtocol) IsValid() bool {
	switch u {
	case UpstreamProtocolHTTP2, UpstreamProtocolHTTP3:
		return true
	default:
		return false
	}
}

// TLSProfile identifies a TLS ClientHello fingerprint in a TrustTunnel URL.
type TLSProfile byte

const (
	TLSProfileChrome       TLSProfile = 0x00
	TLSProfileChromeCanary TLSProfile = 0x01
	TLSProfileSafari       TLSProfile = 0x02
	TLSProfileFirefox      TLSProfile = 0x03
	TLSProfileOkHTTP       TLSProfile = 0x04
	TLSProfileOpenSSL      TLSProfile = 0x05
	TLSProfileBoringSSL    TLSProfile = 0x06
)

func (p TLSProfile) IsValid() bool {
	return p <= TLSProfileBoringSSL
}

type URL struct {
	Version             byte
	Hostname            string
	Addresses           []M.Socksaddr
	CustomSNI           string
	Username            string
	Password            string
	SkipVerification    bool
	Certificate         []byte // der
	UpstreamProtocol    UpstreamProtocol
	AntiDPI             bool
	ClientRandomPrefix  ClientRandomPrefix
	Name                string
	DNSUpstreams        []string
	SubscriptionURL     string
	ClientRandomAuthKey []byte      // will be encoded to hex
	TLSProfile          *TLSProfile // nil omits the tag, for which the client defaults to Chrome
}

func Parse(link string) (*URL, error) {
	base64String, found := strings.CutPrefix(link, Schema+"://")
	if !found {
		return nil, E.New("schema is not ", Schema)
	}
	// since draft 2
	// https://github.com/TrustTunnel/TrustTunnel/blob/984817f3b92f5769aedb15e3f90782bc88839825/DEEP_LINK.md?plain=1#L8
	base64String = strings.TrimPrefix(base64String, "?")
	buffer := buf.NewSize(base64.RawURLEncoding.DecodedLen(len(base64String)))
	defer buffer.Release()
	n, err := base64.RawURLEncoding.Decode(buffer.FreeBytes(), []byte(base64String))
	if err != nil {
		return nil, err
	}
	buffer.Truncate(n)

	url := new(URL)
	err = parseTLV(buffer, url)
	if err != nil {
		return nil, err
	}
	url.applyDefaults()
	err = url.requireValid()
	if err != nil {
		return nil, err
	}
	return url, nil
}

func parseTLV(buffer *buf.Buffer, url *URL) error {
	for {
		tag, err := readVarint(buffer)
		if err != nil {
			if err == io.EOF {
				break
			}
			return err
		}

		err = parseTag(buffer, url, tag)
		if err != nil {
			return err
		}
	}
	return nil
}

func parseTag(buffer *buf.Buffer, url *URL, tag uint64) error {
	switch tag {
	case TagVersion:
		version, err := readTLVByte(buffer, tag)
		if err != nil {
			return err
		}
		if !IsValidVersion(version) {
			return E.New("unexpected version: ", version)
		}
		url.Version = version
	case TagHostname:
		value, err := readTLVString(buffer, tag)
		if err != nil {
			return err
		}
		url.Hostname = value
	case TagAddresses:
		value, err := readTLVString(buffer, tag)
		if err != nil {
			return err
		}
		address := M.ParseSocksaddr(value)
		if !address.IsValid() || address.Port == 0 {
			return E.New("invalid address: ", value)
		}
		url.Addresses = append(url.Addresses, address)
	case TagCustomSNI:
		value, err := readTLVString(buffer, tag)
		if err != nil {
			return err
		}
		url.CustomSNI = value
	case TagUsername:
		value, err := readTLVString(buffer, tag)
		if err != nil {
			return err
		}
		url.Username = value
	case TagPassword:
		value, err := readTLVString(buffer, tag)
		if err != nil {
			return err
		}
		url.Password = value
	case TagSkipVerification:
		value, err := readTLVBool(buffer, tag)
		if err != nil {
			return err
		}
		url.SkipVerification = value
	case TagCertificate:
		value, err := readTLVBytes(buffer, tag)
		if err != nil {
			return err
		}
		url.Certificate = value
	case TagUpstreamProtocol:
		value, err := readTLVByte(buffer, tag)
		if err != nil {
			return err
		}
		upstreamProtocol := UpstreamProtocol(value)
		if !upstreamProtocol.IsValid() {
			return E.New("invalid upstream protocol: ", byte(upstreamProtocol))
		}
		url.UpstreamProtocol = upstreamProtocol
	case TagAntiDPI:
		value, err := readTLVBool(buffer, tag)
		if err != nil {
			return err
		}
		url.AntiDPI = value
	case TagClientRandomPrefix:
		value, err := readTLVString(buffer, tag)
		if err != nil {
			return err
		}
		randomPrefix, err := ParseClientRandomPrefix(value)
		if err != nil {
			return err
		}
		url.ClientRandomPrefix = randomPrefix
	case TagName:
		value, err := readTLVString(buffer, tag)
		if err != nil {
			return err
		}
		url.Name = value
	case TagDNSUpstreams:
		value, err := readTLVStringArray(buffer, tag)
		if err != nil {
			return err
		}
		url.DNSUpstreams = value
	case TagSubscriptionURL:
		value, err := readTLVString(buffer, tag)
		if err != nil {
			return err
		}
		url.SubscriptionURL = value
	case TagClientRandomAuthKey:
		rawValue, err := readTLVString(buffer, tag)
		if err != nil {
			return err
		}
		value, err := hex.DecodeString(rawValue)
		if err != nil {
			return E.Cause(err, "client random auth key is not hex")
		}
		url.ClientRandomAuthKey = value
	case TagTLSProfile:
		value, err := readTLVByte(buffer, tag)
		if err != nil {
			return err
		}
		profile := TLSProfile(value)
		if !profile.IsValid() {
			return E.New("invalid TLS profile: ", value)
		}
		url.TLSProfile = &profile
	case TagHasIPv6:
		fallthrough
	default:
		return skipTLV(buffer, tag)
	}
	return nil
}

func readTLVString(buffer *buf.Buffer, tag uint64) (string, error) {
	value, err := readTLVBytes(buffer, tag)
	if err != nil {
		return "", err
	}
	return string(value), nil
}

func readTLVBool(buffer *buf.Buffer, tag uint64) (bool, error) {
	value, err := readTLVByte(buffer, tag)
	if err != nil {
		return false, err
	}
	return value != 0, nil
}

func readTLVByte(buffer *buf.Buffer, tag uint64) (byte, error) {
	value, err := readTLVFixedBytes(buffer, tag, 1)
	if err != nil {
		return 0, err
	}
	return value[0], nil
}

func readTLVFixedBytes(buffer *buf.Buffer, tag uint64, expectLength uint64) ([]byte, error) {
	length, err := readTLVLength(buffer, tag)
	if err != nil {
		return nil, err
	}
	if length != expectLength {
		if tag == TagVersion {
			return nil, E.New("invalid version length: ", length)
		}
		return nil, E.New("invalid length of tag ", tag, ": ", length)
	}
	readBuffer := make([]byte, int(length))
	_, err = io.ReadFull(buffer, readBuffer)
	if err != nil {
		return nil, err
	}
	return readBuffer, nil
}

func readTLVBytes(buffer *buf.Buffer, tag uint64) ([]byte, error) {
	length, err := readTLVLength(buffer, tag)
	if err != nil {
		return nil, err
	}
	if length == 0 {
		return nil, nil
	}
	readBuffer := make([]byte, int(length))
	_, err = io.ReadFull(buffer, readBuffer)
	if err != nil {
		return nil, err
	}
	return readBuffer, nil
}

func readTLVStringArray(buffer *buf.Buffer, tag uint64) ([]string, error) {
	data, err := readTLVBytes(buffer, tag)
	if err != nil {
		return nil, err
	}
	if len(data) == 0 {
		return nil, nil
	}
	arrayBuffer := buf.As(data)
	var result []string
	for !arrayBuffer.IsEmpty() {
		item, err := readTLVString(arrayBuffer, tag)
		if err != nil {
			return nil, E.Cause(err, "read string array item ", len(result))
		}
		result = append(result, item)
	}
	return result, nil
}

func readTLVLength(buffer *buf.Buffer, tag uint64) (uint64, error) {
	length, err := readVarint(buffer)
	if err != nil {
		return 0, err
	}
	remaining := buffer.Len()
	if length > uint64(buffer.Len()) {
		return 0, E.New("invalid length of tag ", tag, ": ", length, ", remaining: ", remaining)
	}
	return length, nil
}

func skipTLV(buffer *buf.Buffer, tag uint64) error {
	length, err := readTLVLength(buffer, tag)
	if err != nil {
		return err
	}
	return rw.SkipN(buffer, int(length))
}

func (u *URL) applyDefaults() {
	if u.UpstreamProtocol == 0 {
		u.UpstreamProtocol = UpstreamProtocolHTTP2
	}
}

func (u URL) requireValid() error {
	if !IsValidVersion(u.Version) {
		return E.New("unexpected version: ", u.Version)
	}
	if u.SubscriptionURL != "" {
		if !strings.HasPrefix(u.SubscriptionURL, "https://") {
			return E.New("subscription URL must start with https://")
		}
	} else {
		if u.Hostname == "" {
			return E.New("missing hostname")
		}
		if u.Username == "" {
			return E.New("missing username")
		}
		if u.Password == "" {
			return E.New("missing password")
		}
		if len(u.Addresses) == 0 {
			return E.New("missing addresses")
		}
	}
	if invalidIndex := slices.IndexFunc(u.Addresses, func(address M.Socksaddr) bool {
		return !address.IsValid() || address.Port == 0
	}); invalidIndex >= 0 {
		return E.New("address [", invalidIndex, "] is invalid")
	}
	if !u.UpstreamProtocol.IsValid() {
		return E.New("invalid upstream protocol ", byte(u.UpstreamProtocol))
	}
	if u.TLSProfile != nil && !u.TLSProfile.IsValid() {
		return E.New("invalid TLS profile: ", byte(*u.TLSProfile))
	}
	return nil
}

func (u URL) lowestVersion() byte {
	if u.SubscriptionURL != "" || len(u.ClientRandomAuthKey) > 0 || u.TLSProfile != nil {
		return Version2
	}
	/*if u.Name != "" || len(u.DNSUpstreams) > 0 {
		return Version1
	}
	return Version0*/
	return Version1
}

func (u URL) Build() (string, error) {
	u.applyDefaults()
	err := u.requireValid()
	if err != nil {
		return "", err
	}
	builder := bytes.NewBuffer(nil)
	err = writeTLV(builder, TagVersion, max(u.Version, u.lowestVersion()))
	if err != nil {
		return "", E.Cause(err, "write version")
	}
	if u.Hostname != "" {
		err = writeTLV(builder, TagHostname, u.Hostname)
		if err != nil {
			return "", E.Cause(err, "write hostname")
		}
	}
	for i, address := range u.Addresses {
		err = writeTLV(builder, TagAddresses, address.String())
		if err != nil {
			return "", E.Cause(err, "write address ", i)
		}
	}
	if u.CustomSNI != "" {
		err = writeTLV(builder, TagCustomSNI, u.CustomSNI)
		if err != nil {
			return "", E.Cause(err, "write custom sni")
		}
	}
	if u.Username != "" {
		err = writeTLV(builder, TagUsername, u.Username)
		if err != nil {
			return "", E.Cause(err, "write username")
		}
	}
	if u.Password != "" {
		err = writeTLV(builder, TagPassword, u.Password)
		if err != nil {
			return "", E.Cause(err, "write password")
		}
	}
	if !u.ClientRandomPrefix.IsEmpty() {
		err = writeTLV(builder, TagClientRandomPrefix, u.ClientRandomPrefix.String())
		if err != nil {
			return "", E.Cause(err, "write client random prefix")
		}
	}
	if u.SkipVerification {
		err = writeTLV(builder, TagSkipVerification, true)
		if err != nil {
			return "", E.Cause(err, "write skip verification")
		}
	}
	if cert := u.Certificate; len(cert) > 0 {
		err = writeTLV(builder, TagCertificate, cert)
		if err != nil {
			return "", E.Cause(err, "write certificate")
		}
	}
	if u.UpstreamProtocol != UpstreamProtocolHTTP2 {
		err = writeTLV(builder, TagUpstreamProtocol, byte(u.UpstreamProtocol))
		if err != nil {
			return "", E.Cause(err, "write upstream protocol")
		}
	}
	if u.AntiDPI {
		err = writeTLV(builder, TagAntiDPI, true)
		if err != nil {
			return "", E.Cause(err, "write anti-dpi")
		}
	}
	if name := u.Name; name != "" {
		err = writeTLV(builder, TagName, name)
		if err != nil {
			return "", E.Cause(err, "write name")
		}
	}
	if len(u.DNSUpstreams) > 0 {
		err = writeTLV(builder, TagDNSUpstreams, u.DNSUpstreams)
		if err != nil {
			return "", E.Cause(err, "write dns upstreams")
		}
	}
	if u.SubscriptionURL != "" {
		err = writeTLV(builder, TagSubscriptionURL, u.SubscriptionURL)
		if err != nil {
			return "", E.Cause(err, "write subscription url")
		}
	}
	if len(u.ClientRandomAuthKey) > 0 {
		err = writeTLV(builder, TagClientRandomAuthKey, hex.EncodeToString(u.ClientRandomAuthKey))
		if err != nil {
			return "", E.Cause(err, "write client random auth key")
		}
	}
	if u.TLSProfile != nil {
		err = writeTLV(builder, TagTLSProfile, byte(*u.TLSProfile))
		if err != nil {
			return "", E.Cause(err, "write tls profile")
		}
	}

	return Schema + "://?" + base64.RawURLEncoding.EncodeToString(builder.Bytes()), nil
}

func writeTLV(buffer *bytes.Buffer, tag uint64, data any) error {
	err := writeVarint(buffer, tag)
	if err != nil {
		return err
	}
	switch data := data.(type) {
	case byte:
		buffer.WriteByte(1)
		buffer.WriteByte(data)
	case bool:
		buffer.WriteByte(1)
		if data {
			buffer.WriteByte(0x01)
		} else {
			buffer.WriteByte(0x00)
		}
	case string:
		err = writeVarint(buffer, uint64(len(data)))
		if err != nil {
			return err
		}
		buffer.WriteString(data)
	case []byte:
		err = writeVarint(buffer, uint64(len(data)))
		if err != nil {
			return err
		}
		buffer.Write(data)
	case []string:
		var length int
		for i, value := range data {
			itemLengthSize, err := varintLength(uint64(len(value)))
			if err != nil {
				return E.Cause(err, "write string array length ", i)
			}
			length += itemLengthSize + len(value)
		}
		err = writeVarint(buffer, uint64(length))
		if err != nil {
			return E.Cause(err, "write string array tlv length")
		}
		for _, value := range data {
			// Lengths are validated by the loop above.
			_ = writeVarint(buffer, uint64(len(value)))
			buffer.WriteString(value)
		}
	default:
		panic("unexpected data type")
	}
	return nil
}

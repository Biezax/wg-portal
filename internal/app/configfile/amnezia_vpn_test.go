package configfile

import (
	"bytes"
	"compress/zlib"
	"encoding/binary"
	"io"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseEndpointHostPort(t *testing.T) {
	tests := []struct {
		name         string
		endpoint     string
		expectedHost string
		expectedPort int
	}{
		{"empty", "", "127.0.0.1", 51820},
		{"whitespace", "   ", "127.0.0.1", 51820},
		{"ipv4 with port", "192.168.1.1:51821", "192.168.1.1", 51821},
		{"ipv4 without port", "192.168.1.1", "192.168.1.1", 51820},
		{"hostname with port", "vpn.example.com:443", "vpn.example.com", 443},
		{"hostname without port", "vpn.example.com", "vpn.example.com", 51820},
		{"ipv6 with port", "[::1]:51821", "::1", 51821},
		{"ipv6 full with port", "[2001:db8::1]:8080", "2001:db8::1", 8080},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			host, port := parseEndpointHostPort(tt.endpoint)
			assert.Equal(t, tt.expectedHost, host)
			assert.Equal(t, tt.expectedPort, port)
		})
	}
}

func TestPickDnsServers(t *testing.T) {
	tests := []struct {
		name     string
		dns      string
		expected [2]string
	}{
		{"empty uses defaults", "", [2]string{"1.1.1.1", "1.0.0.1"}},
		{"single dns", "8.8.8.8", [2]string{"8.8.8.8", "1.0.0.1"}},
		{"two dns servers", "8.8.8.8,8.8.4.4", [2]string{"8.8.8.8", "8.8.4.4"}},
		{"with spaces", " 8.8.8.8 , 8.8.4.4 ", [2]string{"8.8.8.8", "8.8.4.4"}},
		{"three dns servers", "1.1.1.1,8.8.8.8,9.9.9.9", [2]string{"1.1.1.1", "8.8.8.8"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dns1, dns2 := pickDnsServers(tt.dns)
			assert.Equal(t, tt.expected[0], dns1)
			assert.Equal(t, tt.expected[1], dns2)
		})
	}
}

func TestSplitCsvOrDefault(t *testing.T) {
	tests := []struct {
		name     string
		value    string
		fallback string
		expected []string
	}{
		{"empty uses fallback", "", "a,b", []string{"a", "b"}},
		{"whitespace uses fallback", "   ", "a,b", []string{"a", "b"}},
		{"single value", "x", "a,b", []string{"x"}},
		{"multiple values", "x,y,z", "a,b", []string{"x", "y", "z"}},
		{"with spaces", " x , y , z ", "a,b", []string{"x", "y", "z"}},
		{"empty items filtered", "x,,y", "a,b", []string{"x", "y"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := splitCsvOrDefault(tt.value, tt.fallback)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestU16ToString(t *testing.T) {
	assert.Equal(t, "0", u16ToString(0))
	assert.Equal(t, "1", u16ToString(1))
	assert.Equal(t, "65535", u16ToString(65535))
	assert.Equal(t, "1000", u16ToString(1000))
}

func TestU16ToStringOptional(t *testing.T) {
	assert.Equal(t, "", u16ToStringOptional(0))
	assert.Equal(t, "1", u16ToStringOptional(1))
	assert.Equal(t, "65535", u16ToStringOptional(65535))
	assert.Equal(t, "1000", u16ToStringOptional(1000))
}

func TestQtQCompress(t *testing.T) {
	data := []byte("test data for compression")

	compressed, err := qtQCompress(data, 6)
	require.NoError(t, err)
	require.True(t, len(compressed) > 4)

	// First 4 bytes are big-endian size header
	sizeHeader := binary.BigEndian.Uint32(compressed[:4])
	assert.Equal(t, uint32(len(data)), sizeHeader)

	// Rest is zlib-compressed data
	zlibReader, err := zlib.NewReader(bytes.NewReader(compressed[4:]))
	require.NoError(t, err)
	defer zlibReader.Close()

	decompressed, err := io.ReadAll(zlibReader)
	require.NoError(t, err)
	assert.Equal(t, data, decompressed)
}

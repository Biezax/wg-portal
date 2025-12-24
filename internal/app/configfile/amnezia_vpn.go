package configfile

import (
	"bytes"
	"compress/zlib"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net"
	"strconv"
	"strings"

	"github.com/biezax/wg-portal/internal/domain"
)

type amneziaEnvelope struct {
	Containers       []amneziaContainer `json:"containers"`
	DefaultContainer string            `json:"defaultContainer"`
	Description      string            `json:"description"`
	DNS1             string            `json:"dns1"`
	DNS2             string            `json:"dns2"`
	HostName         string            `json:"hostName"`
}

type amneziaContainer struct {
	Awg       amneziaAwgContainer `json:"awg"`
	Container string             `json:"container"`
}

type amneziaAwgContainer struct {
	H1 string `json:"H1"`
	H2 string `json:"H2"`
	H3 string `json:"H3"`
	H4 string `json:"H4"`
	Jc string `json:"Jc"`
	Jmax string `json:"Jmax"`
	Jmin string `json:"Jmin"`
	S1 string `json:"S1"`
	S2 string `json:"S2"`

	S3 string `json:"S3,omitempty"`
	S4 string `json:"S4,omitempty"`
	I1 string `json:"I1,omitempty"`
	I2 string `json:"I2,omitempty"`
	I3 string `json:"I3,omitempty"`
	I4 string `json:"I4,omitempty"`
	I5 string `json:"I5,omitempty"`

	LastConfig     string `json:"last_config"`
	Port           string `json:"port"`
	TransportProto string `json:"transport_proto"`
}

type amneziaAwgLastConfig struct {
	H1 string `json:"H1"`
	H2 string `json:"H2"`
	H3 string `json:"H3"`
	H4 string `json:"H4"`
	Jc string `json:"Jc"`
	Jmax string `json:"Jmax"`
	Jmin string `json:"Jmin"`
	S1 string `json:"S1"`
	S2 string `json:"S2"`

	S3 string `json:"S3,omitempty"`
	S4 string `json:"S4,omitempty"`
	I1 string `json:"I1,omitempty"`
	I2 string `json:"I2,omitempty"`
	I3 string `json:"I3,omitempty"`
	I4 string `json:"I4,omitempty"`
	I5 string `json:"I5,omitempty"`

	AllowedIPs []string `json:"allowed_ips"`

	ClientID      string `json:"clientId"`
	ClientIP      string `json:"client_ip"`
	ClientPrivKey string `json:"client_priv_key"`
	ClientPubKey  string `json:"client_pub_key"`

	Config string `json:"config"`

	HostName             string `json:"hostName"`
	MTU                  string `json:"mtu"`
	PersistentKeepAlive  string `json:"persistent_keep_alive"`
	Port                 int    `json:"port"`
	PSKKey               string `json:"psk_key"`
	ServerPubKey         string `json:"server_pub_key"`
}

func buildAmneziaAwgVpnLink(peer *domain.Peer, description, configText string) (string, error) {
	if peer == nil {
		return "", fmt.Errorf("nil peer")
	}
	if peer.Interface.AdvancedSecurity == nil {
		return "", fmt.Errorf("missing advanced security")
	}

	endpointHost, endpointPort := parseEndpointHostPort(peer.Endpoint.GetValue())
	dns1, dns2 := pickDnsServers(peer.Interface.DnsStr.GetValue())

	privKey := peer.Interface.KeyPair.PrivateKey
	clientPubKey := domain.PublicKeyFromPrivateKey(privKey)
	if clientPubKey == "" {
		clientPubKey = peer.Interface.KeyPair.PublicKey
	}

	clientIP := ""
	if len(peer.Interface.Addresses) > 0 {
		clientIP = strings.TrimSpace(peer.Interface.Addresses[0].Addr)
	}

	allowedIPs := splitCsvOrDefault(peer.AllowedIPsStr.GetValue(), "0.0.0.0/0,::/0")

	mtu := peer.Interface.Mtu.GetValue()
	mtuStr := "1280"
	if mtu != 0 {
		mtuStr = strconv.Itoa(mtu)
	}

	keepAlive := peer.PersistentKeepalive.GetValue()
	keepAliveStr := "25"
	if keepAlive != 0 {
		keepAliveStr = strconv.Itoa(keepAlive)
	}

	serverPubKey := strings.TrimSpace(peer.EndpointPublicKey.GetValue())
	psk := strings.TrimSpace(string(peer.PresharedKey))

	adv := peer.Interface.AdvancedSecurity
	base := amneziaAwgBaseParams(adv)
	ext := amneziaAwgExtendedParams(adv)

	lastCfg := amneziaAwgLastConfig{
		H1: base.H1,
		H2: base.H2,
		H3: base.H3,
		H4: base.H4,
		Jc: base.Jc,
		Jmax: base.Jmax,
		Jmin: base.Jmin,
		S1: base.S1,
		S2: base.S2,

		S3: ext.S3,
		S4: ext.S4,
		I1: ext.I1,
		I2: ext.I2,
		I3: ext.I3,
		I4: ext.I4,
		I5: ext.I5,

		AllowedIPs: allowedIPs,

		ClientID:      clientPubKey,
		ClientIP:      clientIP,
		ClientPrivKey: privKey,
		ClientPubKey:  clientPubKey,

		Config: configText,

		HostName:            endpointHost,
		MTU:                 mtuStr,
		PersistentKeepAlive: keepAliveStr,
		Port:                endpointPort,
		PSKKey:              psk,
		ServerPubKey:        serverPubKey,
	}

	lastCfgJSON, err := json.Marshal(lastCfg)
	if err != nil {
		return "", fmt.Errorf("marshal last_config: %w", err)
	}

	envelope := amneziaEnvelope{
		Containers: []amneziaContainer{
			{
				Awg: amneziaAwgContainer{
					H1: base.H1,
					H2: base.H2,
					H3: base.H3,
					H4: base.H4,
					Jc: base.Jc,
					Jmax: base.Jmax,
					Jmin: base.Jmin,
					S1: base.S1,
					S2: base.S2,

					S3: ext.S3,
					S4: ext.S4,
					I1: ext.I1,
					I2: ext.I2,
					I3: ext.I3,
					I4: ext.I4,
					I5: ext.I5,

					LastConfig:     string(lastCfgJSON),
					Port:           strconv.Itoa(endpointPort),
					TransportProto: "udp",
				},
				Container: "amnezia-awg",
			},
		},
		DefaultContainer: "amnezia-awg",
		Description:      description,
		DNS1:             dns1,
		DNS2:             dns2,
		HostName:         endpointHost,
	}

	envelopeJSON, err := json.Marshal(envelope)
	if err != nil {
		return "", fmt.Errorf("marshal envelope: %w", err)
	}

	compressed, err := qtQCompress(envelopeJSON, 8)
	if err != nil {
		return "", err
	}

	encoded := base64.RawURLEncoding.EncodeToString(compressed)
	return "vpn://" + encoded, nil
}

type amneziaAwgBase struct {
	H1   string
	H2   string
	H3   string
	H4   string
	Jc   string
	Jmax string
	Jmin string
	S1   string
	S2   string
}

type amneziaAwgExtended struct {
	S3 string
	S4 string
	I1 string
	I2 string
	I3 string
	I4 string
	I5 string
}

func amneziaAwgBaseParams(adv *domain.AdvancedSecurity) amneziaAwgBase {
	if adv == nil {
		return amneziaAwgBase{}
	}
	return amneziaAwgBase{
		H1: strings.TrimSpace(adv.InitPacketMagicHeader),
		H2: strings.TrimSpace(adv.ResponsePacketMagicHeader),
		H3: strings.TrimSpace(adv.UnderloadPacketMagicHeader),
		H4: strings.TrimSpace(adv.TransportPacketMagicHeader),
		Jc: u16ToString(adv.JunkPacketCount),
		Jmax: u16ToString(adv.JunkPacketMaxSize),
		Jmin: u16ToString(adv.JunkPacketMinSize),
		S1: u16ToString(adv.InitPacketJunkSize),
		S2: u16ToString(adv.ResponsePacketJunkSize),
	}
}

func amneziaAwgExtendedParams(adv *domain.AdvancedSecurity) amneziaAwgExtended {
	if adv == nil {
		return amneziaAwgExtended{}
	}

	ext := amneziaAwgExtended{
		S3: u16ToStringOptional(adv.CookieReplyPacketJunkSize),
		S4: u16ToStringOptional(adv.TransportPacketJunkSize),
	}

	if adv.FirstSpecialJunkPacket != nil {
		ext.I1 = strings.TrimSpace(*adv.FirstSpecialJunkPacket)
	}
	if adv.SecondSpecialJunkPacket != nil {
		ext.I2 = strings.TrimSpace(*adv.SecondSpecialJunkPacket)
	}
	if adv.ThirdSpecialJunkPacket != nil {
		ext.I3 = strings.TrimSpace(*adv.ThirdSpecialJunkPacket)
	}
	if adv.FourthSpecialJunkPacket != nil {
		ext.I4 = strings.TrimSpace(*adv.FourthSpecialJunkPacket)
	}
	if adv.FifthSpecialJunkPacket != nil {
		ext.I5 = strings.TrimSpace(*adv.FifthSpecialJunkPacket)
	}

	// Use omitempty on JSON fields, so we normalize empty strings to "".
	return ext
}

func u16ToString(v uint16) string {
	return strconv.Itoa(int(v))
}

func u16ToStringOptional(v uint16) string {
	if v == 0 {
		return ""
	}
	return strconv.Itoa(int(v))
}

func qtQCompress(data []byte, level int) ([]byte, error) {
	var buf bytes.Buffer

	var sizeHdr [4]byte
	binary.BigEndian.PutUint32(sizeHdr[:], uint32(len(data)))
	_, _ = buf.Write(sizeHdr[:])

	zw, err := zlib.NewWriterLevel(&buf, level)
	if err != nil {
		return nil, fmt.Errorf("zlib writer: %w", err)
	}
	if _, err := zw.Write(data); err != nil {
		_ = zw.Close()
		return nil, fmt.Errorf("zlib write: %w", err)
	}
	if err := zw.Close(); err != nil {
		return nil, fmt.Errorf("zlib close: %w", err)
	}

	return buf.Bytes(), nil
}

func parseEndpointHostPort(endpoint string) (host string, port int) {
	host = "127.0.0.1"
	port = 51820

	endpoint = strings.TrimSpace(endpoint)
	if endpoint == "" {
		return host, port
	}

	h, p, err := net.SplitHostPort(endpoint)
	if err != nil {
		return endpoint, port
	}
	if h = strings.TrimSpace(h); h != "" {
		host = h
	}
	if pi, err := strconv.Atoi(p); err == nil {
		port = pi
	}
	return host, port
}

func pickDnsServers(dns string) (dns1, dns2 string) {
	parts := splitCsvOrDefault(dns, "1.1.1.1,1.0.0.1")
	dns1 = "1.1.1.1"
	dns2 = "1.0.0.1"
	if len(parts) > 0 {
		dns1 = parts[0]
	}
	if len(parts) > 1 {
		dns2 = parts[1]
	}
	return dns1, dns2
}

func splitCsvOrDefault(value, fallback string) []string {
	raw := strings.TrimSpace(value)
	if raw == "" {
		raw = fallback
	}
	raw = strings.ReplaceAll(raw, " ", "")
	if raw == "" {
		return nil
	}

	items := strings.Split(raw, ",")
	out := make([]string, 0, len(items))
	for _, item := range items {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}
		out = append(out, item)
	}
	return out
}



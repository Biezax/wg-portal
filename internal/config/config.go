package config

import (
	"bytes"
	"fmt"
	"io"
	"log/slog"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/a8m/envsubst"
	"gopkg.in/yaml.v3"
)

const (
	WireGuardModeDisabled  = "disabled"
	WireGuardModeWireGuard = "wireguard"
	WireGuardModeAmneziaWG = "amneziawg"
)

// maxAwgStringLen matches wgctrl ioctl buffer limit for special junk packets
const maxAwgStringLen = 5 * 1024

// Config is the main configuration struct.
type Config struct {
	Core struct {
		// AdminUser defines the default administrator account that will be created
		AdminUserDisabled bool   `yaml:"disable_admin_user"`
		AdminUser         string `yaml:"admin_user"`
		AdminPassword     string `yaml:"admin_password"`
		AdminApiToken     string `yaml:"admin_api_token"` // if set, the API access is enabled automatically
		WireGuardMode     string `yaml:"wireguard_mode"`

		EditableKeys                bool `yaml:"editable_keys"`
		CreateDefaultPeer           bool `yaml:"create_default_peer"`
		CreateDefaultPeerOnCreation bool `yaml:"create_default_peer_on_creation"`
		ReEnablePeerAfterUserEnable bool `yaml:"re_enable_peer_after_user_enable"`
		DeletePeerAfterUserDeleted  bool `yaml:"delete_peer_after_user_deleted"`
		ImportExisting              bool `yaml:"import_existing"`
		RestoreState                bool `yaml:"restore_state"`
	} `yaml:"core"`

	Advanced struct {
		LogLevel            string        `yaml:"log_level"`
		LogPretty           bool          `yaml:"log_pretty"`
		LogJson             bool          `yaml:"log_json"`
		StartListenPort     int           `yaml:"start_listen_port"`
		StartCidrV4         string        `yaml:"start_cidr_v4"`
		StartCidrV6         string        `yaml:"start_cidr_v6"`
		UseIpV6             bool          `yaml:"use_ip_v6"`
		ConfigStoragePath   string        `yaml:"config_storage_path"` // keep empty to disable config export to file
		ExpiryCheckInterval time.Duration `yaml:"expiry_check_interval"`
		RulePrioOffset      int           `yaml:"rule_prio_offset"`
		RouteTableOffset    int           `yaml:"route_table_offset"`
		ApiAdminOnly        bool          `yaml:"api_admin_only"` // if true, only admin users can access the API
	} `yaml:"advanced"`

	Backend Backend `yaml:"backend"`

	Statistics struct {
		UsePingChecks          bool          `yaml:"use_ping_checks"`
		PingCheckWorkers       int           `yaml:"ping_check_workers"`
		PingUnprivileged       bool          `yaml:"ping_unprivileged"`
		PingCheckInterval      time.Duration `yaml:"ping_check_interval"`
		DataCollectionInterval time.Duration `yaml:"data_collection_interval"`
		CollectInterfaceData   bool          `yaml:"collect_interface_data"`
		CollectPeerData        bool          `yaml:"collect_peer_data"`
		CollectAuditData       bool          `yaml:"collect_audit_data"`
		ListeningAddress       string        `yaml:"listening_address"`
	} `yaml:"statistics"`

	Mail MailConfig `yaml:"mail"`

	Auth Auth `yaml:"auth"`

	Database DatabaseConfig `yaml:"database"`

	Web WebConfig `yaml:"web"`

	Webhook WebhookConfig `yaml:"webhook"`

	Provisioning ProvisioningConfig `yaml:"provisioning"`
}

type ProvisioningConfig struct {
	Interfaces []ProvisioningInterface `yaml:"interfaces"`
}

type ProvisioningInterface struct {
	Identifier  string `yaml:"identifier"`
	DisplayName string `yaml:"display_name"`
	Mode        string `yaml:"mode"` // server, client, any

	Enabled *bool `yaml:"enabled"` // default: true

	PrivateKey string   `yaml:"private_key"`
	ListenPort int      `yaml:"listen_port"`
	Addresses  []string `yaml:"addresses"`

	Dns       []string `yaml:"dns"`
	DnsSearch []string `yaml:"dns_search"`

	Mtu          int    `yaml:"mtu"`
	FirewallMark uint32 `yaml:"firewall_mark"`
	RoutingTable string `yaml:"routing_table"`

	PreUp    string `yaml:"pre_up"`
	PostUp   string `yaml:"post_up"`
	PreDown  string `yaml:"pre_down"`
	PostDown string `yaml:"post_down"`

	SaveConfig *bool  `yaml:"save_config"` // default: cfg.Advanced.ConfigStoragePath != ""
	Notes      string `yaml:"notes"`

	PeerDefNetwork             []string `yaml:"peer_def_network"`
	PeerDefDns                 []string `yaml:"peer_def_dns"`
	PeerDefDnsSearch           []string `yaml:"peer_def_dns_search"`
	PeerDefEndpoint            string   `yaml:"peer_def_endpoint"`
	PeerDefAllowedIPs          []string `yaml:"peer_def_allowed_ips"`
	PeerDefMtu                 int      `yaml:"peer_def_mtu"`
	PeerDefPersistentKeepalive int      `yaml:"peer_def_persistent_keepalive"`
	PeerDefFirewallMark        uint32   `yaml:"peer_def_firewall_mark"`
	PeerDefRoutingTable        string   `yaml:"peer_def_routing_table"`
	PeerDefPreUp               string   `yaml:"peer_def_pre_up"`
	PeerDefPostUp              string   `yaml:"peer_def_post_up"`
	PeerDefPreDown             string   `yaml:"peer_def_pre_down"`
	PeerDefPostDown            string   `yaml:"peer_def_post_down"`

	AdvancedSecurity *ProvisioningInterfaceAdvancedSecurity `yaml:"advanced_security"`
}

type ProvisioningInterfaceAdvancedSecurity struct {
	JunkPacketCount   uint16 `yaml:"jc"`
	JunkPacketMinSize uint16 `yaml:"jmin"`
	JunkPacketMaxSize uint16 `yaml:"jmax"`

	InitPacketJunkSize        uint16 `yaml:"s1"`
	ResponsePacketJunkSize    uint16 `yaml:"s2"`
	CookieReplyPacketJunkSize uint16 `yaml:"s3"`
	TransportPacketJunkSize   uint16 `yaml:"s4"`

	InitPacketMagicHeader      string `yaml:"h1"`
	ResponsePacketMagicHeader  string `yaml:"h2"`
	UnderloadPacketMagicHeader string `yaml:"h3"`
	TransportPacketMagicHeader string `yaml:"h4"`

	FirstSpecialJunkPacket  *string `yaml:"i1"`
	SecondSpecialJunkPacket *string `yaml:"i2"`
	ThirdSpecialJunkPacket  *string `yaml:"i3"`
	FourthSpecialJunkPacket *string `yaml:"i4"`
	FifthSpecialJunkPacket  *string `yaml:"i5"`
}

func (c *Config) Sanitize() error {
	c.Core.WireGuardMode = strings.TrimSpace(strings.ToLower(c.Core.WireGuardMode))
	if c.Core.WireGuardMode == "" {
		c.Core.WireGuardMode = WireGuardModeDisabled
	}
	switch c.Core.WireGuardMode {
	case WireGuardModeDisabled, WireGuardModeWireGuard, WireGuardModeAmneziaWG:
		// ok
	default:
		return fmt.Errorf("invalid core.wireguard_mode %q", c.Core.WireGuardMode)
	}

	if err := sanitizeProvisioningInterfaces(c); err != nil {
		return err
	}
	return nil
}

func sanitizeProvisioningInterfaces(c *Config) error {
	if len(c.Provisioning.Interfaces) == 0 {
		return nil
	}

	seen := make(map[string]struct{}, len(c.Provisioning.Interfaces))
	for idx := range c.Provisioning.Interfaces {
		iface := &c.Provisioning.Interfaces[idx]

		id := strings.TrimSpace(iface.Identifier)
		if id == "" {
			return fmt.Errorf("provisioning.interfaces[%d].identifier must not be empty", idx)
		}
		iface.Identifier = id

		if _, ok := seen[id]; ok {
			return fmt.Errorf("provisioning.interfaces.identifier %q is not unique", id)
		}
		seen[id] = struct{}{}

		mode := strings.ToLower(strings.TrimSpace(iface.Mode))
		if mode != "" {
			switch mode {
			case "server", "client", "any":
				iface.Mode = mode
			default:
				return fmt.Errorf("provisioning.interfaces[%s].mode must be one of: server, client, any", id)
			}
		}

		if iface.ListenPort != 0 && (iface.ListenPort < 1 || iface.ListenPort > 65535) {
			return fmt.Errorf("provisioning.interfaces[%s].listen_port must be 0 or between 1 and 65535", id)
		}

		if iface.Mtu < 0 {
			return fmt.Errorf("provisioning.interfaces[%s].mtu must be >= 0", id)
		}
		if iface.PeerDefMtu < 0 {
			return fmt.Errorf("provisioning.interfaces[%s].peer_def_mtu must be >= 0", id)
		}

		if len(iface.Addresses) > 0 {
			if err := validateCidrArray(fmt.Sprintf("provisioning.interfaces[%s].addresses", id), iface.Addresses); err != nil {
				return err
			}
		}
		if len(iface.PeerDefAllowedIPs) > 0 {
			if err := validateCidrArray(fmt.Sprintf("provisioning.interfaces[%s].peer_def_allowed_ips", id), iface.PeerDefAllowedIPs); err != nil {
				return err
			}
		}
		if len(iface.PeerDefNetwork) > 0 {
			if err := validateCidrArray(fmt.Sprintf("provisioning.interfaces[%s].peer_def_network", id), iface.PeerDefNetwork); err != nil {
				return err
			}
		}

		if iface.AdvancedSecurity != nil {
			if c.Core.WireGuardMode != WireGuardModeAmneziaWG {
				return fmt.Errorf("provisioning.interfaces[%s].advanced_security is only supported with core.wireguard_mode %q", id, WireGuardModeAmneziaWG)
			}
			if err := validateAdvancedSecurity(fmt.Sprintf("provisioning.interfaces[%s].advanced_security", id), iface.AdvancedSecurity); err != nil {
				return err
			}
		}

		// non-fatal hints for common misconfigurations
		if len(iface.Dns) > 0 && len(iface.PeerDefDns) == 0 {
			slog.Warn("provisioning: interface dns set but peer_def_dns is empty; peers will not inherit dns",
				"interface", id)
		}
		if iface.Mtu != 0 && iface.PeerDefMtu == 0 {
			slog.Warn("provisioning: interface mtu set but peer_def_mtu is not set; peers will use default mtu",
				"interface", id,
				"mtu", iface.Mtu)
		}
	}

	return nil
}

func validateCidrArray(field string, cidrs []string) error {
	for i, raw := range cidrs {
		val := strings.TrimSpace(raw)
		if val == "" {
			return fmt.Errorf("%s[%d] must not be empty", field, i)
		}
		if _, err := netip.ParsePrefix(val); err != nil {
			return fmt.Errorf("%s[%d] invalid CIDR %q: %w", field, i, raw, err)
		}
	}
	return nil
}

func validateAdvancedSecurity(field string, s *ProvisioningInterfaceAdvancedSecurity) error {
	// junk packets: require coherent range if enabled
	if s.JunkPacketCount > 0 {
		if s.JunkPacketMinSize == 0 || s.JunkPacketMaxSize == 0 {
			return fmt.Errorf("%s: jmin and jmax must be > 0 when jc > 0", field)
		}
		if s.JunkPacketMinSize > s.JunkPacketMaxSize {
			return fmt.Errorf("%s: jmin must be <= jmax", field)
		}
	} else if s.JunkPacketMinSize != 0 || s.JunkPacketMaxSize != 0 {
		slog.Warn("advanced_security: jmin/jmax set but jc=0; junk packets disabled", "field", field)
	}

	// headers: validate as uint32 (decimal or 0x...) when present
	if err := validateAwgUint32IfSet(field+".init_packet_magic_header (h1)", s.InitPacketMagicHeader); err != nil {
		return err
	}
	if err := validateAwgUint32IfSet(field+".response_packet_magic_header (h2)", s.ResponsePacketMagicHeader); err != nil {
		return err
	}
	if err := validateAwgUint32IfSet(field+".underload_packet_magic_header (h3)", s.UnderloadPacketMagicHeader); err != nil {
		return err
	}
	if err := validateAwgUint32IfSet(field+".transport_packet_magic_header (h4)", s.TransportPacketMagicHeader); err != nil {
		return err
	}

	// special junk packets: non-empty and within wgctrl limits when present
	if err := validateAwgStringPtr(field+".first_special_junk_packet (i1)", &s.FirstSpecialJunkPacket); err != nil {
		return err
	}
	if err := validateAwgStringPtr(field+".second_special_junk_packet (i2)", &s.SecondSpecialJunkPacket); err != nil {
		return err
	}
	if err := validateAwgStringPtr(field+".third_special_junk_packet (i3)", &s.ThirdSpecialJunkPacket); err != nil {
		return err
	}
	if err := validateAwgStringPtr(field+".fourth_special_junk_packet (i4)", &s.FourthSpecialJunkPacket); err != nil {
		return err
	}
	if err := validateAwgStringPtr(field+".fifth_special_junk_packet (i5)", &s.FifthSpecialJunkPacket); err != nil {
		return err
	}

	return nil
}

func validateAwgUint32IfSet(field, raw string) error {
	val := strings.TrimSpace(raw)
	if val == "" {
		return nil
	}
	if _, err := strconv.ParseUint(val, 0, 32); err != nil {
		return fmt.Errorf("%s must be a uint32 (decimal or 0x...): %w", field, err)
	}
	return nil
}

func validateAwgStringPtr(field string, raw **string) error {
	if raw == nil || *raw == nil {
		return nil
	}
	val := strings.TrimSpace(**raw)
	if val == "" {
		return fmt.Errorf("%s must not be empty", field)
	}
	if len(val) >= maxAwgStringLen {
		return fmt.Errorf("%s must be shorter than %d bytes", field, maxAwgStringLen)
	}
	**raw = val
	return nil
}

// LogStartupValues logs the startup values of the configuration in debug level
func (c *Config) LogStartupValues() {
	slog.Info("Configuration loaded!", "logLevel", c.Advanced.LogLevel)

	slog.Debug("Config Features",
		"wireguardMode", c.Core.WireGuardMode,
		"editableKeys", c.Core.EditableKeys,
		"createDefaultPeerOnCreation", c.Core.CreateDefaultPeerOnCreation,
		"reEnablePeerAfterUserEnable", c.Core.ReEnablePeerAfterUserEnable,
		"deletePeerAfterUserDeleted", c.Core.DeletePeerAfterUserDeleted,
		"importExisting", c.Core.ImportExisting,
		"restoreState", c.Core.RestoreState,
		"useIpV6", c.Advanced.UseIpV6,
		"collectInterfaceData", c.Statistics.CollectInterfaceData,
		"collectPeerData", c.Statistics.CollectPeerData,
		"collectAuditData", c.Statistics.CollectAuditData,
	)

	slog.Debug("Config Settings",
		"configStoragePath", c.Advanced.ConfigStoragePath,
		"externalUrl", c.Web.ExternalUrl,
	)

	slog.Debug("Config Authentication",
		"oidcProviders", len(c.Auth.OpenIDConnect),
		"oauthProviders", len(c.Auth.OAuth),
		"ldapProviders", len(c.Auth.Ldap),
		"webauthnEnabled", c.Auth.WebAuthn.Enabled,
		"minPasswordLength", c.Auth.MinPasswordLength,
		"hideLoginForm", c.Auth.HideLoginForm,
	)

	slog.Debug("Config Backend",
		"defaultBackend", c.Backend.Default,
		"extraBackends", len(c.Backend.Mikrotik),
	)

}

// defaultConfig returns the default configuration
func defaultConfig() *Config {
	cfg := &Config{}

	cfg.Core.AdminUserDisabled = getEnvBool("WG_PORTAL_CORE_DISABLE_ADMIN_USER", false)
	cfg.Core.AdminUser = getEnvStr("WG_PORTAL_CORE_ADMIN_USER", "admin@wgportal.local")
	cfg.Core.AdminPassword = getEnvStr("WG_PORTAL_CORE_ADMIN_PASSWORD", "wgportal-default")
	cfg.Core.AdminApiToken = getEnvStr("WG_PORTAL_CORE_ADMIN_API_TOKEN", "") // by default, the API access is disabled
	cfg.Core.WireGuardMode = getEnvStr("WG_PORTAL_CORE_WIREGUARD_MODE", WireGuardModeDisabled)
	cfg.Core.ImportExisting = getEnvBool("WG_PORTAL_CORE_IMPORT_EXISTING", true)
	cfg.Core.RestoreState = getEnvBool("WG_PORTAL_CORE_RESTORE_STATE", true)
	cfg.Core.CreateDefaultPeer = getEnvBool("WG_PORTAL_CORE_CREATE_DEFAULT_PEER", false)
	cfg.Core.CreateDefaultPeerOnCreation = getEnvBool("WG_PORTAL_CORE_CREATE_DEFAULT_PEER_ON_CREATION", false)
	cfg.Core.EditableKeys = getEnvBool("WG_PORTAL_CORE_EDITABLE_KEYS", true)
	cfg.Core.ReEnablePeerAfterUserEnable = getEnvBool("WG_PORTAL_CORE_RE_ENABLE_PEER_AFTER_USER_ENABLE", true)
	cfg.Core.DeletePeerAfterUserDeleted = getEnvBool("WG_PORTAL_CORE_DELETE_PEER_AFTER_USER_DELETED", false)

	cfg.Database = DatabaseConfig{
		Debug:                getEnvBool("WG_PORTAL_DATABASE_DEBUG", false),
		SlowQueryThreshold:   getEnvDuration("WG_PORTAL_DATABASE_SLOW_QUERY_THRESHOLD", 0),
		Type:                 SupportedDatabase(getEnvStr("WG_PORTAL_DATABASE_TYPE", "sqlite")),
		DSN:                  getEnvStr("WG_PORTAL_DATABASE_DSN", "data/sqlite.db"),
		EncryptionPassphrase: getEnvStr("WG_PORTAL_DATABASE_ENCRYPTION_PASSPHRASE", ""),
	}

	cfg.Backend = Backend{
		Default:                LocalBackendName, // local backend is the default (using wgcrtl)
		IgnoredLocalInterfaces: getEnvStrSlice("WG_PORTAL_BACKEND_IGNORED_LOCAL_INTERFACES", nil),
		// Most resolconf implementations use "tun." as a prefix for interface names.
		// But systemd's implementation uses no prefix, for example.
		LocalResolvconfPrefix: getEnvStr("WG_PORTAL_BACKEND_LOCAL_RESOLVCONF_PREFIX", "tun."),
	}

	cfg.Web = WebConfig{
		RequestLogging:    getEnvBool("WG_PORTAL_WEB_REQUEST_LOGGING", false),
		ExposeHostInfo:    getEnvBool("WG_PORTAL_WEB_EXPOSE_HOST_INFO", false),
		ExternalUrl:       getEnvStr("WG_PORTAL_WEB_EXTERNAL_URL", "http://localhost:8888"),
		ListeningAddress:  getEnvStr("WG_PORTAL_WEB_LISTENING_ADDRESS", ":8888"),
		SessionIdentifier: getEnvStr("WG_PORTAL_WEB_SESSION_IDENTIFIER", "wgPortalSession"),
		SessionSecret:     getEnvStr("WG_PORTAL_WEB_SESSION_SECRET", "very_secret"),
		CsrfSecret:        getEnvStr("WG_PORTAL_WEB_CSRF_SECRET", "extremely_secret"),
		SiteTitle:         getEnvStr("WG_PORTAL_WEB_SITE_TITLE", "WireGuard Portal"),
		SiteCompanyName:   getEnvStr("WG_PORTAL_WEB_SITE_COMPANY_NAME", "WireGuard Portal"),
		CertFile:          getEnvStr("WG_PORTAL_WEB_CERT_FILE", ""),
		KeyFile:           getEnvStr("WG_PORTAL_WEB_KEY_FILE", ""),
	}

	cfg.Advanced.LogLevel = getEnvStr("WG_PORTAL_ADVANCED_LOG_LEVEL", "info")
	cfg.Advanced.LogPretty = getEnvBool("WG_PORTAL_ADVANCED_LOG_PRETTY", false)
	cfg.Advanced.LogJson = getEnvBool("WG_PORTAL_ADVANCED_LOG_JSON", false)
	cfg.Advanced.StartListenPort = getEnvInt("WG_PORTAL_ADVANCED_START_LISTEN_PORT", 51820)
	cfg.Advanced.StartCidrV4 = getEnvStr("WG_PORTAL_ADVANCED_START_CIDR_V4", "10.11.12.0/24")
	cfg.Advanced.StartCidrV6 = getEnvStr("WG_PORTAL_ADVANCED_START_CIDR_V6", "fdfd:d3ad:c0de:1234::0/64")
	cfg.Advanced.UseIpV6 = getEnvBool("WG_PORTAL_ADVANCED_USE_IP_V6", true)
	cfg.Advanced.ConfigStoragePath = getEnvStr("WG_PORTAL_ADVANCED_CONFIG_STORAGE_PATH", "")
	cfg.Advanced.ExpiryCheckInterval = getEnvDuration("WG_PORTAL_ADVANCED_EXPIRY_CHECK_INTERVAL", 15*time.Minute)
	cfg.Advanced.RulePrioOffset = getEnvInt("WG_PORTAL_ADVANCED_RULE_PRIO_OFFSET", 20000)
	cfg.Advanced.RouteTableOffset = getEnvInt("WG_PORTAL_ADVANCED_ROUTE_TABLE_OFFSET", 20000)
	cfg.Advanced.ApiAdminOnly = getEnvBool("WG_PORTAL_ADVANCED_API_ADMIN_ONLY", true)

	cfg.Statistics.UsePingChecks = getEnvBool("WG_PORTAL_STATISTICS_USE_PING_CHECKS", true)
	cfg.Statistics.PingCheckWorkers = getEnvInt("WG_PORTAL_STATISTICS_PING_CHECK_WORKERS", 10)
	cfg.Statistics.PingUnprivileged = getEnvBool("WG_PORTAL_STATISTICS_PING_UNPRIVILEGED", false)
	cfg.Statistics.PingCheckInterval = getEnvDuration("WG_PORTAL_STATISTICS_PING_CHECK_INTERVAL", 1*time.Minute)
	cfg.Statistics.DataCollectionInterval = getEnvDuration("WG_PORTAL_STATISTICS_DATA_COLLECTION_INTERVAL",
		1*time.Minute)
	cfg.Statistics.CollectInterfaceData = getEnvBool("WG_PORTAL_STATISTICS_COLLECT_INTERFACE_DATA", true)
	cfg.Statistics.CollectPeerData = getEnvBool("WG_PORTAL_STATISTICS_COLLECT_PEER_DATA", true)
	cfg.Statistics.CollectAuditData = getEnvBool("WG_PORTAL_STATISTICS_COLLECT_AUDIT_DATA", true)
	cfg.Statistics.ListeningAddress = getEnvStr("WG_PORTAL_STATISTICS_LISTENING_ADDRESS", ":8787")

	cfg.Mail = MailConfig{
		Host:           getEnvStr("WG_PORTAL_MAIL_HOST", "127.0.0.1"),
		Port:           getEnvInt("WG_PORTAL_MAIL_PORT", 25),
		Encryption:     MailEncryption(getEnvStr("WG_PORTAL_MAIL_ENCRYPTION", string(MailEncryptionNone))),
		CertValidation: getEnvBool("WG_PORTAL_MAIL_CERT_VALIDATION", true),
		Username:       getEnvStr("WG_PORTAL_MAIL_USERNAME", ""),
		Password:       getEnvStr("WG_PORTAL_MAIL_PASSWORD", ""),
		AuthType:       MailAuthType(getEnvStr("WG_PORTAL_MAIL_AUTH_TYPE", string(MailAuthPlain))),
		From:           getEnvStr("WG_PORTAL_MAIL_FROM", "Wireguard Portal <noreply@wireguard.local>"),
		LinkOnly:       getEnvBool("WG_PORTAL_MAIL_LINK_ONLY", false),
		AllowPeerEmail: getEnvBool("WG_PORTAL_MAIL_ALLOW_PEER_EMAIL", false),
	}

	cfg.Webhook.Url = getEnvStr("WG_PORTAL_WEBHOOK_URL", "") // no webhook by default
	cfg.Webhook.Authentication = getEnvStr("WG_PORTAL_WEBHOOK_AUTHENTICATION", "")
	cfg.Webhook.Timeout = getEnvDuration("WG_PORTAL_WEBHOOK_TIMEOUT", 10*time.Second)

	cfg.Auth.WebAuthn.Enabled = getEnvBool("WG_PORTAL_AUTH_WEBAUTHN_ENABLED", true)
	cfg.Auth.MinPasswordLength = getEnvInt("WG_PORTAL_AUTH_MIN_PASSWORD_LENGTH", 16)
	cfg.Auth.HideLoginForm = getEnvBool("WG_PORTAL_AUTH_HIDE_LOGIN_FORM", false)

	return cfg
}

// GetConfig returns the configuration from the config file.
// Environment variable substitution is supported.
func GetConfig() (*Config, error) {
	cfg := defaultConfig()

	// override config values from YAML file

	cfgFileName := "config/config.yaml"
	cfgFileNameFallback := "config/config.yml"
	if envCfgFileName := os.Getenv("WG_PORTAL_CONFIG"); envCfgFileName != "" {
		cfgFileName = envCfgFileName
		cfgFileNameFallback = envCfgFileName
	}

	// check if the config file exists, otherwise use the fallback file name
	if _, err := os.Stat(cfgFileName); os.IsNotExist(err) {
		cfgFileName = cfgFileNameFallback
	}

	if err := loadConfigFile(cfg, cfgFileName); err != nil {
		return nil, fmt.Errorf("failed to load config from yaml: %w", err)
	}

	if err := cfg.Sanitize(); err != nil {
		return nil, err
	}
	cfg.Web.Sanitize()
	err := cfg.Backend.Validate()
	if err != nil {
		return nil, err
	}
	for i := range cfg.Auth.Ldap {
		if err := cfg.Auth.Ldap[i].Sanitize(); err != nil {
			return nil, fmt.Errorf("sanitizing of ldap config for %s failed: %w", cfg.Auth.Ldap[i].ProviderName, err)
		}
	}

	return cfg, nil
}

// loadConfigFile loads the configuration from a YAML file into the given cfg struct.
func loadConfigFile(cfg any, filename string) error {
	data, err := envsubst.ReadFile(filename)
	if err != nil {
		if os.IsNotExist(err) {
			slog.Warn("Config file not found, using default values", "filename", filename)
			return nil
		}
		return fmt.Errorf("envsubst error: %v", err)
	}

	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	if err := dec.Decode(cfg); err != nil {
		return fmt.Errorf("yaml error: %v", err)
	}
	// Ensure there are no trailing YAML documents.
	var extra any
	if err := dec.Decode(&extra); err != io.EOF {
		if err == nil {
			return fmt.Errorf("yaml error: unexpected extra document")
		}
		return fmt.Errorf("yaml error: %v", err)
	}

	return nil
}

func getEnvStr(name, fallback string) string {
	if v, ok := os.LookupEnv(name); ok {
		return v
	}

	return fallback
}

func getEnvStrSlice(name string, fallback []string) []string {
	v, ok := os.LookupEnv(name)
	if !ok {
		return fallback
	}

	strParts := strings.Split(v, ",")
	stringSlice := make([]string, 0, len(strParts))

	for _, s := range strParts {
		trimmed := strings.TrimSpace(s)
		if trimmed != "" {
			stringSlice = append(stringSlice, trimmed)
		}
	}

	return stringSlice
}

func getEnvBool(name string, fallback bool) bool {
	v, ok := os.LookupEnv(name)
	if !ok {
		return fallback
	}

	b, err := strconv.ParseBool(v)
	if err != nil {
		slog.Warn("invalid bool env, using fallback", "env", name, "value", v, "fallback", fallback)
		return fallback
	}

	return b
}

func getEnvInt(name string, fallback int) int {
	v, ok := os.LookupEnv(name)
	if !ok {
		return fallback
	}

	i, err := strconv.Atoi(v)
	if err != nil {
		slog.Warn("invalid int env, using fallback", "env", name, "value", v, "fallback", fallback)
		return fallback
	}

	return i
}

func getEnvDuration(name string, fallback time.Duration) time.Duration {
	v, ok := os.LookupEnv(name)
	if !ok {
		return fallback
	}

	d, err := time.ParseDuration(v)
	if err != nil {
		slog.Warn("invalid duration env, using fallback", "env", name, "value", v, "fallback", fallback)
		return fallback
	}

	return d
}

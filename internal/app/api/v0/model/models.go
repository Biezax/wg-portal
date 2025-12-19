package model

type Error struct {
	Code    int    `json:"Code"`
	Message string `json:"Message"`
}

type Settings struct {
	MailLinkOnly              bool                   `json:"MailLinkOnly"`
	PersistentConfigSupported bool                   `json:"PersistentConfigSupported"`
	ApiAdminOnly              bool                   `json:"ApiAdminOnly"`
	WebAuthnEnabled           bool                   `json:"WebAuthnEnabled"`
	MinPasswordLength         int                    `json:"MinPasswordLength"`
	MaxPeersPerUser           int                    `json:"MaxPeersPerUser"`
	AvailableBackends         []SettingsBackendNames `json:"AvailableBackends"`
	LoginFormVisible          bool                   `json:"LoginFormVisible"`
}

type SettingsBackendNames struct {
	Id   string `json:"Id"`
	Name string `json:"Name"`
}

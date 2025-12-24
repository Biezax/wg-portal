package configfile

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"strings"

	"github.com/yeqown/go-qrcode/v2"
	"github.com/yeqown/go-qrcode/writer/compressed"

	"github.com/biezax/wg-portal/internal/app"
	"github.com/biezax/wg-portal/internal/config"
	"github.com/biezax/wg-portal/internal/domain"
)

// region dependencies

type UserDatabaseRepo interface {
	// GetUser returns the user with the given identifier from the SQL database.
	GetUser(ctx context.Context, id domain.UserIdentifier) (*domain.User, error)
}

type WireguardDatabaseRepo interface {
	// GetInterfaceAndPeers returns the interface and all peers associated with it.
	GetInterfaceAndPeers(ctx context.Context, id domain.InterfaceIdentifier) (*domain.Interface, []domain.Peer, error)
	// GetPeer returns the peer with the given identifier.
	GetPeer(ctx context.Context, id domain.PeerIdentifier) (*domain.Peer, error)
	// GetInterface returns the interface with the given identifier.
	GetInterface(ctx context.Context, id domain.InterfaceIdentifier) (*domain.Interface, error)
}

type FileSystemRepo interface {
	// WriteFile writes the contents to the file at the given path.
	WriteFile(path string, contents io.Reader) error

	// DeleteFile deletes the file at the given path.
	DeleteFile(path string) error
}

type TemplateRenderer interface {
	// GetInterfaceConfig returns the configuration file for the given interface.
	GetInterfaceConfig(iface *domain.Interface, peers []domain.Peer) (io.Reader, error)
	// GetPeerConfig returns the configuration file for the given peer.
	GetPeerConfig(peer *domain.Peer, style string) (io.Reader, error)
}

type EventBus interface {
	// Subscribe subscribes to the given topic.
	Subscribe(topic string, fn any) error
}

// endregion dependencies

// Manager is responsible for managing the configuration files of the WireGuard interfaces and peers.
type Manager struct {
	cfg *config.Config
	bus EventBus

	tplHandler TemplateRenderer
	fsRepo     FileSystemRepo
	users      UserDatabaseRepo
	wg         WireguardDatabaseRepo
}

// NewConfigFileManager creates a new Manager instance.
func NewConfigFileManager(
	cfg *config.Config,
	bus EventBus,
	users UserDatabaseRepo,
	wg WireguardDatabaseRepo,
	fsRepo FileSystemRepo,
) (*Manager, error) {
	tplHandler, err := newTemplateHandler()
	if err != nil {
		return nil, fmt.Errorf("failed to initialize template handler: %w", err)
	}

	m := &Manager{
		cfg:        cfg,
		bus:        bus,
		tplHandler: tplHandler,

		fsRepo: fsRepo,
		users:  users,
		wg:     wg,
	}

	if m.cfg.Advanced.ConfigStoragePath != "" {
		if err := m.createStorageDirectory(); err != nil {
			return nil, err
		}

		m.connectToMessageBus()
	}

	return m, nil
}

func (m Manager) createStorageDirectory() error {
	err := os.MkdirAll(m.cfg.Advanced.ConfigStoragePath, os.ModePerm)
	if err != nil {
		return fmt.Errorf("failed to create configuration storage path %s: %w",
			m.cfg.Advanced.ConfigStoragePath, err)
	}

	return nil
}

func (m Manager) connectToMessageBus() {
	_ = m.bus.Subscribe(app.TopicInterfaceCreated, m.handleInterfaceSavedEvent)
	_ = m.bus.Subscribe(app.TopicInterfaceUpdated, m.handleInterfaceSavedEvent)
	_ = m.bus.Subscribe(app.TopicInterfaceDeleted, m.handleInterfaceDeleteEvent)
	_ = m.bus.Subscribe(app.TopicPeerInterfaceUpdated, m.handlePeerInterfaceUpdatedEvent)
}

func (m Manager) handleInterfaceSavedEvent(iface domain.Interface) {
	if !iface.SaveConfig {
		return
	}

	slog.Debug("handling interface save event", "interface", iface.Identifier)

	err := m.PersistInterfaceConfig(context.Background(), iface.Identifier)
	if err != nil {
		slog.Error("failed to automatically persist interface config",
			"interface", iface.Identifier, "error", err)
	}
}

func (m Manager) handleInterfaceDeleteEvent(iface domain.Interface) {
	if !iface.SaveConfig {
		return
	}

	slog.Debug("handling interface delete event", "interface", iface.Identifier)

	err := m.UnpersistInterfaceConfig(context.Background(), iface.GetConfigFileName())
	if err != nil {
		slog.Error("failed to remove persisted interface config",
			"interface", iface.Identifier, "error", err)
	}
}

func (m Manager) handlePeerInterfaceUpdatedEvent(id domain.InterfaceIdentifier) {
	peerInterface, err := m.wg.GetInterface(context.Background(), id)
	if err != nil {
		slog.Error("failed to load interface",
			"interface", id,
			"error", err)
		return
	}

	if !peerInterface.SaveConfig {
		return
	}

	slog.Debug("handling peer interface updated event", "interface", id)

	err = m.PersistInterfaceConfig(context.Background(), peerInterface.Identifier)
	if err != nil {
		slog.Error("failed to automatically persist interface config",
			"interface", peerInterface.Identifier,
			"error", err)
	}
}

// GetInterfaceConfig returns the configuration file for the given interface.
// The file is structured in wg-quick format.
func (m Manager) GetInterfaceConfig(ctx context.Context, id domain.InterfaceIdentifier) (io.Reader, error) {
	if err := domain.ValidateAdminAccessRights(ctx); err != nil {
		return nil, err
	}

	iface, peers, err := m.wg.GetInterfaceAndPeers(ctx, id)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch interface %s: %w", id, err)
	}

	return m.tplHandler.GetInterfaceConfig(iface, peers)
}

// GetPeerConfig returns the configuration file for the given peer.
// The file is structured in wg-quick format.
func (m Manager) GetPeerConfig(ctx context.Context, id domain.PeerIdentifier, style string) (io.Reader, error) {
	peer, err := m.wg.GetPeer(ctx, id)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch peer %s: %w", id, err)
	}

	if err := domain.ValidateUserAccessRights(ctx, peer.UserIdentifier); err != nil {
		return nil, err
	}

	cfg, err := m.tplHandler.GetPeerConfig(peer, style)
	if err != nil {
		return nil, err
	}

	// Add a stable, human-friendly name header for importers/UI.
	displayName := m.getPeerConfigDisplayName(ctx, peer)
	if displayName != "" {
		header := fmt.Sprintf("# Name = %s\n", displayName)
		return io.MultiReader(strings.NewReader(header), cfg), nil
	}

	return cfg, nil
}

func (m Manager) getPeerConfigDisplayName(ctx context.Context, peer *domain.Peer) string {
	if peer == nil {
		return ""
	}

	ifaceName := strings.TrimSpace(string(peer.InterfaceIdentifier))
	if iface, err := m.wg.GetInterface(ctx, peer.InterfaceIdentifier); err == nil && iface != nil {
		if n := strings.TrimSpace(iface.DisplayName); n != "" {
			ifaceName = n
		} else if id := strings.TrimSpace(string(iface.Identifier)); id != "" {
			ifaceName = id
		}
	}

	peerName := strings.TrimSpace(peer.DisplayName)
	if peerName == "" {
		peerName = strings.TrimSpace(string(peer.Identifier))
	}

	if ifaceName == "" {
		return peerName
	}
	if peerName == "" {
		return ifaceName
	}
	return ifaceName + " - " + peerName
}

func (m Manager) getPeerQrConfigText(cfgData io.Reader, keepNameHeader bool, displayName string) (string, error) {
	sb := strings.Builder{}
	if keepNameHeader && displayName != "" {
		sb.WriteString("# Name = ")
		sb.WriteString(displayName)
		sb.WriteString("\n")
	}

	scanner := bufio.NewScanner(cfgData)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if strings.HasPrefix(line, "#") {
			continue
		}
		sb.WriteString(line)
		sb.WriteString("\n")
	}
	if err := scanner.Err(); err != nil {
		return "", err
	}
	return sb.String(), nil
}

// GetPeerConfigQrCode returns a QR code image containing the configuration for the given peer.
func (m Manager) GetPeerConfigQrCode(ctx context.Context, id domain.PeerIdentifier, style string) (io.Reader, error) {
	peer, err := m.wg.GetPeer(ctx, id)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch peer %s: %w", id, err)
	}

	if err := domain.ValidateUserAccessRights(ctx, peer.UserIdentifier); err != nil {
		return nil, err
	}

	var qrPayload string
	switch {
	case peer.Interface.HasAdvancedSecurity():
		displayName := m.getPeerConfigDisplayName(ctx, peer)

		// For AmneziaWG QR we always use WG-Quick config to ensure Address/DNS/MTU are present.
		cfgData, err := m.tplHandler.GetPeerConfig(peer, domain.ConfigStyleWgQuick)
		if err != nil {
			return nil, fmt.Errorf("failed to get peer config for %s: %w", id, err)
		}

		cfgText, err := m.getPeerQrConfigText(cfgData, true, displayName)
		if err != nil {
			return nil, fmt.Errorf("failed to read peer config for %s: %w", id, err)
		}

		vpnLink, err := buildAmneziaAwgVpnLink(peer, displayName, cfgText)
		if err != nil {
			return nil, fmt.Errorf("failed to build amnezia vpn link for %s: %w", id, err)
		}

		qrPayload = vpnLink
	default:
		cfgData, err := m.tplHandler.GetPeerConfig(peer, style)
		if err != nil {
			return nil, fmt.Errorf("failed to get peer config for %s: %w", id, err)
		}

		cfgText, err := m.getPeerQrConfigText(cfgData, false, "")
		if err != nil {
			return nil, fmt.Errorf("failed to read peer config for %s: %w", id, err)
		}

		qrPayload = cfgText
	}

	code, err := qrcode.NewWith(qrPayload,
		qrcode.WithErrorCorrectionLevel(qrcode.ErrorCorrectionLow), qrcode.WithEncodingMode(qrcode.EncModeByte))
	if err != nil {
		return nil, fmt.Errorf("failed to initialize qr code for %s: %w", id, err)
	}

	buf := bytes.NewBuffer(nil)
	wr := nopCloser{Writer: buf}
	option := compressed.Option{
		Padding:   8, // padding pixels around the qr code.
		BlockSize: 4, // block pixels which represents a bit data.
	}
	qrWriter := compressed.NewWithWriter(wr, &option)
	err = code.Save(qrWriter)
	if err != nil {
		return nil, fmt.Errorf("failed to write code for %s: %w", id, err)
	}

	return buf, nil
}

// PersistInterfaceConfig writes the configuration file for the given interface to the file system.
func (m Manager) PersistInterfaceConfig(ctx context.Context, id domain.InterfaceIdentifier) error {
	iface, peers, err := m.wg.GetInterfaceAndPeers(ctx, id)
	if err != nil {
		return fmt.Errorf("failed to fetch interface %s: %w", id, err)
	}

	cfg, err := m.tplHandler.GetInterfaceConfig(iface, peers)
	if err != nil {
		return fmt.Errorf("failed to get interface config: %w", err)
	}

	if err := m.fsRepo.WriteFile(iface.GetConfigFileName(), cfg); err != nil {
		return fmt.Errorf("failed to write interface config: %w", err)
	}

	return nil
}

// UnpersistInterfaceConfig removes the configuration file for the given interface from the file system.
func (m Manager) UnpersistInterfaceConfig(_ context.Context, filename string) error {
	if err := m.fsRepo.DeleteFile(filename); err != nil {
		return fmt.Errorf("failed to remove interface config: %w", err)
	}

	return nil
}

type nopCloser struct {
	io.Writer
}

// Close is a no-op for the nopCloser.
func (nopCloser) Close() error { return nil }

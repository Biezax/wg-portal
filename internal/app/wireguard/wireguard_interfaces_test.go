package wireguard

import (
	"context"
	"testing"

	"github.com/biezax/wg-portal/internal/config"
	"github.com/biezax/wg-portal/internal/domain"
)

func TestBootstrapInterfacesFromConfig_EmptyConfig(t *testing.T) {
	cfg := &config.Config{}
	cfg.Core.WireGuardHostManagement = false

	m := Manager{
		cfg: cfg,
		db:  &mockDB{},
		bus: &mockBus{},
	}

	ctx := domain.SetUserInfo(context.Background(), &domain.ContextUserInfo{IsAdmin: true})

	bootstrapped, err := m.BootstrapInterfacesFromConfig(ctx)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if bootstrapped {
		t.Fatal("expected bootstrapped=false when no provisioning interfaces configured")
	}
}

func TestBootstrapInterfacesFromConfig_SkipsWhenInterfacesExist(t *testing.T) {
	cfg := &config.Config{}
	cfg.Core.WireGuardHostManagement = false
	cfg.Provisioning.Interfaces = []config.ProvisioningInterface{
		{Identifier: "wg0"},
	}

	db := &mockDB{}
	db.existingInterfaces = []domain.Interface{{Identifier: "existing"}}

	m := Manager{
		cfg: cfg,
		db:  db,
		bus: &mockBus{},
	}

	ctx := domain.SetUserInfo(context.Background(), &domain.ContextUserInfo{IsAdmin: true})

	bootstrapped, err := m.BootstrapInterfacesFromConfig(ctx)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if bootstrapped {
		t.Fatal("expected bootstrapped=false when interfaces already exist")
	}
}

func TestBootstrapInterfacesFromConfig_DuplicateIdentifier(t *testing.T) {
	cfg := &config.Config{}
	cfg.Core.WireGuardHostManagement = false
	cfg.Provisioning.Interfaces = []config.ProvisioningInterface{
		{Identifier: "wg0"},
		{Identifier: "wg0"},
	}

	m := Manager{
		cfg: cfg,
		db:  &mockDB{},
		bus: &mockBus{},
	}

	ctx := domain.SetUserInfo(context.Background(), &domain.ContextUserInfo{IsAdmin: true})

	_, err := m.BootstrapInterfacesFromConfig(ctx)
	if err == nil {
		t.Fatal("expected error for duplicate identifier")
	}
}

func TestBootstrapInterfacesFromConfig_EmptyIdentifier(t *testing.T) {
	cfg := &config.Config{}
	cfg.Core.WireGuardHostManagement = false
	cfg.Provisioning.Interfaces = []config.ProvisioningInterface{
		{Identifier: ""},
	}

	m := Manager{
		cfg: cfg,
		db:  &mockDB{},
		bus: &mockBus{},
	}

	ctx := domain.SetUserInfo(context.Background(), &domain.ContextUserInfo{IsAdmin: true})

	_, err := m.BootstrapInterfacesFromConfig(ctx)
	if err == nil {
		t.Fatal("expected error for empty identifier")
	}
}

func TestBootstrapInterfacesFromConfig_InvalidMode(t *testing.T) {
	cfg := &config.Config{}
	cfg.Core.WireGuardHostManagement = false
	cfg.Provisioning.Interfaces = []config.ProvisioningInterface{
		{Identifier: "wg0", Mode: "invalid"},
	}

	m := Manager{
		cfg: cfg,
		db:  &mockDB{},
		bus: &mockBus{},
	}

	ctx := domain.SetUserInfo(context.Background(), &domain.ContextUserInfo{IsAdmin: true})

	_, err := m.BootstrapInterfacesFromConfig(ctx)
	if err == nil {
		t.Fatal("expected error for invalid mode")
	}
}

func TestBootstrapInterfacesFromConfig_Success(t *testing.T) {
	cfg := &config.Config{}
	cfg.Core.WireGuardHostManagement = false
	cfg.Advanced.StartListenPort = 51820
	cfg.Advanced.StartCidrV4 = "10.0.0.0/24"
	cfg.Provisioning.Interfaces = []config.ProvisioningInterface{
		{
			Identifier:  "wg0",
			DisplayName: "Test Interface",
			Mode:        "server",
		},
	}

	db := &mockDB{}
	m := Manager{
		cfg: cfg,
		db:  db,
		bus: &mockBus{},
	}

	ctx := domain.SetUserInfo(context.Background(), &domain.ContextUserInfo{IsAdmin: true})

	bootstrapped, err := m.BootstrapInterfacesFromConfig(ctx)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !bootstrapped {
		t.Fatal("expected bootstrapped=true")
	}
	if db.iface == nil {
		t.Fatal("expected interface to be saved")
	}
	if db.iface.DisplayName != "Test Interface" {
		t.Fatalf("expected DisplayName='Test Interface', got %q", db.iface.DisplayName)
	}
	if db.iface.Mtu != DefaultMTU {
		t.Fatalf("expected Mtu=%d, got %d", DefaultMTU, db.iface.Mtu)
	}
}

func TestBootstrapInterfacesFromConfig_RequiresAdmin(t *testing.T) {
	cfg := &config.Config{}
	cfg.Provisioning.Interfaces = []config.ProvisioningInterface{
		{Identifier: "wg0"},
	}

	m := Manager{
		cfg: cfg,
		db:  &mockDB{},
		bus: &mockBus{},
	}

	ctx := domain.SetUserInfo(context.Background(), &domain.ContextUserInfo{IsAdmin: false})

	_, err := m.BootstrapInterfacesFromConfig(ctx)
	if err == nil {
		t.Fatal("expected error for non-admin user")
	}
}

func TestBootstrapInterfacesFromConfig_WithAdvancedSecurity_SetsAmneziaClient(t *testing.T) {
	cfg := &config.Config{}
	cfg.Core.WireGuardHostManagement = false
	cfg.Advanced.StartListenPort = 51820
	cfg.Advanced.StartCidrV4 = "10.0.0.0/24"
	cfg.Provisioning.Interfaces = []config.ProvisioningInterface{
		{
			Identifier:  "awg0",
			DisplayName: "AmneziaWG Interface",
			Mode:        "server",
			AdvancedSecurity: &config.ProvisioningInterfaceAdvancedSecurity{
				JunkPacketCount:   4,
				JunkPacketMinSize: 50,
				JunkPacketMaxSize: 1000,
			},
		},
	}

	db := &mockDB{}
	m := Manager{
		cfg: cfg,
		db:  db,
		bus: &mockBus{},
	}

	ctx := domain.SetUserInfo(context.Background(), &domain.ContextUserInfo{IsAdmin: true})

	bootstrapped, err := m.BootstrapInterfacesFromConfig(ctx)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !bootstrapped {
		t.Fatal("expected bootstrapped=true")
	}
	if db.iface == nil {
		t.Fatal("expected interface to be saved")
	}
	if db.iface.ClientType != 1 { // wgtypes.AmneziaClient
		t.Fatalf("expected ClientType=AmneziaClient(1), got %d", db.iface.ClientType)
	}
	if db.iface.AdvancedSecurity == nil {
		t.Fatal("expected AdvancedSecurity to be set")
	}
	if db.iface.AdvancedSecurity.JunkPacketCount != 4 {
		t.Fatalf("expected Jc=4, got %d", db.iface.AdvancedSecurity.JunkPacketCount)
	}
}

func TestBootstrapInterfacesFromConfig_WithoutAdvancedSecurity_SetsNativeClient(t *testing.T) {
	cfg := &config.Config{}
	cfg.Core.WireGuardHostManagement = false
	cfg.Advanced.StartListenPort = 51820
	cfg.Advanced.StartCidrV4 = "10.0.0.0/24"
	cfg.Provisioning.Interfaces = []config.ProvisioningInterface{
		{
			Identifier:  "wg0",
			DisplayName: "WireGuard Interface",
			Mode:        "server",
		},
	}

	db := &mockDB{}
	m := Manager{
		cfg: cfg,
		db:  db,
		bus: &mockBus{},
	}

	ctx := domain.SetUserInfo(context.Background(), &domain.ContextUserInfo{IsAdmin: true})

	bootstrapped, err := m.BootstrapInterfacesFromConfig(ctx)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !bootstrapped {
		t.Fatal("expected bootstrapped=true")
	}
	if db.iface == nil {
		t.Fatal("expected interface to be saved")
	}
	if db.iface.ClientType != 0 { // wgtypes.NativeClient
		t.Fatalf("expected ClientType=NativeClient(0), got %d", db.iface.ClientType)
	}
	if db.iface.AdvancedSecurity != nil {
		t.Fatal("expected AdvancedSecurity to be nil for WireGuard interface")
	}
}

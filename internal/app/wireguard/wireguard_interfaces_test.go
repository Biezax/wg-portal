package wireguard

import (
	"context"
	"testing"

	"github.com/biezax/wg-portal/internal/config"
	"github.com/biezax/wg-portal/internal/domain"
)

func TestBootstrapInterfacesFromConfig_EmptyConfig(t *testing.T) {
	cfg := &config.Config{}
	cfg.Core.WireGuardMode = config.WireGuardModeDisabled

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
	cfg.Core.WireGuardMode = config.WireGuardModeDisabled
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
	cfg.Core.WireGuardMode = config.WireGuardModeDisabled
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
	cfg.Core.WireGuardMode = config.WireGuardModeDisabled
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
	cfg.Core.WireGuardMode = config.WireGuardModeDisabled
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
	cfg.Core.WireGuardMode = config.WireGuardModeDisabled
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

package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeTempConfig(t *testing.T, contents string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yml")
	if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
		t.Fatalf("write temp config: %v", err)
	}
	return path
}

func TestLoadConfigFile_UnknownFieldFails(t *testing.T) {
	cfg := defaultConfig()

	path := writeTempConfig(t, `
core:
  wireguard_mode: amneziawg
provisioning:
  interfaces:
    - identifier: wg0
      unknown_key: 1
`)

	err := loadConfigFile(cfg, path)
	if err == nil {
		t.Fatalf("expected error, got nil")
	}
	if !strings.Contains(err.Error(), "unknown_key") {
		t.Fatalf("expected error mentioning unknown_key, got: %v", err)
	}
}

func TestSanitizeProvisioningInterfaces_InvalidCIDRFails(t *testing.T) {
	cfg := defaultConfig()

	path := writeTempConfig(t, `
core:
  wireguard_mode: amneziawg
provisioning:
  interfaces:
    - identifier: wg0
      addresses:
        - 10.0.0.1/33
`)

	if err := loadConfigFile(cfg, path); err != nil {
		t.Fatalf("loadConfigFile: %v", err)
	}
	if err := cfg.Sanitize(); err == nil {
		t.Fatalf("expected sanitize error, got nil")
	}
}

func TestSanitizeProvisioningInterfaces_DuplicateIdentifierFails(t *testing.T) {
	cfg := defaultConfig()

	path := writeTempConfig(t, `
core:
  wireguard_mode: amneziawg
provisioning:
  interfaces:
    - identifier: wg0
    - identifier: wg0
`)

	if err := loadConfigFile(cfg, path); err != nil {
		t.Fatalf("loadConfigFile: %v", err)
	}
	err := cfg.Sanitize()
	if err == nil {
		t.Fatalf("expected sanitize error, got nil")
	}
	if !strings.Contains(err.Error(), "not unique") {
		t.Fatalf("expected not unique error, got: %v", err)
	}
}

func TestSanitizeProvisioningInterfaces_AdvancedSecurityRequiresAmneziaWG(t *testing.T) {
	cfg := defaultConfig()

	path := writeTempConfig(t, `
core:
  wireguard_mode: wireguard
provisioning:
  interfaces:
    - identifier: wg0
      advanced_security:
        jc: 1
        jmin: 50
        jmax: 100
`)

	if err := loadConfigFile(cfg, path); err != nil {
		t.Fatalf("loadConfigFile: %v", err)
	}
	err := cfg.Sanitize()
	if err == nil {
		t.Fatalf("expected sanitize error, got nil")
	}
	if !strings.Contains(err.Error(), "advanced_security is only supported") {
		t.Fatalf("expected advanced_security mode error, got: %v", err)
	}
}

func TestSanitizeProvisioningInterfaces_AdvancedSecurityJminJmaxOrderFails(t *testing.T) {
	cfg := defaultConfig()

	path := writeTempConfig(t, `
core:
  wireguard_mode: amneziawg
provisioning:
  interfaces:
    - identifier: wg0
      advanced_security:
        jc: 1
        jmin: 100
        jmax: 50
`)

	if err := loadConfigFile(cfg, path); err != nil {
		t.Fatalf("loadConfigFile: %v", err)
	}
	err := cfg.Sanitize()
	if err == nil {
		t.Fatalf("expected sanitize error, got nil")
	}
	if !strings.Contains(err.Error(), "jmin must be <=") {
		t.Fatalf("expected jmin/jmax order error, got: %v", err)
	}
}

func TestSanitizeProvisioningInterfaces_AdvancedSecurityH1MustBeUint32(t *testing.T) {
	cfg := defaultConfig()

	path := writeTempConfig(t, `
core:
  wireguard_mode: amneziawg
provisioning:
  interfaces:
    - identifier: wg0
      advanced_security:
        h1: not-a-number
`)

	if err := loadConfigFile(cfg, path); err != nil {
		t.Fatalf("loadConfigFile: %v", err)
	}
	err := cfg.Sanitize()
	if err == nil {
		t.Fatalf("expected sanitize error, got nil")
	}
	if !strings.Contains(err.Error(), "must be a uint32") {
		t.Fatalf("expected uint32 parse error, got: %v", err)
	}
}

func TestLoadConfigFile_TrailingDocumentFails(t *testing.T) {
	cfg := defaultConfig()

	path := writeTempConfig(t, `
core:
  wireguard_mode: wireguard
---
extra: document
`)

	err := loadConfigFile(cfg, path)
	if err == nil {
		t.Fatalf("expected error for trailing document, got nil")
	}
	if !strings.Contains(err.Error(), "extra document") {
		t.Fatalf("expected extra document error, got: %v", err)
	}
}

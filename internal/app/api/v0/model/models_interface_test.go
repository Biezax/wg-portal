package model

import (
	"testing"

	"github.com/Biezax/wgctrl/wgtypes"

	"github.com/biezax/wg-portal/internal/domain"
)

func TestNewInterface_AmneziaClient_SetsUsesAdvancedSecurity(t *testing.T) {
	src := &domain.Interface{
		Identifier: "awg0",
		ClientType: wgtypes.AmneziaClient,
		AdvancedSecurity: &domain.AdvancedSecurity{
			JunkPacketCount: 4,
		},
	}

	iface := NewInterface(src, nil)

	if !iface.UsesAdvancedSecurity {
		t.Fatal("expected UsesAdvancedSecurity=true for AmneziaClient")
	}
	if iface.AdvancedSecurity == nil {
		t.Fatal("expected AdvancedSecurity to be copied")
	}
	if iface.AdvancedSecurity.JunkPacketCount != 4 {
		t.Fatalf("expected Jc=4, got %d", iface.AdvancedSecurity.JunkPacketCount)
	}
}

func TestNewInterface_NativeClient_ClearsAdvancedSecurity(t *testing.T) {
	src := &domain.Interface{
		Identifier: "wg0",
		ClientType: wgtypes.NativeClient,
	}

	iface := NewInterface(src, nil)

	if iface.UsesAdvancedSecurity {
		t.Fatal("expected UsesAdvancedSecurity=false for NativeClient")
	}
	if iface.AdvancedSecurity != nil {
		t.Fatal("expected AdvancedSecurity=nil for NativeClient")
	}
}

func TestNewDomainInterface_UsesAdvancedSecurity_SetsAmneziaClient(t *testing.T) {
	src := &Interface{
		Identifier:           "awg0",
		UsesAdvancedSecurity: true,
		AdvancedSecurity: &domain.AdvancedSecurity{
			JunkPacketCount: 8,
		},
	}

	iface := NewDomainInterface(src)

	if iface.ClientType != wgtypes.AmneziaClient {
		t.Fatalf("expected ClientType=AmneziaClient, got %d", iface.ClientType)
	}
	if iface.AdvancedSecurity == nil {
		t.Fatal("expected AdvancedSecurity to be set")
	}
}

func TestNewDomainInterface_NotUsesAdvancedSecurity_SetsNativeClient(t *testing.T) {
	src := &Interface{
		Identifier:           "wg0",
		UsesAdvancedSecurity: false,
	}

	iface := NewDomainInterface(src)

	if iface.ClientType != wgtypes.NativeClient {
		t.Fatalf("expected ClientType=NativeClient, got %d", iface.ClientType)
	}
}

func TestNewDomainInterface_EmptyAdvancedSecurity_NotCopied(t *testing.T) {
	src := &Interface{
		Identifier:           "awg0",
		UsesAdvancedSecurity: true,
		AdvancedSecurity:     &domain.AdvancedSecurity{},
	}

	iface := NewDomainInterface(src)

	if iface.ClientType != wgtypes.AmneziaClient {
		t.Fatalf("expected ClientType=AmneziaClient, got %d", iface.ClientType)
	}
	if iface.AdvancedSecurity != nil {
		t.Fatal("expected empty AdvancedSecurity to not be copied")
	}
}

func TestIsEmptyAdvancedSecurity(t *testing.T) {
	tests := []struct {
		name     string
		input    *domain.AdvancedSecurity
		expected bool
	}{
		{"nil", nil, true},
		{"zero value", &domain.AdvancedSecurity{}, true},
		{"with jc", &domain.AdvancedSecurity{JunkPacketCount: 1}, false},
		{"with jmin", &domain.AdvancedSecurity{JunkPacketMinSize: 1}, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isEmptyAdvancedSecurity(tt.input); got != tt.expected {
				t.Errorf("isEmptyAdvancedSecurity() = %v, want %v", got, tt.expected)
			}
		})
	}
}

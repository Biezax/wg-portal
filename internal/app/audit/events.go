package audit

import "github.com/biezax/wg-portal/internal/domain"

type AuthEvent struct {
	Username string
	Error    string
}

type InterfaceEvent struct {
	Interface domain.Interface
	Action    string
}

type PeerEvent struct {
	Peer   domain.Peer
	Action string
}

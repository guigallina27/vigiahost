//go:build !linux

package executor

import (
	"errors"
	"net"
)

// PeerCredential só existe no Linux; em outros sistemas o executor recusa todas as conexões.
func PeerCredential(net.Conn) (Cred, error) {
	return Cred{}, errors.New("SO_PEERCRED disponível apenas no Linux")
}

//go:build linux

package executor

import (
	"errors"
	"net"
	"syscall"
)

// PeerCredential lê PID, UID e GID do processo cliente pelo kernel (SO_PEERCRED), sem confiar no que ele declara.
func PeerCredential(conn net.Conn) (Cred, error) {
	uc, ok := conn.(*net.UnixConn)
	if !ok {
		return Cred{}, errors.New("a conexão não é um socket Unix")
	}
	raw, err := uc.SyscallConn()
	if err != nil {
		return Cred{}, err
	}
	var ucred *syscall.Ucred
	var sockErr error
	if err := raw.Control(func(fd uintptr) {
		ucred, sockErr = syscall.GetsockoptUcred(int(fd), syscall.SOL_SOCKET, syscall.SO_PEERCRED)
	}); err != nil {
		return Cred{}, err
	}
	if sockErr != nil {
		return Cred{}, sockErr
	}
	return Cred{PID: ucred.Pid, UID: ucred.Uid, GID: ucred.Gid}, nil
}

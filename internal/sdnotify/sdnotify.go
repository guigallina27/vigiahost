// Package sdnotify avisa o systemd sobre o estado do serviço (Type=notify), sem dependências externas.
package sdnotify

import (
	"net"
	"os"
)

const (
	Ready    = "READY=1"
	Stopping = "STOPPING=1"
)

// Notify envia o estado ao systemd. Fora do systemd (NOTIFY_SOCKET vazio) não faz nada.
func Notify(state string) error {
	path := os.Getenv("NOTIFY_SOCKET")
	if path == "" {
		return nil
	}
	// Socket abstrato: o systemd usa "@" no lugar do byte nulo inicial.
	if path[0] == '@' {
		path = "\x00" + path[1:]
	}
	conn, err := net.DialUnix("unixgram", nil, &net.UnixAddr{Name: path, Net: "unixgram"})
	if err != nil {
		return err
	}
	defer func() { _ = conn.Close() }()
	_, err = conn.Write([]byte(state))
	return err
}

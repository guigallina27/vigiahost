//go:build linux

package executor

import (
	"context"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/guigallina27/vigiahost/internal/ipc"
	"github.com/guigallina27/vigiahost/internal/sysinfo"
)

// Exercita o caminho real: socket Unix, permissões do arquivo e SO_PEERCRED do kernel.
func TestSocketRealComPeerCred(t *testing.T) {
	sock := filepath.Join(t.TempDir(), "executor.sock")
	ln, err := ListenUnix(context.Background(), sock, os.Getegid())
	if err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(sock)
	if err != nil {
		t.Fatal(err)
	}
	if perm := info.Mode().Perm(); perm != 0o660 {
		t.Errorf("permissão do socket = %o, esperado 660", perm)
	}

	uid := uint32(os.Geteuid())
	srv := &Server{
		Logger:   slog.New(slog.NewTextHandler(io.Discard, nil)),
		Policy:   Policy{AllowedUIDs: map[uint32]bool{uid: true}},
		Local:    testHello,
		Handlers: DefaultHandlers(os.DirFS("/")),
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- srv.Serve(ctx, ln) }()

	c, err := ipc.Dial(ctx, sock, testHello)
	if err != nil {
		t.Fatalf("handshake pelo socket real: %v", err)
	}
	var caps sysinfo.Capabilities
	if err := c.Call(ctx, ipc.OpCapabilities, nil, &caps); err != nil {
		t.Fatalf("capabilities: %v", err)
	}
	c.Close()
	if caps.DistroID == "" {
		t.Errorf("distribuição não detectada: %+v", caps)
	}

	cancel()
	if err := <-done; err != nil {
		t.Fatalf("Serve terminou com erro: %v", err)
	}
}

func TestListenUnixRecusaArquivoComum(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nao-e-socket")
	if err := os.WriteFile(path, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := ListenUnix(context.Background(), path, -1); err == nil {
		t.Fatal("ListenUnix deveria recusar substituir um arquivo comum")
	}
}

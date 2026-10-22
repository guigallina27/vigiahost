package main

import (
	"context"
	"errors"
	"flag"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/guigallina27/vigiahost/internal/core"
	"github.com/guigallina27/vigiahost/internal/ipc"
	"github.com/guigallina27/vigiahost/internal/sdnotify"
	"github.com/guigallina27/vigiahost/internal/store"
	"github.com/guigallina27/vigiahost/internal/version"
	"github.com/guigallina27/vigiahost/internal/webui"
)

const (
	defaultListen         = "127.0.0.1:8743"
	defaultExecutorSocket = "/run/vigiahost-executor/executor.sock"
)

func localHello() ipc.Hello {
	return ipc.Hello{ProtocolMajor: version.ProtocolMajor, ProtocolMinor: version.ProtocolMinor, Version: version.Version}
}

// defaultDB usa o diretório criado pelo systemd (StateDirectory) quando disponível.
func defaultDB() string {
	dir := os.Getenv("STATE_DIRECTORY")
	if dir == "" {
		dir = "/var/lib/vigiahost"
	}
	return filepath.Join(dir, "vigiahost.db")
}

func runServe(args []string) int {
	fs := flag.NewFlagSet("serve", flag.ContinueOnError)
	listen := fs.String("listen", defaultListen, "endereço e porta da interface web")
	dbPath := fs.String("db", defaultDB(), "arquivo do banco SQLite")
	socket := fs.String("executor-socket", defaultExecutorSocket, "socket do executor")
	if err := fs.Parse(args); err != nil {
		return 2
	}

	logger := slog.New(slog.NewJSONHandler(os.Stderr, nil))
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	if host, _, err := net.SplitHostPort(*listen); err == nil {
		if ip := net.ParseIP(host); ip == nil || !ip.IsLoopback() {
			logger.Warn("interface web fora do endereço local; restrinja o acesso no firewall", "listen", *listen)
		}
	}

	db, err := store.Open(ctx, *dbPath)
	if err != nil {
		logger.Error("falha ao abrir o banco", "db", *dbPath, "erro", err)
		return 1
	}
	defer db.Close()
	mig, err := store.Migrate(ctx, db)
	if err != nil {
		logger.Error("falha ao migrar o banco", "erro", err)
		return 1
	}
	if mig.NewerSchema {
		logger.Warn("esquema do banco é de uma versão mais nova do produto; seguindo sem migrar", "versao_esquema", mig.From)
	} else if mig.From != mig.To {
		logger.Info("banco migrado", "de", mig.From, "para", mig.To)
	}

	srv := &core.Server{Logger: logger, Version: version.Version, Probe: core.ProbeExecutor(*socket, localHello()), UI: webui.Handler()}
	httpSrv := core.NewHTTPServer(*listen, srv.Handler(), logger)
	ln, err := (&net.ListenConfig{}).Listen(ctx, "tcp", *listen)
	if err != nil {
		logger.Error("falha ao abrir a porta da interface", "listen", *listen, "erro", err)
		return 1
	}

	errCh := make(chan error, 1)
	go func() { errCh <- httpSrv.Serve(ln) }()
	logger.Info("vigiahost iniciado", "versao", version.Version, "listen", ln.Addr().String())
	_ = sdnotify.Notify(sdnotify.Ready)

	select {
	case <-ctx.Done():
	case err := <-errCh:
		if !errors.Is(err, http.ErrServerClosed) {
			logger.Error("serviço web interrompido", "erro", err)
			return 1
		}
	}
	_ = sdnotify.Notify(sdnotify.Stopping)
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := httpSrv.Shutdown(shutdownCtx); err != nil {
		logger.Warn("encerramento forçado", "erro", err)
	}
	logger.Info("vigiahost encerrado")
	return 0
}

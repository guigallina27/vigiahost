package main

import (
	"context"
	"crypto/tls"
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
	_ "time/tzdata" // fusos IANA embarcados: os agendamentos não dependem do tzdata do sistema

	"github.com/guigallina27/vigiahost/internal/auth"
	"github.com/guigallina27/vigiahost/internal/backup"
	"github.com/guigallina27/vigiahost/internal/core"
	"github.com/guigallina27/vigiahost/internal/ipc"
	"github.com/guigallina27/vigiahost/internal/orchestrator"
	"github.com/guigallina27/vigiahost/internal/sdnotify"
	"github.com/guigallina27/vigiahost/internal/store"
	"github.com/guigallina27/vigiahost/internal/version"
	"github.com/guigallina27/vigiahost/internal/webui"
)

const (
	defaultListen         = "127.0.0.1:8743"
	defaultExecutorSocket = "/run/vigiahost-executor/executor.sock"
	firstAccessFileName   = "first-access-token"
)

func localHello() ipc.Hello {
	return ipc.Hello{ProtocolMajor: version.ProtocolMajor, ProtocolMinor: version.ProtocolMinor, Version: version.Version}
}

// stateDir usa o diretório criado pelo systemd (StateDirectory) quando disponível.
func stateDir() string {
	if dir := os.Getenv("STATE_DIRECTORY"); dir != "" {
		return dir
	}
	return "/var/lib/vigiahost"
}

func defaultDB() string { return filepath.Join(stateDir(), "vigiahost.db") }

func isLoopbackListen(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return false
	}
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func runServe(args []string) int {
	fs := flag.NewFlagSet("serve", flag.ContinueOnError)
	listen := fs.String("listen", defaultListen, "endereço e porta da interface web")
	dbPath := fs.String("db", defaultDB(), "arquivo do banco SQLite")
	socket := fs.String("executor-socket", defaultExecutorSocket, "socket do executor")
	tlsCert := fs.String("tls-cert", "", "certificado TLS (PEM); vazio gera um autoassinado quando a escuta não é local")
	tlsKey := fs.String("tls-key", "", "chave do certificado TLS (PEM)")
	trustProxy := fs.Bool("trust-proxy", false, "aceita X-Forwarded-Proto/For de um proxy reverso no endereço local")
	if err := fs.Parse(args); err != nil {
		return 2
	}

	logger := slog.New(slog.NewJSONHandler(os.Stderr, nil))
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	raw, err := store.Open(ctx, *dbPath)
	if err != nil {
		logger.Error("falha ao abrir o banco", "db", *dbPath, "erro", err)
		return 1
	}
	defer func() { _ = raw.Close() }()
	backupDir := filepath.Join(filepath.Dir(*dbPath), "backups")
	// Cópia antes de migrar (escopo, seção 15): permite voltar ao estado anterior se a migração der errado.
	if cur, err := store.SchemaVersion(ctx, raw); err == nil && cur > 0 && cur < store.LatestSchema() {
		info, err := backup.Create(ctx, raw, backupDir, "pre-migration", time.Now())
		if err != nil {
			logger.Error("cópia antes da migração falhou; a migração não foi feita", "erro", err)
			return 1
		}
		logger.Info("cópia do banco antes da migração", "arquivo", info.Name)
	}
	mig, err := store.Migrate(ctx, raw)
	if err != nil {
		logger.Error("falha ao migrar o banco", "erro", err)
		return 1
	}
	if mig.NewerSchema {
		logger.Warn("esquema do banco é de uma versão mais nova do produto; seguindo sem migrar", "versao_esquema", mig.From)
	} else if mig.From != mig.To {
		logger.Info("banco migrado", "de", mig.From, "para", mig.To)
	}
	db := store.New(raw)

	exec := &orchestrator.ExecClient{Socket: *socket, Local: localHello()}
	defer exec.Close()
	hub := orchestrator.NewHub()
	authSvc := &auth.Service{DB: db, Logger: logger, FailLog: os.Stderr}
	orch := &orchestrator.Service{DB: db, Exec: exec, Hub: hub, Logger: logger}

	firstAccess := filepath.Join(filepath.Dir(*dbPath), firstAccessFileName)
	if err := ensureFirstAccess(ctx, authSvc, firstAccess, logger); err != nil {
		logger.Error("falha ao preparar o primeiro acesso", "erro", err)
	}

	var tlsConf *tls.Config
	validCert := false
	switch {
	case *tlsCert != "" || *tlsKey != "":
		cert, err := tls.LoadX509KeyPair(*tlsCert, *tlsKey)
		if err != nil {
			logger.Error("certificado TLS inválido", "erro", err)
			return 1
		}
		tlsConf, validCert = &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}, true
	case !isLoopbackListen(*listen):
		cert, fp, err := selfSignedCert(filepath.Join(filepath.Dir(*dbPath), "tls"))
		if err != nil {
			logger.Error("falha ao gerar o certificado autoassinado", "erro", err)
			return 1
		}
		tlsConf = &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}
		// O setup apply mostra a impressão digital ao administrador.
		_ = os.WriteFile(filepath.Join(filepath.Dir(*dbPath), "tls", "fingerprint"), []byte(fp+"\n"), 0o600)
		logger.Warn("interface web fora do endereço local com certificado autoassinado; confira a impressão digital "+
			"no navegador e restrinja o acesso no firewall", "listen", *listen, "sha256", fp)
	}

	srv := &core.Server{Logger: logger, Version: version.Version, Probe: core.ProbeExecutor(*socket, localHello()),
		UI: webui.Handler(), DB: db, Auth: authSvc, Captcha: auth.NewCaptcha(), Orch: orch, Hub: hub, Exec: exec, TrustProxy: *trustProxy,
		HSTS: validCert, FirstAccessFile: firstAccess, BackupDir: backupDir}
	httpSrv := core.NewHTTPServer(*listen, srv.Handler(), logger)
	httpSrv.TLSConfig = tlsConf
	ln, err := (&net.ListenConfig{}).Listen(ctx, "tcp", *listen)
	if err != nil {
		logger.Error("falha ao abrir a porta da interface", "listen", *listen, "erro", err)
		return 1
	}

	go orch.Run(ctx)
	go housekeeping(ctx, db, backupDir, logger)

	errCh := make(chan error, 1)
	go func() {
		if tlsConf != nil {
			errCh <- httpSrv.ServeTLS(ln, "", "")
			return
		}
		errCh <- httpSrv.Serve(ln)
	}()
	logger.Info("vigiahost iniciado", "versao", version.Version, "listen", ln.Addr().String(), "tls", tlsConf != nil)
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

// ensureFirstAccess gera o token de primeiro acesso quando ainda não há usuários e grava o valor num arquivo do
// diretório de estado (0600), lido pelo root com "vigiahost first-access". Não há senha padrão (ADR-016).
func ensureFirstAccess(ctx context.Context, a *auth.Service, path string, logger *slog.Logger) error {
	n, err := a.DB.CountUsers(ctx)
	if err != nil || n > 0 {
		_ = os.Remove(path)
		return err
	}
	if ok, err := a.DB.HasValidFirstAccessToken(ctx); err != nil {
		return err
	} else if ok {
		if _, err := os.Stat(path); err == nil {
			logger.Info("primeiro acesso pendente; leia o token com: sudo vigiahost first-access")
			return nil
		}
	}
	tok, err := a.NewFirstAccessToken(ctx)
	if err != nil {
		return err
	}
	if err := os.WriteFile(path, []byte(tok+"\n"), 0o600); err != nil {
		return err
	}
	logger.Info("primeiro acesso pendente; leia o token com: sudo vigiahost first-access (vale 24 horas)")
	return nil
}

// housekeeping remove sessões vencidas e faz a cópia automática diária do banco.
func housekeeping(ctx context.Context, db *store.DB, backupDir string, logger *slog.Logger) {
	t := time.NewTicker(10 * time.Minute)
	defer t.Stop()
	for {
		if err := db.PurgeExpiredSessions(ctx, 30*time.Minute); err != nil && ctx.Err() == nil {
			logger.Warn("limpeza de sessões falhou", "erro", err)
		}
		dailyBackup(ctx, db, backupDir, logger)
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// dailyBackup faz uma cópia automática por dia (VACUUM INTO, sem parar o serviço) e aplica a retenção.
func dailyBackup(ctx context.Context, db *store.DB, dir string, logger *slog.Logger) {
	list, err := backup.List(dir)
	if err != nil {
		logger.Warn("lista de cópias do banco ilegível", "erro", err)
		return
	}
	for _, i := range list {
		if i.Origin == "automatic" && time.Since(i.CreatedAt) < 24*time.Hour {
			return
		}
	}
	info, err := backup.Create(ctx, db.DB, dir, "automatic", time.Now())
	if err != nil {
		if ctx.Err() == nil {
			logger.Error("cópia automática do banco falhou", "erro", err)
		}
		return
	}
	n, _ := backup.Prune(dir, backup.KeepAutomatic)
	logger.Info("cópia automática do banco", "arquivo", info.Name, "bytes", info.Size, "antigas_removidas", n)
}

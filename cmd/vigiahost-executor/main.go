// Comando vigiahost-executor: processo root mínimo que atende o core por um socket Unix.
// Sem servidor HTTP nem interface; aceita só operações tipadas e aplica a própria política.
package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"os/user"
	"strconv"
	"strings"
	"syscall"

	"github.com/guigallina27/vigiahost/internal/executor"
	"github.com/guigallina27/vigiahost/internal/ipc"
	"github.com/guigallina27/vigiahost/internal/rules"
	"github.com/guigallina27/vigiahost/internal/sdnotify"
	"github.com/guigallina27/vigiahost/internal/version"
)

func main() {
	os.Exit(run(os.Args[1:]))
}

func run(args []string) int {
	if len(args) > 0 && args[0] == "scan" {
		return runScan(args[1:])
	}
	if len(args) > 0 && args[0] == "inspect" {
		return runInspect(args[1:])
	}
	if len(args) > 0 && args[0] == "rules" {
		return runRules(args[1:])

	}
	if len(args) > 0 && args[0] == "integrity" {
		return runIntegrity(args[1:])
	}
	if len(args) > 0 && args[0] == "updates" {
		return runUpdates(args[1:])
	}
	fs := flag.NewFlagSet("vigiahost-executor", flag.ContinueOnError)
	socket := fs.String("socket", "/run/vigiahost-executor/executor.sock", "caminho do socket Unix")
	allow := fs.String("allow-user", "vigiahost", "usuários (separados por vírgula) autorizados além do root")
	group := fs.String("socket-group", "vigiahost", "grupo dono do socket")
	state := fs.String("state", defaultStateDir, "diretório de estado (execuções, cache, regras)")
	localConf := fs.String("config", "/etc/vigiahost/executor.json", "configuração local, alterável só pelo root")
	userRules := fs.String("user-rules", rules.UserDir, "diretório das fontes locais de regras YARA (só do root)")
	showVersion := fs.Bool("version", false, "mostra a versão e sai")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *showVersion {
		fmt.Printf("vigiahost-executor %s (commit %s), protocolo %d.%d\n",
			version.Version, version.Commit, version.ProtocolMajor, version.ProtocolMinor)
		return 0
	}

	logger := slog.New(slog.NewJSONHandler(os.Stderr, nil))
	if os.Geteuid() != 0 {
		logger.Error("o executor precisa rodar como root")
		return 1
	}

	allowed, err := resolveUsers(*allow)
	if err != nil {
		logger.Error("usuário autorizado inválido", "erro", err)
		return 1
	}
	gid, err := resolveGroup(*group)
	if err != nil {
		logger.Error("grupo do socket inválido", "erro", err)
		return 1
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	ln, err := executor.ListenUnix(ctx, *socket, gid)
	if err != nil {
		logger.Error("falha ao abrir o socket", "socket", *socket, "erro", err)
		return 1
	}
	defer func() { _ = os.Remove(*socket) }()

	local, err := executor.LoadLocalConfig(*localConf)
	if err != nil {
		logger.Error("configuração local inválida", "arquivo", *localConf, "erro", err)
		return 1
	}
	exe, err := os.Executable()
	if err != nil {
		logger.Error("caminho do próprio binário indisponível", "erro", err)
		return 1
	}
	runs := &executor.Runs{Logger: logger, StateDir: *state, Exe: exe, CoreGID: gid, Local: local,
		Hardware: executor.DetectHardware(), UserRules: *userRules}
	if err := runs.Prepare(); err != nil {
		logger.Error("diretório de estado indisponível", "dir", *state, "erro", err)
		return 1
	}
	defer runs.Close()
	handlers := executor.DefaultHandlers(os.DirFS("/"), *state)
	runs.Register(handlers)

	srv := &executor.Server{
		Logger:   logger,
		Policy:   executor.Policy{AllowedUIDs: allowed},
		Local:    ipc.Hello{ProtocolMajor: version.ProtocolMajor, ProtocolMinor: version.ProtocolMinor, Version: version.Version},
		Handlers: handlers,
	}
	logger.Info("executor iniciado", "versao", version.Version, "socket", *socket)
	_ = sdnotify.Notify(sdnotify.Ready)
	if err := srv.Serve(ctx, ln); err != nil {
		logger.Error("executor interrompido", "erro", err)
		return 1
	}
	_ = sdnotify.Notify(sdnotify.Stopping)
	logger.Info("executor encerrado")
	return 0
}

func resolveUsers(list string) (map[uint32]bool, error) {
	allowed := make(map[uint32]bool)
	for name := range strings.SplitSeq(list, ",") {
		name = strings.TrimSpace(name)
		if name == "" {
			continue
		}
		u, err := user.Lookup(name)
		if err != nil {
			return nil, err
		}
		uid, err := strconv.ParseUint(u.Uid, 10, 32)
		if err != nil {
			return nil, err
		}
		allowed[uint32(uid)] = true
	}
	return allowed, nil
}

func resolveGroup(name string) (int, error) {
	g, err := user.LookupGroup(name)
	if err != nil {
		return -1, err
	}
	return strconv.Atoi(g.Gid)
}

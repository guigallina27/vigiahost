package main

import (
	"context"
	"flag"
	"log/slog"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/guigallina27/vigiahost/internal/integrity"
	"github.com/guigallina27/vigiahost/internal/report"
	"github.com/guigallina27/vigiahost/internal/scan"
	"github.com/guigallina27/vigiahost/internal/updates"
)

// runIntegrity é o processo da unidade transitória da verificação contra os pacotes (E2.2).
func runIntegrity(args []string) int {
	fs := flag.NewFlagSet("integrity", flag.ContinueOnError)
	dir := fs.String("dir", "", "diretório de saída da execução (com request.json)")
	_ = fs.String("state", defaultStateDir, "diretório de estado do executor")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	return runSystem(*dir, report.KindIntegrity, func(ctx context.Context, req report.Request, logger *slog.Logger) (report.Summary, error) {
		return integrity.Run(ctx, integrity.Config{Request: req, OutDir: *dir, Logger: logger})
	})
}

// runUpdates é o processo da unidade transitória de correções pendentes e reinícios (E2.4). -refresh só chega quando
// o root liberou a atualização da lista de pacotes em /etc/vigiahost/executor.json.
func runUpdates(args []string) int {
	fs := flag.NewFlagSet("updates", flag.ContinueOnError)
	dir := fs.String("dir", "", "diretório de saída da execução (com request.json)")
	_ = fs.String("state", defaultStateDir, "diretório de estado do executor")
	refresh := fs.Bool("refresh", false, "atualiza a lista de pacotes antes de conferir (usa a rede)")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	return runSystem(*dir, report.KindUpdates, func(ctx context.Context, req report.Request, logger *slog.Logger) (report.Summary, error) {
		return updates.Run(ctx, updates.Config{Request: req, OutDir: *dir, Logger: logger, Refresh: *refresh})
	})
}

func runSystem(dir string, kind report.Kind, fn func(context.Context, report.Request, *slog.Logger) (report.Summary, error)) int {
	req, logger, code := readRequest(dir)
	if code != 0 {
		return code
	}
	if req.Kind != kind {
		logger.Error("pedido de outro tipo", "tipo", req.Kind, "esperado", kind)
		return 2
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	started := time.Now().UTC()
	sum, err := fn(ctx, req, logger)
	if err != nil {
		sum = report.Summary{RunID: req.RunID, Kind: kind, Status: report.StatusFailed, Error: err.Error(),
			StartedAt: started, FinishedAt: time.Now().UTC()}
	}
	if err := scan.WriteJSONAtomic(filepath.Join(dir, report.SummaryFile), sum); err != nil {
		logger.Error("resumo não gravado", "erro", err)
		return 1
	}
	logger.Info("verificação encerrada", "tipo", kind, "estado", sum.Status, "achados", sum.Findings)
	if sum.Status == report.StatusFailed {
		return 1
	}
	return 0
}

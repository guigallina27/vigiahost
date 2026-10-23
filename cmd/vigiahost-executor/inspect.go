package main

import (
	"context"
	"flag"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/guigallina27/vigiahost/internal/engines/clamav"
	"github.com/guigallina27/vigiahost/internal/inspect"
	"github.com/guigallina27/vigiahost/internal/report"
	"github.com/guigallina27/vigiahost/internal/rules"
	"github.com/guigallina27/vigiahost/internal/scan"
)

// runInspect é o processo da unidade transitória de uma inspeção de processos, rede e persistência.
func runInspect(args []string) int {
	fs := flag.NewFlagSet("inspect", flag.ContinueOnError)
	dir := fs.String("dir", "", "diretório de saída da execução (com request.json)")
	state := fs.String("state", defaultStateDir, "diretório de estado do executor (regras compiladas, cache)")
	userRules := fs.String("user-rules", rules.UserDir, "diretório das fontes locais de regras YARA")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	req, logger, code := readRequest(*dir)
	if code != 0 {
		return code
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	started := time.Now().UTC()
	info := scan.DiscoverEngines(ctx, *state, scan.DiscoverOptions{Compile: true, ClamdWait: time.Minute,
		UserRules: *userRules, DisabledRules: req.DisabledRuleSources, Trigger: "inspect"},
		func() (clamav.Config, bool) { return clamav.Discover(os.DirFS("/")) })
	cfg := inspect.Config{Request: req, OutDir: *dir, StateDir: *state, Logger: logger}
	info.Apply(&cfg.Engines)
	sum, err := inspect.Run(ctx, cfg)
	if err != nil {
		sum = report.Summary{RunID: req.RunID, Kind: report.KindProcesses, Status: report.StatusFailed, Error: err.Error(),
			StartedAt: started, FinishedAt: time.Now().UTC()}
	}
	if err := scan.WriteJSONAtomic(filepath.Join(*dir, report.SummaryFile), sum); err != nil {
		logger.Error("resumo não gravado", "erro", err)
		return 1
	}
	logger.Info("inspeção encerrada", "estado", sum.Status, "processos", sum.FilesSeen, "achados", sum.Findings)
	if sum.Status == report.StatusFailed {
		return 1
	}
	return 0
}

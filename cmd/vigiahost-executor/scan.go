package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/guigallina27/vigiahost/internal/engines/clamav"
	"github.com/guigallina27/vigiahost/internal/report"
	"github.com/guigallina27/vigiahost/internal/scan"
)

const defaultStateDir = "/var/lib/vigiahost-executor"

// readRequest lê DIR/request.json; código diferente de zero encerra o subcomando.
func readRequest(dir string) (report.Request, *slog.Logger, int) {
	logger := slog.New(slog.NewJSONHandler(os.Stderr, nil))
	var req report.Request
	if dir == "" {
		logger.Error("informe -dir")
		return req, logger, 2
	}
	raw, err := os.ReadFile(filepath.Join(dir, report.RequestFile)) //nolint:gosec // diretório da execução criado pelo executor
	if err == nil {
		err = json.Unmarshal(raw, &req)
	}
	if err != nil {
		logger.Error("pedido da execução ilegível", "erro", err)
		return req, logger, 1
	}
	return req, logger.With("execucao", req.RunID), 0
}

// runScan é o processo que roda dentro da unidade transitória de uma execução de arquivos. Lê o pedido em
// DIR/request.json, grava progresso, achados e resumo no mesmo diretório e termina.
func runScan(args []string) int {
	fs := flag.NewFlagSet("scan", flag.ContinueOnError)
	dir := fs.String("dir", "", "diretório de saída da execução (com request.json)")
	state := fs.String("state", defaultStateDir, "diretório de estado do executor (regras compiladas, cache)")
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
	info := scan.DiscoverEngines(ctx, *state, scan.DiscoverOptions{Compile: true, ClamdWait: 3 * time.Minute}, func() (clamav.Config, bool) { return clamav.Discover(os.DirFS("/")) })
	cfg := scan.Config{Request: req, OutDir: *dir, Logger: logger, CachePath: filepath.Join(*state, "cache", "files.gob")}
	info.Apply(&cfg)
	for _, w := range []string{info.YRError, info.ClamdError} {
		if w != "" {
			logger.Warn("motor indisponível", "detalhe", w)
		}
	}

	sum, err := scan.Run(ctx, cfg)
	if err != nil {
		sum = report.Summary{RunID: req.RunID, Kind: report.KindFiles, Status: report.StatusFailed, Error: err.Error(), StartedAt: started, FinishedAt: time.Now().UTC()}
	}
	if info.Clamd == nil && info.ClamdError != "" && info.Clamscan != "" {
		sum.Warnings = append(sum.Warnings, "clamd indisponível ("+info.ClamdError+"); ClamAV rodou pelo clamscan, mais lento")
	}
	if err := scan.WriteJSONAtomic(filepath.Join(*dir, report.SummaryFile), sum); err != nil {
		logger.Error("resumo não gravado", "erro", err)
		return 1
	}
	logger.Info("execução encerrada", "estado", sum.Status, "arquivos", sum.FilesEligible, "achados", sum.Findings,
		"ignorados", fmt.Sprint(scan.SortedSkips(sum.Skipped)))
	if sum.Status == report.StatusFailed {
		return 1
	}
	return 0
}

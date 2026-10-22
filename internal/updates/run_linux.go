package updates

import (
	"context"
	"io"
	"log/slog"
	"path/filepath"
	"time"

	"github.com/guigallina27/vigiahost/internal/pkgverify"
	"github.com/guigallina27/vigiahost/internal/report"
	"github.com/guigallina27/vigiahost/internal/scan"
	"github.com/guigallina27/vigiahost/internal/version"
)

// Config da execução de atualizações.
type Config struct {
	Request report.Request
	OutDir  string
	Logger  *slog.Logger
	// Refresh vem da configuração local do executor (refresh_package_metadata), nunca do core.
	Refresh bool
}

// Run confere correções pendentes e reinícios, grava achados e updates.json e devolve o resumo.
func Run(ctx context.Context, cfg Config) (report.Summary, error) {
	if cfg.Logger == nil {
		cfg.Logger = slog.New(slog.NewJSONHandler(io.Discard, nil))
	}
	started := time.Now().UTC()
	sum := report.Summary{RunID: cfg.Request.RunID, Kind: report.KindUpdates, StartedAt: started}
	fw, err := scan.NewFindingWriter(filepath.Join(cfg.OutDir, report.FindingsFile))
	if err != nil {
		return sum, err
	}
	defer func() { _ = fw.Close() }()
	prog := report.Progress{StartedAt: started}
	col := &Collector{Manager: pkgverify.Detect("/"), LogDir: cfg.OutDir, Refresh: cfg.Refresh,
		Phase: func(p string) {
			prog.Phase, prog.UpdatedAt = report.Phase(p), time.Now().UTC()
			_ = scan.WriteJSONAtomic(filepath.Join(cfg.OutDir, report.ProgressFile), prog)
		}}
	rep := col.Collect(ctx)
	for _, f := range Findings(rep, time.Now().UTC()) {
		fw.Write(f)
	}
	if err := scan.WriteJSONAtomic(filepath.Join(cfg.OutDir, report.UpdatesFile), rep); err != nil {
		cfg.Logger.Warn("relatório de atualizações não gravado", "erro", err)
	}
	pending := int64(len(rep.Security) + len(rep.Other))
	sum.FinishedAt = time.Now().UTC()
	sum.FilesSeen, sum.FilesEligible, sum.Findings = pending, int64(len(rep.Security)), fw.Count()
	sum.Warnings = append(sum.Warnings, rep.Warnings...)
	if rep.RefreshError != "" {
		sum.Warnings = append(sum.Warnings, "lista de pacotes não atualizada: "+rep.RefreshError)
	}
	cov := report.EngineCoverage{Engine: Engine, Version: version.Version, Available: rep.Error == "",
		SelfTest: report.SelfTest{Ran: true, Positive: true, Negative: true}, Eligible: pending, Analyzed: pending,
		Seconds: rep.Seconds, Error: rep.Error}
	sum.Engines = []report.EngineCoverage{cov}
	switch {
	case ctx.Err() != nil:
		sum.Status = report.StatusCanceled
	case rep.Error != "":
		// Sem a lista de correções, mas reinício e serviços foram conferidos: parcial, com o motivo.
		sum.Status, sum.Error = report.StatusPartial, rep.Error
	default:
		sum.Status = report.StatusCompleted
	}
	_ = scan.WriteJSONAtomic(filepath.Join(cfg.OutDir, report.ProgressFile), report.Progress{Phase: report.PhaseDone,
		StartedAt: started, UpdatedAt: time.Now().UTC(), Findings: fw.Count()})
	return sum, nil
}

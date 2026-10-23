package integrity

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"syscall"
	"time"

	"golang.org/x/sys/unix"

	"github.com/guigallina27/vigiahost/internal/pkgverify"
	"github.com/guigallina27/vigiahost/internal/report"
	"github.com/guigallina27/vigiahost/internal/scan"
	"github.com/guigallina27/vigiahost/internal/version"
)

// Config da execução de integridade.
type Config struct {
	Request  report.Request
	OutDir   string
	Logger   *slog.Logger
	Verifier *pkgverify.Verifier // nil = sistema em execução
}

// Run confere os pacotes, grava achados, integrity.json e devolve o resumo.
func Run(ctx context.Context, cfg Config) (report.Summary, error) {
	if cfg.Logger == nil {
		cfg.Logger = slog.New(slog.NewJSONHandler(io.Discard, nil))
	}
	v := cfg.Verifier
	if v == nil {
		v = pkgverify.New()
	}
	started := time.Now().UTC()
	sum := report.Summary{RunID: cfg.Request.RunID, Kind: report.KindIntegrity, StartedAt: started}
	prog := report.Progress{StartedAt: started}
	fw, err := scan.NewFindingWriter(filepath.Join(cfg.OutDir, report.FindingsFile))
	if err != nil {
		return sum, err
	}
	defer func() { _ = fw.Close() }()
	phase := func(p report.Phase) {
		prog.Phase, prog.UpdatedAt, prog.Findings = p, time.Now().UTC(), fw.Count()
		_ = scan.WriteJSONAtomic(filepath.Join(cfg.OutDir, report.ProgressFile), prog)
	}
	rep := Report{Manager: v.Manager, Ignored: map[string]int{}, Files: []FileResult{}, BySeverity: map[report.Severity]int{}}
	cov := report.EngineCoverage{Engine: Engine, Version: version.Version, Available: v.Available(),
		SelfTest: report.SelfTest{Ran: true, Positive: true, Negative: true}}

	phase(report.PhaseVerify)
	if !v.Available() {
		rep.Error = pkgverify.ErrNoManager.Error()
		cov.Error = rep.Error
		return finish(cfg, sum, rep, cov, fw, report.StatusFailed, rep.Error, started)
	}
	rep.Packages = v.PackageCount(ctx)
	prog.FilesEligible = int64(rep.Packages)
	res, err := v.Verify(ctx)
	rep.Tools, rep.DebsumsAvailable, rep.Warnings = res.Tools, res.DebsumsAvailable, res.Warnings
	if err != nil {
		rep.Error = err.Error()
		cov.Error = rep.Error
		status := report.StatusFailed
		if ctx.Err() != nil {
			status = report.StatusCanceled
		}
		return finish(cfg, sum, rep, cov, fw, status, "verificação dos pacotes: "+err.Error(), started)
	}
	rep.Differences = len(res.Issues)
	assessed, ignored := AssessAll(res.Issues, statPath)
	rep.Ignored = ignored
	checks, err := v.CheckFiles(ctx, DigestPaths(assessed))
	if err != nil {
		rep.Warnings = append(rep.Warnings, "resumos esperados indisponíveis: "+err.Error())
	}
	findings, files := FileFindings(v.Manager, assessed, checks)
	for _, f := range findings {
		fw.Write(f)
	}
	rep.BySeverity = CountSeverity(files)
	if len(files) > MaxFiles {
		rep.Truncated = len(files) - MaxFiles
		files = files[:MaxFiles]
	}
	rep.Files = files
	prog.FilesProcessed = int64(rep.Packages)

	phase(report.PhaseSignature)
	status, msg := report.StatusCompleted, ""
	sig, err := v.Signatures(ctx)
	if err != nil {
		rep.SignatureError = err.Error()
		status, msg = report.StatusPartial, "assinaturas não conferidas: "+err.Error()
	} else {
		if len(sig.Unsigned) > 500 {
			sig.Unsigned = sig.Unsigned[:500]
		}
		if len(sig.UnknownKey) > 500 {
			sig.UnknownKey = sig.UnknownKey[:500]
		}
		rep.Signatures = &sig
		for _, f := range SignatureFindings(sig) {
			fw.Write(f)
		}
	}
	if ctx.Err() != nil {
		status = report.StatusCanceled
	}
	cov.Eligible, cov.Analyzed = int64(rep.Packages), int64(rep.Packages)
	return finish(cfg, sum, rep, cov, fw, status, msg, started)
}

func finish(cfg Config, sum report.Summary, rep Report, cov report.EngineCoverage, fw *scan.FindingWriter,
	status report.Status, msg string, started time.Time) (report.Summary, error) {
	rep.Seconds = time.Since(started).Seconds()
	cov.Seconds = rep.Seconds
	if err := scan.WriteJSONAtomic(filepath.Join(cfg.OutDir, report.IntegrityFile), rep); err != nil {
		cfg.Logger.Warn("relatório de integridade não gravado", "erro", err)
	}
	sum.FinishedAt = time.Now().UTC()
	sum.Status = status
	sum.Error = msg
	sum.FilesSeen = int64(rep.Packages)
	sum.FilesEligible = int64(rep.Differences)
	sum.Findings = fw.Count()
	sum.Engines = []report.EngineCoverage{cov}
	sum.Warnings = append(sum.Warnings, rep.Warnings...)
	_ = scan.WriteJSONAtomic(filepath.Join(cfg.OutDir, report.ProgressFile), report.Progress{Phase: report.PhaseDone,
		StartedAt: started, UpdatedAt: time.Now().UTC(), Findings: fw.Count(), FilesEligible: int64(rep.Packages),
		FilesProcessed: int64(rep.Packages)})
	return sum, nil
}

// statPath lê a localização sem seguir link (o link alterado é o próprio achado).
func statPath(p string) (*report.Location, *pkgverify.FileState) {
	st, err := os.Lstat(p)
	if err != nil {
		return nil, nil
	}
	loc := &report.Location{Size: st.Size(), Mode: uint32(st.Mode().Perm()), Mtime: st.ModTime().UTC()}
	loc.SetPath(p)
	if sys, ok := st.Sys().(*syscall.Stat_t); ok {
		loc.Dev, loc.Ino, loc.Mode, loc.UID, loc.GID, loc.Nlink = sys.Dev, sys.Ino, sys.Mode, sys.Uid, sys.Gid, uint64(sys.Nlink) //nolint:unconvert // Nlink varia por arquitetura
		loc.Ctime = time.Unix(sys.Ctim.Sec, sys.Ctim.Nsec).UTC()                                                                  //nolint:unconvert // idem
	}
	fst := &pkgverify.FileState{Mode: st.Mode()}
	if st.Mode().IsRegular() {
		// Tamanho do atributo security.capability: ENODATA é "sem capacidades"; outro erro deixa desconhecido.
		n, err := unix.Lgetxattr(p, "security.capability", nil)
		fst.CapsKnown = err == nil || errors.Is(err, unix.ENODATA)
		fst.Caps = err == nil && n > 0
	}
	return loc, fst
}

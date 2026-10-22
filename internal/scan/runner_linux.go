package scan

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"golang.org/x/sys/unix"

	"github.com/guigallina27/vigiahost/internal/controls"
	"github.com/guigallina27/vigiahost/internal/engines/clamav"
	"github.com/guigallina27/vigiahost/internal/engines/lmd"
	"github.com/guigallina27/vigiahost/internal/engines/yarax"
	"github.com/guigallina27/vigiahost/internal/report"
)

type engineStats struct {
	eligible, analyzed, fromCache, bytes atomic.Int64
	nanos                                atomic.Int64
	mu                                   sync.Mutex
	skipped                              map[report.SkipReason]int64
	errs                                 map[string]int64
}

// fail conta o arquivo como não analisado e guarda até 10 mensagens distintas para o diagnóstico.
func (s *engineStats) fail(r report.SkipReason, msg string) {
	s.skip(r)
	msg = strings.TrimSpace(msg)
	if i := strings.Index(msg, "/dev/fd/"); i >= 0 { // o número do descritor muda a cada arquivo
		msg = msg[:i] + "/dev/fd/N" + strings.TrimLeft(msg[i+len("/dev/fd/"):], "0123456789")
	}
	s.mu.Lock()
	if s.errs == nil {
		s.errs = map[string]int64{}
	}
	if _, ok := s.errs[msg]; ok || len(s.errs) < 10 {
		s.errs[msg]++
	}
	s.mu.Unlock()
}

func (s *engineStats) skip(r report.SkipReason) {
	s.mu.Lock()
	if s.skipped == nil {
		s.skipped = map[report.SkipReason]int64{}
	}
	s.skipped[r]++
	s.mu.Unlock()
}

type runner struct {
	cfg      Config
	ctx      context.Context
	cache    *Cache
	findings *FindingWriter
	progress report.Progress
	pmu      sync.Mutex

	seen, eligible, processed, bytesElig, bytesDone, cacheHits atomic.Int64
	smu                                                        sync.Mutex
	skipped                                                    map[report.SkipReason]int64
	warnings                                                   []string
	yara, clam, lmd                                            engineStats
	yaraErr, clamErr, lmdErr                                   atomic.Value // string: falha geral do motor
	objects                                                    sync.Map     // sha256 -> struct{}
	large                                                      []*file
	lmu                                                        sync.Mutex
	// Fila do LMD: descritores duplicados entregues ao maldet em sessões grandes, numa goroutine própria (o
	// canal com espaço para um lote limita os descritores abertos).
	lmdQueue []*file
	lmdMu    sync.Mutex
	lmdCh    chan []*file
	lmdWG    sync.WaitGroup
}

// Run executa a varredura de arquivos e grava progresso, achados e resumo no diretório de saída.
func Run(ctx context.Context, cfg Config) (report.Summary, error) {
	cfg.defaults()
	raiseNoFile()
	r := &runner{cfg: cfg, ctx: ctx, skipped: map[report.SkipReason]int64{}}
	sum := report.Summary{RunID: cfg.Request.RunID, Kind: report.KindFiles, StartedAt: time.Now().UTC()}
	r.progress.StartedAt = sum.StartedAt

	fw, err := NewFindingWriter(filepath.Join(cfg.OutDir, report.FindingsFile))
	if err != nil {
		return sum, err
	}
	r.findings = fw
	defer func() { _ = fw.Close() }()

	stopProgress := r.startProgress()
	defer stopProgress()

	// Autoteste: motor que falha no controle positivo não analisa nada e a execução vira "falha de motor".
	r.setPhase(report.PhaseSelfTest)
	yaraST, clamST := r.selfTest()
	if !yaraST.Passed() {
		r.cfg.YARA = nil
	}
	clamOK := clamST.Passed()
	var lmdST report.SelfTest
	if cfg.Request.LMD {
		lmdST = LMDSelfTest(ctx, cfg)
		if !lmdST.Passed() {
			r.cfg.LMD = nil
		}
	}
	if cfg.LMD != nil {
		// A árvore-sombra e as sessões do LMD não precisam sobreviver à execução.
		defer func() { _ = os.RemoveAll(cfg.LMD.Work) }()
	}

	clamVer := cfg.ClamVersion.Engine + "/" + cfg.ClamVersion.Database
	cacheYARA := ""
	if r.cfg.YARA != nil {
		cacheYARA = cfg.YARAVersion + "/" + cfg.RulesVersion
	}
	if !cfg.Request.Incremental {
		r.cache = LoadCache("", "", "")
		r.cache.path = cfg.CachePath // varredura completa: ignora o cache antigo, mas grava o novo
		r.cache.yaraVer, r.cache.clamVer = cacheYARA, clamVer
	} else {
		r.cache = LoadCache(cfg.CachePath, cacheYARA, clamVer)
	}
	r.cache.SetLMDVersion(LMDVersion(r.cfg.LMD))
	if !clamOK {
		r.cfg.Clamd, r.cfg.Clamscan = nil, nil
	}
	if r.cfg.LMD != nil {
		r.lmdCh = make(chan []*file, 1)
		r.lmdWG.Go(func() {
			for b := range r.lmdCh {
				r.runLMD(b)
			}
		})
	}

	// Inventário e análise em lotes, em paralelo.
	r.setPhase(report.PhaseScanning)
	batches := make(chan []*file, cfg.Request.Profile.Workers)
	var wg sync.WaitGroup
	for range cfg.Request.Profile.Workers {
		wg.Go(func() {
			for b := range batches {
				r.processBatch(b)
			}
		})
	}
	var batch []*file
	flush := func() {
		if len(batch) > 0 {
			batches <- batch
			batch = nil
		}
	}
	w := &walker{
		exclude:  cfg.Request.Exclude,
		maxDepth: 512,
		visited:  map[[2]uint64]bool{},
		seen:     func() { r.seen.Add(1) },
		skip:     func(reason report.SkipReason, _ string) { r.addSkip(reason) },
		warn:     r.warn,
		stop:     func() bool { return ctx.Err() != nil },
		emit: func(fl *file) {
			r.eligible.Add(1)
			r.bytesElig.Add(fl.st.Size)
			batch = append(batch, fl)
			if len(batch) >= cfg.BatchSize {
				flush()
			}
		},
	}
	for _, root := range cfg.Request.Paths {
		if err := w.walkRootOwned(root, cfg.Request.Owners[root]); err != nil {
			r.warn(fmt.Sprintf("raiz %s não pôde ser percorrida: %v", quote(root), err))
		}
	}
	flush()
	close(batches)
	wg.Wait()

	// Último lote do LMD (os anteriores rodaram durante o percurso).
	if r.lmdCh != nil {
		r.setPhase(report.PhaseLMD)
		r.lmdMu.Lock()
		rest := r.lmdQueue
		r.lmdQueue = nil
		r.lmdMu.Unlock()
		if len(rest) > 0 {
			r.lmdCh <- rest
		}
		close(r.lmdCh)
		r.lmdWG.Wait()
	}

	// Fila de arquivos grandes: clamscan com limites maiores.
	r.setPhase(report.PhaseLarge)
	r.processLarge()

	if err := r.cache.Save(); err != nil {
		r.warn("cache não gravado: " + err.Error())
	}

	sum.FinishedAt = time.Now().UTC()
	sum.FilesSeen = r.seen.Load()
	sum.FilesEligible = r.eligible.Load()
	sum.BytesEligible = r.bytesElig.Load()
	sum.Findings = fw.count.Load()
	sum.CacheHits = r.cacheHits.Load()
	r.objects.Range(func(any, any) bool { sum.Objects++; return true })
	r.smu.Lock()
	sum.Skipped = r.skipped
	sum.Warnings = r.warnings
	r.smu.Unlock()
	secs := sum.FinishedAt.Sub(sum.StartedAt).Seconds()
	if secs > 0 {
		sum.FilesPerSecond = float64(sum.FilesEligible) / secs
		sum.MBPerSecond = float64(r.bytesDone.Load()) / (1 << 20) / secs
	}
	sum.Engines = []report.EngineCoverage{
		r.coverage(EngineYARA, cfg.YARAVersion, cfg.RulesVersion, cfg.YARA != nil, yaraST, &r.yara, &r.yaraErr),
		r.coverage(EngineClamAV, cfg.ClamVersion.Engine, cfg.ClamVersion.Database, cfg.Clamd != nil || cfg.Clamscan != nil, clamST, &r.clam, &r.clamErr),
	}
	if cfg.Request.LMD {
		var ver, sigs string
		if cfg.LMD != nil {
			ver, sigs = cfg.LMD.Install.Version, cfg.LMD.Install.SigVersion
		}
		sum.Engines = append(sum.Engines, r.coverage(EngineLMD, ver, sigs, cfg.LMD != nil, lmdST, &r.lmd, &r.lmdErr))
	}
	sum.Status = r.status(sum)
	if ctx.Err() != nil {
		sum.Status = report.StatusCanceled
	}
	r.setPhase(report.PhaseDone)
	return sum, nil
}

func (r *runner) status(sum report.Summary) report.Status {
	engineFail := false
	partial := false
	for _, e := range sum.Engines {
		if !e.SelfTest.Passed() || e.Error != "" {
			engineFail = true
		}
		for reason, n := range e.Skipped {
			if n > 0 && reason != report.SkipCached {
				partial = true
			}
		}
	}
	switch {
	case engineFail:
		return report.StatusEngineError
	case partial || sum.Skipped[report.SkipPermission] > 0 || sum.Skipped[report.SkipChanged] > 0:
		return report.StatusPartial
	}
	return report.StatusCompleted
}

func (r *runner) coverage(name, version, rules string, available bool, st report.SelfTest, s *engineStats, errv *atomic.Value) report.EngineCoverage {
	c := report.EngineCoverage{
		Engine: name, Version: version, RulesVersion: rules, Available: available, SelfTest: st,
		Eligible: s.eligible.Load(), Analyzed: s.analyzed.Load(), FromCache: s.fromCache.Load(),
		BytesAnalyzed: s.bytes.Load(), Seconds: time.Duration(s.nanos.Load()).Seconds(),
	}
	s.mu.Lock()
	c.Skipped = s.skipped
	c.Errors = s.errs
	s.mu.Unlock()
	if e, ok := errv.Load().(string); ok {
		c.Error = e
	}
	if !available && c.Error == "" {
		c.Error = st.Detail
	}
	return c
}

func (r *runner) addSkip(reason report.SkipReason) {
	r.smu.Lock()
	r.skipped[reason]++
	r.smu.Unlock()
}

func (r *runner) warn(msg string) {
	r.smu.Lock()
	if len(r.warnings) < 200 {
		r.warnings = append(r.warnings, msg)
	}
	r.smu.Unlock()
	r.cfg.Logger.Warn(msg)
}

// processBatch: hash e classificação, cache, YARA-X no lote inteiro e clamd arquivo a arquivo.
func (r *runner) processBatch(batch []*file) {
	defer func() {
		for _, fl := range batch {
			if fl.f != nil {
				_ = unix.Fadvise(int(fl.f.Fd()), 0, 0, unix.FADV_DONTNEED)
				_ = fl.f.Close()
			}
		}
	}()
	type state struct {
		fl                   *file
		sha                  [32]byte
		needYARA, needClam   bool
		yaraClean, clamClean bool
		hits                 int
	}
	states := make([]*state, 0, len(batch))
	for _, fl := range batch {
		if r.ctx.Err() != nil {
			return
		}
		st := &state{fl: fl}
		key := fl.key()
		cachedSHA, yaraCached, clamCached, inCache := r.cache.Lookup(key)
		sha, err := r.readHeadAndHash(fl, inCache, cachedSHA)
		if err != nil {
			r.addSkip(report.SkipChanged)
			r.yara.skip(report.SkipChanged)
			r.clam.skip(report.SkipChanged)
			continue
		}
		st.sha, fl.sha = sha, sha
		r.objects.Store(st.sha, struct{}{})
		r.processed.Add(1)
		r.bytesDone.Add(fl.st.Size)
		r.nameIndicators(fl, st.sha)

		// YARA-X: roteamento por tipo e limite de tamanho.
		switch {
		case r.cfg.YARA == nil:
		case fl.st.Size > r.cfg.YARAMaxFile:
			r.yara.eligible.Add(1)
			r.yara.skip(report.SkipTooLarge)
		case !yaraRoutes(fl.typ):
			// Mídia, fontes e imagens sem código: as regras são de scripts, ELF e texto (escopo, seção 12.1).
		case yaraCached:
			r.yara.eligible.Add(1)
			r.yara.fromCache.Add(1)
			r.yara.analyzed.Add(1)
			st.yaraClean = true
		default:
			r.yara.eligible.Add(1)
			st.needYARA = true
		}
		// LMD: mesmo roteamento por tipo do YARA (assinaturas de scripts, binários e texto) e a faixa de tamanho
		// padrão do próprio LMD (scan_min_filesize/scan_max_filesize). Fora dela o arquivo não é elegível para o LMD,
		// como no LMD sozinho, e segue coberto pelo YARA-X e pelo ClamAV; não conta como cobertura parcial. Os
		// arquivos seguem em lotes grandes para a goroutine do LMD.
		lmdQueued := false
		switch {
		case r.cfg.LMD == nil:
		case fl.st.Size < r.cfg.LMDMinFile || fl.st.Size > r.cfg.LMDMaxFile || !yaraRoutes(fl.typ):
		case r.cache.LMDClean(key):
			r.lmd.eligible.Add(1)
			r.lmd.fromCache.Add(1)
			r.lmd.analyzed.Add(1)
			r.cache.StoreLMD(key, sha, true)
		default:
			r.lmd.eligible.Add(1)
			lmdQueued = r.queueLMD(fl)
		}
		// ClamAV: tudo, com arquivos acima do limite do clamd na fila de grandes.
		switch {
		case r.cfg.Clamd == nil && r.cfg.Clamscan == nil:
		case clamCached:
			r.clam.eligible.Add(1)
			r.clam.fromCache.Add(1)
			r.clam.analyzed.Add(1)
			st.clamClean = true
		case fl.st.Size > r.cfg.LargeMaxFile:
			r.clam.eligible.Add(1)
			r.clam.skip(report.SkipTooLarge)
		case r.cfg.Clamd == nil || fl.st.Size > r.cfg.ClamdMaxFile:
			r.clam.eligible.Add(1)
			r.queueClamscan(fl) // o descritor é duplicado; o resultado sai quando a fila esvaziar
			states = append(states, st)
			continue
		default:
			r.clam.eligible.Add(1)
			st.needClam = true
		}
		if yaraCached && (clamCached || r.cfg.Clamd == nil && r.cfg.Clamscan == nil) && !lmdQueued {
			r.cacheHits.Add(1)
		}
		states = append(states, st)
	}

	// YARA-X no lote.
	var yfiles []*os.File
	var yidx []*state
	for _, st := range states {
		if st.needYARA {
			yfiles = append(yfiles, st.fl.f)
			yidx = append(yidx, st)
		}
	}
	if len(yfiles) > 0 {
		t0 := time.Now()
		res, err := r.cfg.YARA.ScanFiles(r.ctx, yfiles)
		r.yara.nanos.Add(int64(time.Since(t0)))
		if err != nil {
			r.yaraErr.Store(err.Error())
			for range yfiles {
				r.yara.fail(report.SkipEngine, err.Error())
			}
		} else {
			for i, st := range yidx {
				if res.Errors[i] != "" {
					reason := report.SkipEngine
					if strings.Contains(strings.ToLower(res.Errors[i]), "timeout") {
						reason = report.SkipTimeout
					}
					r.yara.fail(reason, res.Errors[i])
					continue
				}
				r.yara.analyzed.Add(1)
				r.yara.bytes.Add(st.fl.st.Size)
				for _, m := range res.Matches[i] {
					r.emitYARA(st.fl, st.sha, m)
					st.hits++
				}
				st.yaraClean = len(res.Matches[i]) == 0
			}
		}
	}

	// clamd por descritor, com concorrência limitada (o clamd costuma ser compartilhado com o e-mail).
	sem := make(chan struct{}, r.cfg.Request.Profile.ClamdConcurrency)
	var wg sync.WaitGroup
	for _, st := range states {
		if !st.needClam {
			continue
		}
		sem <- struct{}{}
		wg.Go(func() {
			defer func() { <-sem }()
			t0 := time.Now()
			v := r.cfg.Clamd.ScanFD(r.ctx, st.fl.f)
			r.clam.nanos.Add(int64(time.Since(t0)))
			r.applyClam(st.fl, st.sha, v, &st.clamClean, &st.hits)
		})
	}
	wg.Wait()

	for _, st := range states {
		r.cache.Store(st.fl.key(), st.sha, st.yaraClean && st.hits == 0, st.clamClean && st.hits == 0)
	}
}

func (r *runner) applyClam(fl *file, sha [32]byte, v clamav.Verdict, clean *bool, hits *int) {
	switch {
	case v.Err != nil:
		reason := report.SkipEngine
		msg := strings.ToLower(v.Err.Error())
		if strings.Contains(msg, "size limit") || strings.Contains(msg, "exceeds") {
			reason = report.SkipTooLarge
		}
		r.clam.fail(reason, v.Err.Error())
	case v.Found:
		r.clam.analyzed.Add(1)
		r.clam.bytes.Add(fl.st.Size)
		r.emitClam(fl, sha, v.Signature)
		*hits++
	default:
		r.clam.analyzed.Add(1)
		r.clam.bytes.Add(fl.st.Size)
		*clean = true
	}
}

// yaraRoutes decide se o tipo vai para as regras YARA (as do produto são de scripts, binários e texto).
func yaraRoutes(t FileType) bool {
	switch t {
	case TypeImage, TypeMedia, TypeFont, TypeEmpty:
		return false
	}
	return true
}

// queueClamscan põe o arquivo na fila do clamscan: arquivos acima do limite do clamd ou, sem clamd, todos. O
// clamscan carrega as assinaturas a cada execução (dezenas de segundos), então a fila esvazia em lotes grandes.
func (r *runner) queueClamscan(fl *file) {
	nfd, err := unix.FcntlInt(fl.f.Fd(), unix.F_DUPFD_CLOEXEC, 0) // o lote fecha o original
	if err != nil {
		r.clam.fail(report.SkipEngine, "descritor não duplicado: "+err.Error())
		return
	}
	cp := *fl
	cp.f = os.NewFile(uintptr(nfd), "fila-clamscan")
	r.lmu.Lock()
	r.large = append(r.large, &cp)
	var full []*file
	if len(r.large) >= r.cfg.MaxLarge {
		full, r.large = r.large, nil
	}
	r.lmu.Unlock()
	if full != nil {
		r.runClamscan(full)
	}
}

// processLarge esvazia o que restou na fila do clamscan.
func (r *runner) processLarge() {
	r.lmu.Lock()
	rest := r.large
	r.large = nil
	r.lmu.Unlock()
	r.runClamscan(rest)
}

func (r *runner) runClamscan(queue []*file) {
	defer func() {
		for _, fl := range queue {
			_ = unix.Fadvise(int(fl.f.Fd()), 0, 0, unix.FADV_DONTNEED)
			_ = fl.f.Close()
		}
	}()
	if len(queue) == 0 {
		return
	}
	if r.cfg.Clamscan == nil {
		for range queue {
			r.clam.fail(report.SkipTooLarge, "acima do limite do clamd e sem clamscan para a fila de grandes")
		}
		return
	}
	files := make([]*os.File, len(queue))
	for i, fl := range queue {
		files[i] = fl.f
		_, _ = fl.f.Seek(0, io.SeekStart)
	}
	t0 := time.Now()
	verdicts, err := r.cfg.Clamscan.ScanFiles(r.ctx, files)
	r.clam.nanos.Add(int64(time.Since(t0)))
	if err != nil {
		r.clamErr.Store(err.Error())
		for range queue {
			r.clam.fail(report.SkipEngine, err.Error())
		}
		return
	}
	for i, fl := range queue {
		var clean bool
		var hits int
		r.applyClam(fl, fl.sha, verdicts[i], &clean, &hits)
		r.cache.Store(fl.key(), fl.sha, false, clean && hits == 0)
	}
}

// queueLMD põe o arquivo na fila do LMD (descritor duplicado: o lote fecha o original). Devolve se entrou.
func (r *runner) queueLMD(fl *file) bool {
	nfd, err := unix.FcntlInt(fl.f.Fd(), unix.F_DUPFD_CLOEXEC, 0)
	if err != nil {
		r.lmd.fail(report.SkipEngine, "descritor não duplicado: "+err.Error())
		return false
	}
	cp := *fl
	cp.f = os.NewFile(uintptr(nfd), "fila-lmd")
	r.lmdMu.Lock()
	r.lmdQueue = append(r.lmdQueue, &cp)
	var full []*file
	if len(r.lmdQueue) >= r.cfg.LMDBatch {
		full, r.lmdQueue = r.lmdQueue, nil
	}
	r.lmdMu.Unlock()
	if full != nil {
		r.lmdCh <- full // espera se o LMD ainda está no lote anterior
	}
	return true
}

// runLMD entrega um lote ao maldet e grava as detecções.
func (r *runner) runLMD(queue []*file) {
	defer func() {
		for _, fl := range queue {
			_ = unix.Fadvise(int(fl.f.Fd()), 0, 0, unix.FADV_DONTNEED)
			_ = fl.f.Close()
		}
	}()
	if r.ctx.Err() != nil {
		return
	}
	files := make([]*os.File, len(queue))
	for i, fl := range queue {
		files[i] = fl.f
	}
	t0 := time.Now()
	res, err := r.cfg.LMD.ScanFiles(r.ctx, files)
	r.lmd.nanos.Add(int64(time.Since(t0)))
	if err != nil {
		if r.ctx.Err() != nil {
			return
		}
		r.lmdErr.Store(err.Error())
		for range queue {
			r.lmd.fail(report.SkipEngine, err.Error())
		}
		return
	}
	if res.Unmapped > 0 {
		r.warn(fmt.Sprintf("LMD: %d detecção(ões) da sessão %s citavam arquivo fora do lote e foram descartadas", res.Unmapped, res.ScanID))
	}
	for i, fl := range queue {
		r.lmd.analyzed.Add(1)
		r.lmd.bytes.Add(fl.st.Size)
		seen := map[string]bool{}
		for _, h := range res.Hits[i] {
			if !seen[h.Signature] {
				seen[h.Signature] = true
				r.emitLMD(fl, h)
			}
		}
		r.cache.StoreLMD(fl.key(), fl.sha, len(res.Hits[i]) == 0)
	}
}

func (r *runner) emitLMD(fl *file, h lmd.Hit) {
	cat, sev := ClassifyLMDSignature(h.Signature)
	r.findings.Write(report.Finding{
		Engine: EngineLMD, EngineVersion: r.cfg.LMD.Install.Version, RulesVersion: r.cfg.LMD.Install.SigVersion,
		Signature: h.Signature, Source: SourceRFXN, Reference: "https://www.rfxn.com/projects/linux-malware-detect/",
		Description: "Assinatura do Linux Malware Detect (estágio " + h.Type + ")",
		Category:    cat, Severity: sev,
		SHA256: hex.EncodeToString(fl.sha[:]), FileType: string(fl.typ), Location: fl.location(),
		Evidence: map[string]string{"lmd_estagio": h.Type},
	})
}

// LMDSelfTest roda o EICAR (controle positivo, que o LMD conhece pelo hash e pelo padrão hexadecimal) e o controle
// negativo pelo mesmo caminho da varredura (escopo, seção 7.4).
func LMDSelfTest(parent context.Context, cfg Config) report.SelfTest {
	var st report.SelfTest
	if cfg.LMD == nil {
		st.Detail = cfg.LMDError
		if st.Detail == "" {
			st.Detail = lmd.ErrNotInstalled.Error()
		}
		return st
	}
	st.Ran = true
	ctx, cancel := context.WithTimeout(parent, 3*time.Minute)
	defer cancel()
	pos, err1 := memFile("controle-positivo", controls.EICAR())
	neg, err2 := memFile("controle-negativo", controls.NegativeFile())
	defer closeFiles(pos, neg)
	if err := errors.Join(err1, err2); err != nil {
		st.Detail = err.Error()
		return st
	}
	res, err := cfg.LMD.ScanFiles(ctx, []*os.File{pos, neg})
	if err != nil {
		st.Detail = err.Error()
		return st
	}
	for _, h := range res.Hits[0] {
		if strings.Contains(strings.ToLower(h.Signature), "eicar") {
			st.Positive = true
		}
	}
	st.Negative = len(res.Hits[1]) == 0
	if !st.Positive {
		st.Detail = "o EICAR não foi detectado pelo LMD: assinaturas não carregadas"
	}
	return st
}

// readHeadAndHash lê o arquivo uma vez: cabeçalho para a classificação e SHA-256 do conteúdo inteiro. Arquivo
// inalterado no cache não é relido: só o cabeçalho, para o roteamento.
func (r *runner) readHeadAndHash(fl *file, inCache bool, cached [32]byte) ([32]byte, error) {
	var sum [32]byte
	head := make([]byte, HeadSize)
	n, err := fl.f.ReadAt(head, 0)
	if err != nil && !errors.Is(err, io.EOF) {
		return sum, err
	}
	fl.head = head[:n]
	fl.typ = Classify(fl.head, filepath.Base(fl.raw))
	if inCache {
		return cached, nil
	}
	h := sha256.New()
	if _, err := io.Copy(h, io.NewSectionReader(fl.f, 0, fl.st.Size)); err != nil {
		return sum, err
	}
	var after unix.Stat_t
	if err := unix.Fstat(int(fl.f.Fd()), &after); err != nil || after.Size != fl.st.Size || after.Ctim != fl.st.Ctim {
		return sum, errors.New("arquivo alterado durante a leitura")
	}
	copy(sum[:], h.Sum(nil))
	return sum, nil
}

func (r *runner) nameIndicators(fl *file, sha [32]byte) {
	flags := NameFlags(filepath.Base(fl.raw), fl.typ)
	for _, f := range flags {
		sev, desc := report.SeverityMedium, ""
		switch f {
		case FlagBidi:
			desc = "Nome com caractere de inversão bidirecional, que disfarça a extensão real"
		case FlagControlChars:
			desc = "Nome com caracteres de controle (quebra de linha, escape de terminal)"
		case FlagInvalidUTF8:
			desc = "Nome com bytes inválidos em UTF-8"
			sev = report.SeverityLow
		case FlagInvisibleChars:
			desc = "Nome com caracteres invisíveis"
			sev = report.SeverityLow
		case FlagDoubleExt:
			desc = "Script com extensão dupla de imagem (ex.: foto.jpg.php)"
			sev = report.SeverityHigh
		case FlagHiddenPHP:
			// Informativo: ferramentas de desenvolvimento usam nomes assim (.phpstorm.meta.php, .ht.router.php).
			desc = "Script PHP oculto (nome iniciado por ponto)"
			sev = report.SeverityInfo
		case FlagTypeMismatch:
			desc = "Código PHP em arquivo com extensão de imagem"
			sev = report.SeverityHigh
		}
		r.findings.Write(report.Finding{
			Engine: EngineInventory, Signature: "nome." + string(f), Source: "vigiahost",
			Description: desc, Category: report.CategoryIndicator, Severity: sev,
			SHA256: hex.EncodeToString(sha[:]), FileType: string(fl.typ), Location: fl.location(),
		})
	}
}

func (r *runner) emitYARA(fl *file, sha [32]byte, m yarax.Match) {
	f := report.Finding{
		Engine: EngineYARA, EngineVersion: r.cfg.YARAVersion, RulesVersion: r.cfg.RulesVersion,
		Signature: m.Rule, Source: m.Namespace,
		Author: m.Meta["author"], Reference: m.Meta["reference"], License: m.Meta["license"],
		Description: m.Meta["description"],
		Category:    report.Category(m.Meta["category"]), Severity: report.Severity(m.Meta["severity"]),
		SHA256: hex.EncodeToString(sha[:]), FileType: string(fl.typ), Location: fl.location(),
	}
	if m.Rule == controls.YARARuleName {
		f.Category, f.Severity = report.CategoryTest, report.SeverityInfo
	}
	if f.Category == "" {
		f.Category = report.CategorySuspicious
	}
	if !report.ValidSeverity(f.Severity) {
		f.Severity = report.SeverityMedium
	}
	r.findings.Write(f)
}

func (r *runner) emitClam(fl *file, sha [32]byte, sig string) {
	cat, sev := ClassifyClamSignature(sig)
	source := ClamSource(sig)
	r.findings.Write(report.Finding{
		Engine: EngineClamAV, EngineVersion: r.cfg.ClamVersion.Engine, RulesVersion: r.cfg.ClamVersion.Database,
		Signature: sig, Source: source, Category: cat, Severity: sev,
		SHA256: hex.EncodeToString(sha[:]), FileType: string(fl.typ), Location: fl.location(),
	})
}

func (r *runner) selfTest() (yaraST, clamST report.SelfTest) { return SelfTest(r.ctx, r.cfg) }

// SelfTest roda os controles positivo e negativo em cada motor (escopo, seção 7.4).
func SelfTest(parent context.Context, cfg Config) (yaraST, clamST report.SelfTest) {
	ctx, cancel := context.WithTimeout(parent, 2*time.Minute)
	defer cancel()
	r := struct{ cfg Config }{cfg}
	if r.cfg.YARA == nil {
		yaraST.Detail = "YARA-X não encontrado"
	} else {
		yaraST.Ran = true
		pos, err1 := memFile("controle-positivo", controls.MarkerFile())
		neg, err2 := memFile("controle-negativo", controls.NegativeFile())
		if err := errors.Join(err1, err2); err != nil {
			yaraST.Detail = err.Error()
		} else {
			res, err := r.cfg.YARA.ScanFiles(ctx, []*os.File{pos, neg})
			if err != nil {
				yaraST.Detail = err.Error()
			} else {
				yaraST.Positive = hasRule(res.Matches[0], controls.YARARuleName)
				yaraST.Negative = len(res.Matches[1]) == 0 && res.Errors[1] == ""
				if !yaraST.Positive {
					yaraST.Detail = "o controle positivo não foi detectado: regras não carregadas"
				}
			}
		}
		closeFiles(pos, neg)
	}
	switch {
	case r.cfg.Clamd != nil:
		clamST.Ran = true
		p := r.cfg.Clamd.ScanStream(ctx, strings.NewReader(string(controls.EICAR())))
		n := r.cfg.Clamd.ScanStream(ctx, strings.NewReader(string(controls.NegativeFile())))
		clamST.Positive = p.Found
		clamST.Negative = !n.Found && n.Err == nil
		if p.Err != nil {
			clamST.Detail = p.Err.Error()
		} else if !p.Found {
			clamST.Detail = "o EICAR não foi detectado: assinaturas não carregadas"
		}
	case r.cfg.Clamscan != nil:
		clamST.Ran = true
		pos, err1 := memFile("controle-positivo", controls.EICAR())
		neg, err2 := memFile("controle-negativo", controls.NegativeFile())
		if err := errors.Join(err1, err2); err != nil {
			clamST.Detail = err.Error()
		} else {
			v, err := r.cfg.Clamscan.ScanFiles(ctx, []*os.File{pos, neg})
			if err != nil {
				clamST.Detail = err.Error()
			} else {
				clamST.Positive = v[0].Found
				clamST.Negative = !v[1].Found && v[1].Err == nil
				if !v[0].Found {
					clamST.Detail = "o EICAR não foi detectado: assinaturas não carregadas"
				}
			}
		}
		closeFiles(pos, neg)
	default:
		clamST.Detail = "ClamAV não encontrado (nem clamd nem clamscan)"
	}
	return yaraST, clamST
}

// RulesSelfTest confere um conjunto recém-compilado com o controle positivo e o negativo.
func RulesSelfTest(ctx context.Context, yr, compiled string) (bool, string) {
	pos, err1 := memFile("controle-positivo", controls.MarkerFile())
	neg, err2 := memFile("controle-negativo", controls.NegativeFile())
	defer closeFiles(pos, neg)
	if err := errors.Join(err1, err2); err != nil {
		return false, err.Error()
	}
	res, err := (&yarax.Scanner{Bin: yr, Rules: compiled, Timeout: 60}).ScanFiles(ctx, []*os.File{pos, neg})
	switch {
	case err != nil:
		return false, err.Error()
	case !hasRule(res.Matches[0], controls.YARARuleName):
		return false, "o controle positivo não foi detectado pelo conjunto compilado"
	case len(res.Matches[1]) > 0:
		return false, "o controle negativo foi acusado pela regra " + res.Matches[1][0].Namespace + "." + res.Matches[1][0].Rule
	}
	return true, ""
}

func hasRule(ms []yarax.Match, rule string) bool {
	for _, m := range ms {
		if m.Rule == rule {
			return true
		}
	}
	return false
}

func closeFiles(fs ...*os.File) {
	for _, f := range fs {
		if f != nil {
			_ = f.Close()
		}
	}
}

// MemFile cria um arquivo só em memória (memfd) com o conteúdo, posicionado no início.
func MemFile(name string, data []byte) (*os.File, error) { return memFile(name, data) }

// memFile cria um arquivo só em memória (memfd) com o conteúdo, posicionado no início.
func memFile(name string, data []byte) (*os.File, error) {
	fd, err := unix.MemfdCreate(name, unix.MFD_CLOEXEC)
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(fd), name)
	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		return nil, err
	}
	_, _ = f.Seek(0, io.SeekStart)
	return f, nil
}

func raiseNoFile() {
	var lim syscall.Rlimit
	if syscall.Getrlimit(syscall.RLIMIT_NOFILE, &lim) == nil && lim.Cur < lim.Max {
		lim.Cur = lim.Max
		_ = syscall.Setrlimit(syscall.RLIMIT_NOFILE, &lim)
	}
}

// --- progresso ---

func (r *runner) setPhase(p report.Phase) {
	r.pmu.Lock()
	r.progress.Phase = p
	r.pmu.Unlock()
	r.writeProgress()
}

func (r *runner) startProgress() func() {
	done := make(chan struct{})
	var wg sync.WaitGroup
	wg.Go(func() {
		t := time.NewTicker(time.Second)
		defer t.Stop()
		for {
			select {
			case <-done:
				return
			case <-t.C:
				r.writeProgress()
			}
		}
	})
	return func() { close(done); wg.Wait(); r.writeProgress() }
}

func (r *runner) writeProgress() {
	r.pmu.Lock()
	p := r.progress
	r.pmu.Unlock()
	p.FilesSeen = r.seen.Load()
	p.FilesEligible = r.eligible.Load()
	p.FilesProcessed = r.processed.Load()
	p.BytesEligible = r.bytesElig.Load()
	p.BytesProcessed = r.bytesDone.Load()
	if r.findings != nil {
		p.Findings = r.findings.count.Load()
	}
	p.UpdatedAt = time.Now().UTC()
	_ = WriteJSONAtomic(filepath.Join(r.cfg.OutDir, report.ProgressFile), p)
}

// --- achados ---

// FindingWriter grava achados no findings.ndjson, linha a linha (o core lê enquanto a execução roda).
type FindingWriter struct {
	mu    sync.Mutex
	f     *os.File
	w     *bufio.Writer
	count atomic.Int64
}

// NewFindingWriter cria o arquivo de achados.
func NewFindingWriter(path string) (*FindingWriter, error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC|os.O_APPEND, 0o640) //nolint:gosec // diretório da execução, criado pelo executor
	if err != nil {
		return nil, err
	}
	return &FindingWriter{f: f, w: bufio.NewWriter(f)}, nil
}

// Write grava um achado.
func (fw *FindingWriter) Write(f report.Finding) {
	f.DetectedAt = time.Now().UTC()
	data, err := json.Marshal(f)
	if err != nil {
		return
	}
	fw.mu.Lock()
	_, _ = fw.w.Write(append(data, '\n'))
	_ = fw.w.Flush() // o core lê achados enquanto a execução ainda roda
	fw.mu.Unlock()
	fw.count.Add(1)
}

// Count devolve quantos achados foram gravados.
func (fw *FindingWriter) Count() int64 { return fw.count.Load() }

// Close grava o que falta e fecha.
func (fw *FindingWriter) Close() error {
	fw.mu.Lock()
	defer fw.mu.Unlock()
	return errors.Join(fw.w.Flush(), fw.f.Sync(), fw.f.Close())
}

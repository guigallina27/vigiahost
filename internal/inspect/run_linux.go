package inspect

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/guigallina27/vigiahost/internal/controls"
	"github.com/guigallina27/vigiahost/internal/report"
	"github.com/guigallina27/vigiahost/internal/scan"
	"github.com/guigallina27/vigiahost/internal/version"
)

// Arquivos extras gravados no diretório da execução de processos.
const (
	ProcessesFile   = "processes.json"
	PersistenceFile = "persistence.json"
)

// Config da inspeção; os motores vêm da mesma descoberta da varredura de arquivos.
type Config struct {
	Request  report.Request
	OutDir   string
	StateDir string
	Logger   *slog.Logger
	Engines  scan.Config // YARA, Clamd, Clamscan e versões (o resto é ignorado)
	Proc     string      // raiz do procfs (padrão /proc)
	Root     fs.FS       // raiz do sistema (padrão os.DirFS("/"))
	// CPUSample é a janela de medição de CPU por processo (padrão 2 s).
	CPUSample time.Duration
}

// PersistenceReport é o conteúdo de persistence.json.
type PersistenceReport struct {
	Baseline bool                      `json:"baseline"` // primeira inspeção: sem comparação
	Items    []report.PersistenceEntry `json:"items"`
	Removed  []report.PersistenceEntry `json:"removed,omitempty"`
}

type inspector struct {
	cfg      Config
	ctx      context.Context
	fw       *scan.FindingWriter
	warnings []string
	progress report.Progress
}

func (in *inspector) warn(msg string) {
	in.cfg.Logger.Warn(msg)
	if len(in.warnings) < 100 {
		in.warnings = append(in.warnings, msg)
	}
}

func (in *inspector) phase(p report.Phase) {
	in.progress.Phase = p
	in.progress.UpdatedAt = time.Now().UTC()
	if in.fw != nil {
		in.progress.Findings = in.fw.Count()
	}
	_ = scan.WriteJSONAtomic(filepath.Join(in.cfg.OutDir, report.ProgressFile), in.progress)
}

// Run inspeciona processos, rede e persistência e grava achados, instantâneos e resumo.
func Run(ctx context.Context, cfg Config) (report.Summary, error) {
	if cfg.Proc == "" {
		cfg.Proc = "/proc"
	}
	if cfg.Root == nil {
		cfg.Root = os.DirFS("/")
	}
	if cfg.CPUSample <= 0 {
		cfg.CPUSample = 2 * time.Second
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.New(slog.NewJSONHandler(io.Discard, nil))
	}
	sum := report.Summary{RunID: cfg.Request.RunID, Kind: report.KindProcesses, StartedAt: time.Now().UTC()}
	in := &inspector{cfg: cfg, ctx: ctx}
	in.progress.StartedAt = sum.StartedAt
	fw, err := scan.NewFindingWriter(filepath.Join(cfg.OutDir, report.FindingsFile))
	if err != nil {
		return sum, err
	}
	in.fw = fw
	defer func() { _ = fw.Close() }()

	in.phase(report.PhaseSelfTest)
	yaraST, clamST := scan.SelfTest(ctx, cfg.Engines)
	if !yaraST.Passed() {
		in.cfg.Engines.YARA = nil
	}
	if !clamST.Passed() {
		in.cfg.Engines.Clamd, in.cfg.Engines.Clamscan = nil, nil
	}

	in.phase(report.PhaseInspect)
	uidMin := loginUIDMin(cfg.Root)
	procs := in.processes()
	in.progress.FilesSeen = int64(len(procs))
	in.network(procs)
	in.packages(procs)
	yaraCov, clamCov := in.scanExecutables(procs)
	for _, h := range AnalyzeProcesses(procs, uidMin) {
		in.emitProc(h)
	}
	in.kernel()
	pers := in.persistence(uidMin)

	names := usernames(cfg.Root)
	for _, p := range procs {
		p.User = names[p.UID]
	}
	sort.Slice(procs, func(i, j int) bool { return procs[i].PID < procs[j].PID })
	if err := scan.WriteJSONAtomic(filepath.Join(cfg.OutDir, ProcessesFile), procs); err != nil {
		in.warn("instantâneo dos processos não gravado: " + err.Error())
	}
	if err := scan.WriteJSONAtomic(filepath.Join(cfg.OutDir, PersistenceFile), pers); err != nil {
		in.warn("inventário de persistência não gravado: " + err.Error())
	}

	sum.FinishedAt = time.Now().UTC()
	sum.FilesSeen = int64(len(procs))
	sum.FilesEligible = int64(len(pers.Items))
	sum.Findings = fw.Count()
	sum.Objects = yaraCov.Eligible
	sum.Warnings = in.warnings
	yaraCov.Engine, yaraCov.Version, yaraCov.RulesVersion = scan.EngineYARA, cfg.Engines.YARAVersion, cfg.Engines.RulesVersion
	yaraCov.Available, yaraCov.SelfTest = in.cfg.Engines.YARA != nil, yaraST
	clamCov.Engine, clamCov.Version, clamCov.RulesVersion = scan.EngineClamAV, cfg.Engines.ClamVersion.Engine, cfg.Engines.ClamVersion.Database
	clamCov.Available, clamCov.SelfTest = in.cfg.Engines.Clamd != nil || in.cfg.Engines.Clamscan != nil, clamST
	sum.Engines = []report.EngineCoverage{yaraCov, clamCov,
		{Engine: Engine, Version: version.Version, Available: true, SelfTest: report.SelfTest{Ran: true, Positive: true, Negative: true},
			Eligible: int64(len(procs)), Analyzed: int64(len(procs))}}
	sum.Status = report.StatusCompleted
	switch {
	case ctx.Err() != nil:
		sum.Status = report.StatusCanceled
	case !yaraST.Passed() && !clamST.Passed():
		sum.Status = report.StatusPartial
		sum.Warnings = append(sum.Warnings, "nenhum motor passou no autoteste: os executáveis não foram analisados por assinatura")
	}
	in.phase(report.PhaseDone)
	return sum, nil
}

// loginUIDMin lê UID_MIN de /etc/login.defs (padrão 1000).
func loginUIDMin(root fs.FS) int {
	b, err := fs.ReadFile(root, "etc/login.defs")
	if err != nil {
		return 1000
	}
	for _, l := range strings.Split(string(b), "\n") {
		f := strings.Fields(l)
		if len(f) == 2 && f[0] == "UID_MIN" {
			if n, err := strconv.Atoi(f[1]); err == nil && n > 0 {
				return n
			}
		}
	}
	return 1000
}

func (in *inspector) read(pid int, name string) ([]byte, error) {
	f, err := os.Open(filepath.Join(in.cfg.Proc, strconv.Itoa(pid), name)) //nolint:gosec // procfs
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	return io.ReadAll(io.LimitReader(f, 1<<20))
}

// processes lê todos os processos de usuário (threads do kernel ficam de fora) e mede a CPU numa janela curta.
func (in *inspector) processes() []*Process {
	entries, err := os.ReadDir(in.cfg.Proc)
	if err != nil {
		in.warn("procfs ilegível: " + err.Error())
		return nil
	}
	var procs []*Process
	for _, e := range entries {
		pid, err := strconv.Atoi(e.Name())
		if err != nil || pid <= 0 {
			continue
		}
		p := &Process{PID: pid}
		stat, err := in.read(pid, "stat")
		if err != nil {
			continue // processo terminou
		}
		var ok bool
		p.PPID, p.cpuTicks, p.StartTime, p.Threads, ok = parseStat(stat)
		if !ok || pid == 2 || p.PPID == 2 {
			continue
		}
		if i, j := bytes.IndexByte(stat, '('), bytes.LastIndexByte(stat, ')'); i >= 0 && j > i {
			p.Comm = string(stat[i+1 : j])
		}
		exe, err := os.Readlink(filepath.Join(in.cfg.Proc, e.Name(), "exe"))
		if err != nil && len(p.Comm) > 0 {
			// Sem executável legível (zumbi ou thread do kernel com outro pai): sem o que analisar.
			if c, _ := in.read(pid, "cmdline"); len(c) == 0 {
				continue
			}
		}
		p.Exe = exe
		ClassifyExe(p)
		if b, err := in.read(pid, "status"); err == nil {
			p.UID, p.RSSBytes = parseStatus(b)
		}
		if b, err := in.read(pid, "cmdline"); err == nil {
			raw := splitCmdline(b)
			p.kthreadArg = len(raw) > 0 && IsKernelThreadName(raw[0])
			p.Cmdline = MaskArgs(raw)
		}
		if b, err := in.read(pid, "cgroup"); err == nil {
			p.Cgroup, p.Unit = unitFromCgroup(b)
		}
		if b, err := in.read(pid, "environ"); err == nil {
			p.ldPreload = envValue(b, "LD_PRELOAD")
		}
		p.netns, _ = os.Readlink(filepath.Join(in.cfg.Proc, e.Name(), "ns", "net"))
		p.sockets = in.socketInodes(pid)
		procs = append(procs, p)
	}
	// Segunda leitura para a CPU.
	start := time.Now()
	select {
	case <-in.ctx.Done():
	case <-time.After(in.cfg.CPUSample):
	}
	elapsed := time.Since(start).Seconds()
	const clkTck = 100 // USER_HZ em todas as arquiteturas suportadas
	for _, p := range procs {
		if b, err := in.read(p.PID, "stat"); err == nil {
			if _, ticks, st, _, ok := parseStat(b); ok && st == p.StartTime && ticks >= p.cpuTicks && elapsed > 0 {
				p.CPUPercent = float64(ticks-p.cpuTicks) / clkTck / elapsed * 100
			}
		}
	}
	return procs
}

func (in *inspector) socketInodes(pid int) []uint64 {
	dir := filepath.Join(in.cfg.Proc, strconv.Itoa(pid), "fd")
	ents, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}
	var out []uint64
	for _, e := range ents {
		l, err := os.Readlink(filepath.Join(dir, e.Name()))
		if err != nil || !strings.HasPrefix(l, "socket:[") {
			continue
		}
		if n, err := strconv.ParseUint(strings.TrimSuffix(strings.TrimPrefix(l, "socket:["), "]"), 10, 64); err == nil {
			out = append(out, n)
		}
		if len(out) >= 4096 {
			break
		}
	}
	return out
}

// network lê as tabelas de sockets de cada namespace de rede (a unidade da inspeção roda sem rede, então lê pelo
// /proc/PID/net de um processo de cada namespace) e liga cada socket ao processo dono.
func (in *inspector) network(procs []*Process) {
	byNS := map[string]int{}
	for _, p := range procs {
		if _, ok := byNS[p.netns]; !ok && p.netns != "" {
			byNS[p.netns] = p.PID
		}
	}
	sockets := map[uint64]Socket{}
	for _, pid := range byNS {
		for _, proto := range []string{"tcp", "tcp6", "udp", "udp6"} {
			b, err := in.read(pid, filepath.Join("net", proto))
			if err != nil {
				continue
			}
			for _, s := range ParseNetFile(strings.TrimSuffix(proto, "6"), b) {
				sockets[s.Inode] = s
			}
		}
	}
	for _, p := range procs {
		for _, ino := range p.sockets {
			s, ok := sockets[ino]
			if !ok {
				continue
			}
			switch {
			case s.Proto == "tcp" && s.State == tcpListen, s.Proto == "udp" && s.RPort == 0 && strings.HasSuffix(s.Remote, ":0"):
				p.Listening = appendLimited(p.Listening, s.Proto+" "+s.Local)
			case s.Proto == "tcp" && s.State == tcpEstablished, s.Proto == "udp" && s.RPort != 0:
				p.Connected = appendLimited(p.Connected, s.Proto+" "+s.Local+"->"+s.Remote)
			}
		}
	}
}

func appendLimited(s []string, v string) []string {
	if len(s) >= 64 {
		return s
	}
	for _, x := range s {
		if x == v {
			return s
		}
	}
	return append(s, v)
}

// packages descobre o pacote dono dos executáveis em diretórios do sistema ("-" = nenhum).
func (in *inspector) packages(procs []*Process) {
	paths := map[string][]*Process{}
	for _, p := range procs {
		exe := exePath(p.Exe)
		if p.ExeDeleted || p.ExeMemfd || !hasAnyPrefix(exe, systemDirs) {
			continue
		}
		paths[exe] = append(paths[exe], p)
	}
	if len(paths) == 0 {
		return
	}
	list := make([]string, 0, len(paths))
	for p := range paths {
		list = append(list, p)
	}
	sort.Strings(list)
	owners, err := packageOwners(in.ctx, list)
	if err != nil {
		in.warn("consulta de pacotes indisponível: " + err.Error())
		return
	}
	for exe, ps := range paths {
		for _, p := range ps {
			p.Package = owners[exe]
		}
	}
}

// packageOwners consulta o rpm ou o dpkg em lote.
func packageOwners(ctx context.Context, paths []string) (map[string]string, error) {
	ctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	out := map[string]string{}
	env := append(os.Environ(), "LANG=C", "LC_ALL=C")
	if _, err := os.Stat("/usr/bin/rpm"); err == nil {
		args := append([]string{"-qf", "--qf", "%{NAME}\\n"}, paths...)
		cmd := exec.CommandContext(ctx, "/usr/bin/rpm", args...) //nolint:gosec // caminhos lidos de /proc/PID/exe
		cmd.Env = env
		b, err := cmd.Output()
		if err != nil && len(b) == 0 {
			return nil, err
		}
		lines := strings.Split(strings.TrimRight(string(b), "\n"), "\n")
		if len(lines) != len(paths) {
			return nil, fmt.Errorf("rpm devolveu %d linhas para %d arquivos", len(lines), len(paths))
		}
		for i, l := range lines {
			if strings.Contains(l, "not owned by any package") || strings.HasPrefix(l, "error:") {
				out[paths[i]] = "-"
			} else {
				out[paths[i]] = l
			}
		}
		return out, nil
	}
	if _, err := os.Stat("/usr/bin/dpkg-query"); err == nil {
		// Com /usr unificado, o banco do dpkg pode registrar /bin/x para o que hoje é /usr/bin/x: consulta os dois.
		query := append([]string{}, paths...)
		for _, p := range paths {
			if alt, ok := strings.CutPrefix(p, "/usr"); ok {
				query = append(query, alt)
			}
		}
		cmd := exec.CommandContext(ctx, "/usr/bin/dpkg-query", append([]string{"-S"}, query...)...) //nolint:gosec // idem
		cmd.Env = env
		b, _ := cmd.Output()
		found := map[string]string{}
		for _, l := range strings.Split(string(b), "\n") {
			pkg, file, ok := strings.Cut(l, ": ")
			if ok {
				found[strings.TrimSpace(file)] = strings.Split(pkg, ",")[0]
			}
		}
		for _, p := range paths {
			alt, _ := strings.CutPrefix(p, "/usr")
			switch {
			case found[p] != "":
				out[p] = found[p]
			case found[alt] != "":
				out[p] = found[alt]
			default:
				out[p] = "-"
			}
		}
		return out, nil
	}
	return nil, errors.New("nem rpm nem dpkg encontrados")
}

// scanExecutables calcula o hash de cada executável distinto (por /proc/PID/exe, inclusive memfd e apagados) e o
// analisa com YARA-X e ClamAV pelo descritor (ADR-018).
func (in *inspector) scanExecutables(procs []*Process) (yaraCov, clamCov report.EngineCoverage) {
	type target struct {
		f     *os.File
		sha   string
		procs []*Process
	}
	yaraCov.Skipped, clamCov.Skipped = map[report.SkipReason]int64{}, map[report.SkipReason]int64{}
	byID := map[[2]uint64]*target{}
	var targets []*target
	for _, p := range procs {
		if p.Exe == "" {
			continue
		}
		f, err := os.Open(filepath.Join(in.cfg.Proc, strconv.Itoa(p.PID), "exe")) //nolint:gosec // procfs
		if err != nil {
			continue
		}
		st, err := f.Stat()
		if err != nil || !st.Mode().IsRegular() {
			_ = f.Close()
			continue
		}
		sys, _ := st.Sys().(*syscall.Stat_t)
		var id [2]uint64
		if sys != nil {
			id = [2]uint64{sys.Dev, sys.Ino}
		}
		if t, ok := byID[id]; ok && sys != nil {
			t.procs = append(t.procs, p)
			p.ExeSHA256 = t.sha
			_ = f.Close()
			continue
		}
		if st.Size() > 512<<20 {
			yaraCov.Skipped[report.SkipTooLarge]++
			clamCov.Skipped[report.SkipTooLarge]++
			_ = f.Close()
			continue
		}
		h := sha256.New()
		if _, err := io.Copy(h, f); err != nil {
			_ = f.Close()
			continue
		}
		_, _ = f.Seek(0, io.SeekStart)
		t := &target{f: f, sha: hex.EncodeToString(h.Sum(nil)), procs: []*Process{p}}
		p.ExeSHA256 = t.sha
		byID[id] = t
		targets = append(targets, t)
	}
	defer func() {
		for _, t := range targets {
			_ = t.f.Close()
		}
	}()
	yaraCov.Eligible, clamCov.Eligible = int64(len(targets)), int64(len(targets))
	in.progress.FilesEligible = int64(len(targets))
	eng := in.cfg.Engines
	started := time.Now()
	if eng.YARA != nil {
		for i := 0; i < len(targets); i += 128 {
			batch := targets[i:min(i+128, len(targets))]
			files := make([]*os.File, len(batch))
			for j, t := range batch {
				files[j] = t.f
			}
			res, err := eng.YARA.ScanFiles(in.ctx, files)
			if err != nil {
				in.warn("YARA-X falhou nos executáveis: " + err.Error())
				yaraCov.Skipped[report.SkipEngine] += int64(len(batch))
				continue
			}
			for j, t := range batch {
				if res.Errors[j] != "" {
					yaraCov.Skipped[report.SkipEngine]++
					continue
				}
				yaraCov.Analyzed++
				for _, m := range res.Matches[j] {
					sev := report.Severity(m.Meta["severity"])
					cat := report.Category(m.Meta["category"])
					if m.Rule == controls.YARARuleName {
						cat, sev = report.CategoryTest, report.SeverityInfo
					}
					in.emitExeMatch(t.procs[0], t.sha, scan.EngineYARA, eng.YARAVersion, eng.RulesVersion, m.Rule, m.Namespace,
						m.Meta["description"], cat, sev, map[string]string{"processos": pidList(t.procs)})
				}
				_, _ = t.f.Seek(0, io.SeekStart)
			}
		}
		yaraCov.Seconds = time.Since(started).Seconds()
	}
	started = time.Now()
	switch {
	case eng.Clamd != nil:
		for _, t := range targets {
			_, _ = t.f.Seek(0, io.SeekStart)
			v := eng.Clamd.ScanFD(in.ctx, t.f)
			if v.Err != nil {
				clamCov.Skipped[report.SkipEngine]++
				continue
			}
			clamCov.Analyzed++
			if v.Found {
				cat, sev := scan.ClassifyClamSignature(v.Signature)
				in.emitExeMatch(t.procs[0], t.sha, scan.EngineClamAV, eng.ClamVersion.Engine, eng.ClamVersion.Database,
					v.Signature, "clamav", "", cat, sev, map[string]string{"processos": pidList(t.procs)})
			}
		}
	case eng.Clamscan != nil:
		files := make([]*os.File, len(targets))
		for i, t := range targets {
			_, _ = t.f.Seek(0, io.SeekStart)
			files[i] = t.f
		}
		vs, err := eng.Clamscan.ScanFiles(in.ctx, files)
		if err != nil {
			in.warn("clamscan falhou nos executáveis: " + err.Error())
			clamCov.Skipped[report.SkipEngine] += int64(len(targets))
			break
		}
		for i, v := range vs {
			if v.Err != nil {
				clamCov.Skipped[report.SkipEngine]++
				continue
			}
			clamCov.Analyzed++
			if v.Found {
				cat, sev := scan.ClassifyClamSignature(v.Signature)
				in.emitExeMatch(targets[i].procs[0], targets[i].sha, scan.EngineClamAV, eng.ClamVersion.Engine,
					eng.ClamVersion.Database, v.Signature, "clamav", "", cat, sev, map[string]string{"processos": pidList(targets[i].procs)})
			}
		}
	}
	clamCov.Seconds = time.Since(started).Seconds()
	in.progress.FilesProcessed = int64(len(targets))
	return yaraCov, clamCov
}

func pidList(ps []*Process) string {
	var b strings.Builder
	for i, p := range ps {
		if i == 20 {
			fmt.Fprintf(&b, " e mais %d", len(ps)-20)
			break
		}
		if i > 0 {
			b.WriteString(", ")
		}
		b.WriteString(strconv.Itoa(p.PID))
	}
	return b.String()
}

func evidence(p *Process) *report.ProcessEvidence {
	return &report.ProcessEvidence{PID: p.PID, PPID: p.PPID, UID: p.UID, Comm: p.Comm, Exe: p.Exe, Cmdline: p.Cmdline,
		Unit: p.Unit, Cgroup: p.Cgroup, ExeSHA256: p.ExeSHA256, StartTime: strconv.FormatUint(p.StartTime, 10),
		Listening: p.Listening, Connected: p.Connected}
}

// emitExeMatch grava detecção de motor no executável de um processo; executável sem arquivo agrava a severidade.
func (in *inspector) emitExeMatch(p *Process, sha, engine, ver, rules, sig, source, desc string, cat report.Category,
	sev report.Severity, ev map[string]string) {
	if cat == "" {
		cat = report.CategorySuspicious
	}
	if !report.ValidSeverity(sev) {
		sev = report.SeverityHigh
	}
	if (p.ExeMemfd || p.ExeDeleted) && cat != report.CategoryTest {
		sev = report.SeverityCritical
	}
	p.Flags = append(p.Flags, engine+":"+sig)
	in.fw.Write(report.Finding{Engine: engine, EngineVersion: ver, RulesVersion: rules, Signature: sig, Source: source,
		Description: desc, Category: cat, Severity: sev, SHA256: sha, FileType: "elf", Process: evidence(p), Evidence: ev})
}

func (in *inspector) emitProc(h ProcHit) {
	in.fw.Write(report.Finding{Engine: Engine, EngineVersion: version.Version, Signature: h.Signature, Source: "vigiahost",
		Description: h.Description, Category: h.Category, Severity: h.Severity, SHA256: h.Proc.ExeSHA256,
		Process: evidence(h.Proc), Evidence: h.Evidence})
}

func (in *inspector) emitPersistence(h Hit) {
	e := h.Item
	in.fw.Write(report.Finding{Engine: Engine, EngineVersion: version.Version, Signature: h.Signature, Source: "vigiahost",
		Description: h.Description, Category: h.Category, Severity: h.Severity, Persistence: &e, Evidence: h.Evidence})
}

// kernel confere módulos fora da árvore ou sem assinatura e o taint do kernel.
func (in *inspector) kernel() {
	if b, err := os.ReadFile(filepath.Join(in.cfg.Proc, "modules")); err == nil {
		for _, l := range strings.Split(string(b), "\n") {
			f := strings.Fields(l)
			if len(f) < 6 {
				continue
			}
			flags := f[len(f)-1]
			if strings.HasPrefix(flags, "(") && (strings.Contains(flags, "O") || strings.Contains(flags, "E")) {
				e := report.PersistenceEntry{Kind: "kernel-module", Path: f[0], Detail: "marcas " + flags}
				in.emitPersistence(Hit{Signature: "kernel.modulo_fora_da_arvore", Severity: report.SeverityLow,
					Category: report.CategoryPersistence, Item: e,
					Description: "módulo de kernel fora da árvore oficial ou sem assinatura (O = externo, E = sem assinatura)"})
			}
		}
	}
	if b, err := os.ReadFile(filepath.Join(in.cfg.Proc, "sys", "kernel", "tainted")); err == nil {
		if v := strings.TrimSpace(string(b)); v != "0" && v != "" {
			in.emitPersistence(Hit{Signature: "kernel.taint", Severity: report.SeverityInfo, Category: report.CategoryPersistence,
				Item:        report.PersistenceEntry{Kind: "kernel", Path: "/proc/sys/kernel/tainted", Detail: "valor " + v},
				Description: "kernel marcado (taint): módulo externo, sem assinatura ou erro anterior"})
		}
	}
}

// persistence coleta o inventário, compara com a inspeção anterior e grava a nova referência.
func (in *inspector) persistence(uidMin int) PersistenceReport {
	c := &Collector{Root: in.cfg.Root, Homes: Homes(in.cfg.Root, uidMin), Owner: fileOwner(in.cfg.Root)}
	items := c.Collect()
	invPath := filepath.Join(in.cfg.StateDir, "cache", "persistence-inventory.json")
	var prev map[string]string
	if b, err := os.ReadFile(invPath); err == nil { //nolint:gosec // diretório de estado do executor
		if json.Unmarshal(b, &prev) != nil {
			prev = nil
		}
	}
	removed := Diff(items, prev)
	for _, h := range Analyze(items) {
		in.emitPersistence(h)
	}
	for _, h := range ChangeHits(items, removed) {
		in.emitPersistence(h)
	}
	if in.cfg.StateDir != "" {
		if err := scan.WriteJSONAtomic(invPath, Inventory(items)); err != nil {
			in.warn("referência do inventário de persistência não gravada: " + err.Error())
		}
	}
	rep := PersistenceReport{Baseline: prev == nil, Removed: removed, Items: make([]report.PersistenceEntry, len(items))}
	for i, it := range items {
		rep.Items[i] = it.Entry
	}
	if rep.Baseline {
		in.warn("primeira inspeção de persistência: o inventário atual virou a referência para as próximas comparações")
	}
	return rep
}

// fileOwner devolve o nome do dono do arquivo (pelo UID).
func fileOwner(root fs.FS) func(string) string {
	names := usernames(root)
	return func(p string) string {
		st, err := os.Lstat(p)
		if err != nil {
			return ""
		}
		if sys, ok := st.Sys().(*syscall.Stat_t); ok {
			if n, ok := names[sys.Uid]; ok {
				return n
			}
			return strconv.FormatUint(uint64(sys.Uid), 10)
		}
		return ""
	}
}

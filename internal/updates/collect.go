package updates

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/guigallina27/vigiahost/internal/pkgverify"
)

// Caminhos fixos das ferramentas.
const (
	dnfBin         = "/usr/bin/dnf"
	rpmBin         = "/usr/bin/rpm"
	aptGetBin      = "/usr/bin/apt-get"
	needrestartBin = "/usr/sbin/needrestart"
)

// Collector junta as informações do relatório. Os testes trocam o Runner e as raízes.
type Collector struct {
	Manager pkgverify.Manager
	Runner  pkgverify.Runner
	Root    string // raiz do sistema (padrão "/")
	Proc    string // raiz do procfs (padrão "/proc")
	// LogDir recebe o log do dnf (a unidade da execução não grava em /var/log).
	LogDir string
	// Refresh atualiza a lista de pacotes antes (só com permissão da configuração local do executor).
	Refresh bool
	Now     func() time.Time
	// Phase é chamado ao mudar de etapa (progresso).
	Phase func(string)
}

func (c *Collector) root(p string) string { return filepath.Join(c.rootDir(), filepath.FromSlash(p)) }

func (c *Collector) rootDir() string {
	if c.Root == "" {
		return "/"
	}
	return c.Root
}

func (c *Collector) proc() string {
	if c.Proc == "" {
		return "/proc"
	}
	return c.Proc
}

func (c *Collector) exists(p string) bool {
	_, err := os.Stat(c.root(p))
	return err == nil
}

func (c *Collector) out(ctx context.Context, name string, args ...string) ([]byte, string, int, error) {
	r := c.Runner
	if r == nil {
		r = pkgverify.ExecRunner{}
	}
	return pkgverify.RunOutput(ctx, r, 32<<20, name, args...)
}

func (c *Collector) phase(p string) {
	if c.Phase != nil {
		c.Phase(p)
	}
}

// dnf monta os argumentos comuns: só o cache (-C), saída curta e o log no diretório da execução.
func (c *Collector) dnf(args ...string) []string {
	base := []string{"-q", "-C"}
	if c.LogDir != "" {
		base = append(base, "--setopt=logdir="+c.LogDir)
	}
	return append(base, args...)
}

func firstLine(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		s = s[:i]
	}
	if len(s) > 300 {
		s = s[:300] + "…"
	}
	return s
}

// Collect produz o relatório. Falhas parciais viram avisos; Error só quando não deu para conferir as correções.
func (c *Collector) Collect(ctx context.Context) Report {
	now := time.Now
	if c.Now != nil {
		now = c.Now
	}
	started := now()
	rep := Report{Manager: string(c.Manager), Security: []Update{}, Other: []Update{}, Services: []Service{},
		Processes: []Process{}, Tools: map[string]bool{}, BySeverity: map[string]int{}, RefreshAllowed: c.Refresh}
	c.phase("updates")
	switch c.Manager {
	case pkgverify.RPM:
		c.collectRPM(ctx, &rep)
	case pkgverify.DPKG:
		c.collectApt(ctx, &rep)
	default:
		rep.Error = pkgverify.ErrNoManager.Error()
	}
	rep.BySeverity = CountBySeverity(rep.Security)
	c.phase("restart")
	c.collectRestart(ctx, &rep)
	c.collectReboot(ctx, &rep)
	rep.Seconds = now().Sub(started).Seconds()
	return rep
}

func (c *Collector) collectRPM(ctx context.Context, rep *Report) {
	if !c.exists(dnfBin) {
		rep.Error = "dnf não encontrado: correções pendentes não podem ser conferidas"
		return
	}
	rep.Tools["dnf"] = true
	if c.Refresh {
		_, stderr, code, err := c.out(ctx, dnfBin, "-q", "--setopt=logdir="+c.LogDir, "makecache")
		if err != nil || code != 0 {
			rep.RefreshError = firstLine(stderr)
			if err != nil {
				rep.RefreshError = err.Error()
			}
		} else {
			rep.Refreshed = true
		}
	}
	rep.CacheUpdatedAt, rep.CacheOldestAt = c.cacheTimes(filepath.Join("var", "cache", "dnf", "*", "repodata", "repomd.xml"))
	adv, stderr, code, err := c.out(ctx, dnfBin, c.dnf("updateinfo", "list", "--security")...)
	if err != nil || code != 0 {
		rep.Error = "dnf updateinfo: " + firstLine(stderr)
		if err != nil {
			rep.Error = "dnf updateinfo: " + err.Error()
		}
		return
	}
	cves, _, _, _ := c.out(ctx, dnfBin, c.dnf("updateinfo", "list", "--security", "--with-cve")...)
	upd, stderr, code, err := c.out(ctx, dnfBin, c.dnf("check-update")...)
	if err != nil || (code != 0 && code != 100) {
		rep.Warnings = append(rep.Warnings, "dnf check-update: "+firstLine(stderr))
	}
	inst, _, _, _ := c.out(ctx, rpmBin, "-qa", "--qf", `%{NAME}\t%{ARCH}\t%{EPOCHNUM}\t%{VERSION}\t%{RELEASE}\n`)
	rep.Security, rep.Other = MergeRPM(ParseCheckUpdate(upd), ParseUpdateinfo(adv), ParseUpdateinfo(cves), ParseRPMInstalled(inst))
}

func (c *Collector) collectApt(ctx context.Context, rep *Report) {
	if !c.exists(aptGetBin) {
		rep.Error = "apt-get não encontrado: correções pendentes não podem ser conferidas"
		return
	}
	rep.Tools["apt"] = true
	if c.Refresh {
		_, stderr, code, err := c.out(ctx, aptGetBin, "-q", "update")
		if err != nil || code != 0 {
			rep.RefreshError = firstLine(stderr)
			if err != nil {
				rep.RefreshError = err.Error()
			}
		} else {
			rep.Refreshed = true
		}
	}
	rep.CacheUpdatedAt, rep.CacheOldestAt = c.cacheTimes(filepath.Join("var", "lib", "apt", "lists", "*Release"))
	if t := c.mtime(filepath.Join("var", "lib", "apt", "periodic", "update-success-stamp")); t != nil &&
		(rep.CacheUpdatedAt == nil || t.After(*rep.CacheUpdatedAt)) {
		rep.CacheUpdatedAt = t
	}
	// Simulação sem trava: não altera nada e roda com a raiz somente leitura.
	out, stderr, code, err := c.out(ctx, aptGetBin, "-s", "-o", "Debug::NoLocking=1", "dist-upgrade")
	if err != nil || code != 0 {
		rep.Error = "apt-get -s dist-upgrade: " + firstLine(stderr)
		if err != nil {
			rep.Error = "apt-get: " + err.Error()
		}
		return
	}
	rep.Security, rep.Other = ParseAptSimulate(out)
}

// cacheTimes devolve a data mais recente e a mais antiga entre os arquivos do padrão.
func (c *Collector) cacheTimes(pattern string) (newest, oldest *time.Time) {
	files, _ := filepath.Glob(filepath.Join(c.rootDir(), pattern))
	for _, f := range files {
		st, err := os.Stat(f)
		if err != nil {
			continue
		}
		t := st.ModTime().UTC()
		if newest == nil || t.After(*newest) {
			newest = &t
		}
		if oldest == nil || t.Before(*oldest) {
			t2 := t
			oldest = &t2
		}
	}
	return newest, oldest
}

func (c *Collector) mtime(p string) *time.Time {
	st, err := os.Stat(c.root(p))
	if err != nil {
		return nil
	}
	t := st.ModTime().UTC()
	return &t
}

// collectRestart lê /proc/PID/maps de todos os processos (detecção própria, vale em qualquer distribuição) e soma
// o que o needs-restarting (RPM) ou o needrestart (Debian/Ubuntu) informam.
func (c *Collector) collectRestart(ctx context.Context, rep *Report) {
	units := map[string]*Service{}
	ents, err := os.ReadDir(c.proc())
	if err != nil {
		rep.Warnings = append(rep.Warnings, "procfs ilegível: "+err.Error())
	}
	self := os.Getpid()
	for _, e := range ents {
		pid, err := strconv.Atoi(e.Name())
		if err != nil || pid <= 0 || pid == self || ctx.Err() != nil {
			continue
		}
		dir := filepath.Join(c.proc(), e.Name())
		maps, err := os.ReadFile(filepath.Join(dir, "maps")) //nolint:gosec // procfs
		if err != nil {
			continue
		}
		files := DeletedMappings(maps)
		if len(files) == 0 {
			continue
		}
		cg, _ := os.ReadFile(filepath.Join(dir, "cgroup")) //nolint:gosec // procfs
		if unit := UnitFromCgroup(cg); unit != "" {
			s := units[unit]
			if s == nil {
				s = &Service{Unit: unit, Source: "maps"}
				units[unit] = s
			}
			s.PIDs = append(s.PIDs, pid)
			for _, f := range files {
				if len(s.Files) < 20 {
					s.Files = appendUnique(s.Files, f)
				}
			}
			continue
		}
		if len(rep.Processes) < 500 {
			comm, _ := os.ReadFile(filepath.Join(dir, "comm")) //nolint:gosec // procfs
			p := Process{PID: pid, Comm: strings.TrimSpace(string(comm)), Files: files[:min(len(files), 20)]}
			if st, err := os.ReadFile(filepath.Join(dir, "status")); err == nil { //nolint:gosec // procfs
				p.UID = statusUID(st)
			}
			rep.Processes = append(rep.Processes, p)
		}
	}
	addUnits := func(list []string, source string) {
		for _, u := range list {
			if _, ok := units[u]; !ok {
				units[u] = &Service{Unit: u, Source: source}
			}
		}
	}
	switch c.Manager {
	case pkgverify.RPM:
		if c.exists(dnfBin) {
			out, _, code, err := c.out(ctx, dnfBin, c.dnf("needs-restarting", "-s")...)
			if err == nil && code == 0 {
				rep.Tools["needs-restarting"] = true
				addUnits(ParseUnitList(out), "needs-restarting")
			}
		}
	case pkgverify.DPKG:
		if c.exists(needrestartBin) {
			out, _, _, err := c.out(ctx, needrestartBin, "-b", "-r", "l")
			if err == nil {
				nr := ParseNeedrestart(out)
				if nr.Version != "" {
					rep.Tools["needrestart"] = true
					addUnits(nr.Services, "needrestart")
					rep.Notes = map[string]string{"needrestart_kernel_status": strconv.Itoa(nr.KernelStatus),
						"needrestart_kernel_latest": nr.KernelLatest}
				}
			}
		}
	}
	for _, s := range units {
		sort.Ints(s.PIDs)
		rep.Services = append(rep.Services, *s)
	}
	sort.Slice(rep.Services, func(i, j int) bool { return rep.Services[i].Unit < rep.Services[j].Unit })
	sort.Slice(rep.Processes, func(i, j int) bool { return rep.Processes[i].PID < rep.Processes[j].PID })
}

func statusUID(b []byte) uint32 {
	for _, l := range strings.Split(string(b), "\n") {
		if v, ok := strings.CutPrefix(l, "Uid:"); ok {
			if f := strings.Fields(v); len(f) > 0 {
				n, _ := strconv.ParseUint(f[0], 10, 32)
				return uint32(n)
			}
		}
	}
	return 0
}

// collectReboot compara o kernel em uso com o mais novo instalado e soma o needs-restarting -r (RPM) ou o
// /run/reboot-required e o needrestart (Debian/Ubuntu).
func (c *Collector) collectReboot(ctx context.Context, rep *Report) {
	b, _ := os.ReadFile(filepath.Join(c.proc(), "sys", "kernel", "osrelease")) //nolint:gosec // procfs
	rb := Reboot{RunningKernel: strings.TrimSpace(string(b))}
	switch c.Manager {
	case pkgverify.RPM:
		out, _, _, err := c.out(ctx, rpmBin, "-q", "--whatprovides", "kernel", "--qf", `%{INSTALLTIME}\t%{VERSION}-%{RELEASE}.%{ARCH}\n`)
		if err == nil {
			rb.LatestKernel = latestRPMKernel(out)
		}
		if c.exists(dnfBin) {
			out, _, code, err := c.out(ctx, dnfBin, c.dnf("needs-restarting", "-r")...)
			if err == nil && (code == 0 || code == 1) {
				rb.Known = true
				if req, pkgs := NeedsRestartingReboot(out, code); req {
					rb.Required = true
					rb.Packages = pkgs
					rb.Reasons = append(rb.Reasons, "pacotes centrais atualizados depois do boot (needs-restarting)")
				}
			}
		}
	case pkgverify.DPKG:
		if c.exists("run/reboot-required") {
			rb.Known, rb.Required = true, true
			rb.Reasons = append(rb.Reasons, "o sistema marcou reinício necessário (/run/reboot-required)")
			if pk, err := os.ReadFile(c.root("run/reboot-required.pkgs")); err == nil {
				for _, l := range strings.Fields(string(pk)) {
					rb.Packages = appendUnique(rb.Packages, l)
				}
			}
		}
		rb.LatestKernel = c.latestBootKernel()
		if rep.Notes != nil {
			if st := rep.Notes["needrestart_kernel_status"]; st == "2" || st == "3" {
				rb.Known, rb.Required = true, true
				rb.Reasons = append(rb.Reasons, "o needrestart encontrou kernel mais novo instalado")
				if rb.LatestKernel == "" {
					rb.LatestKernel = rep.Notes["needrestart_kernel_latest"]
				}
			}
		}
	}
	if rb.LatestKernel != "" && rb.RunningKernel != "" {
		rb.Known = true
		if CompareKernel(rb.RunningKernel, rb.LatestKernel) < 0 {
			rb.Required = true
			rb.Reasons = append(rb.Reasons, "kernel mais novo instalado e ainda não carregado")
		}
	}
	rep.Reboot = rb
}

// latestRPMKernel escolhe o kernel instalado por último ("INSTALLTIME\tversão").
func latestRPMKernel(out []byte) string {
	best, bestT := "", int64(-1)
	for _, l := range strings.Split(string(bytes.TrimSpace(out)), "\n") {
		t, v, ok := strings.Cut(strings.TrimSpace(l), "\t")
		if !ok {
			continue
		}
		n, err := strconv.ParseInt(t, 10, 64)
		if err != nil {
			continue
		}
		if n > bestT || (n == bestT && CompareKernel(v, best) > 0) {
			best, bestT = v, n
		}
	}
	return best
}

// latestBootKernel devolve a versão do vmlinuz mais novo em /boot (vazio em contêiner).
func (c *Collector) latestBootKernel() string {
	files, _ := filepath.Glob(filepath.Join(c.rootDir(), "boot", "vmlinuz-*"))
	best := ""
	for _, f := range files {
		v := strings.TrimPrefix(filepath.Base(f), "vmlinuz-")
		if best == "" || CompareKernel(v, best) > 0 {
			best = v
		}
	}
	return best
}

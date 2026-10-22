package updates

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/guigallina27/vigiahost/internal/pkgverify"
	"github.com/guigallina27/vigiahost/internal/report"
)

func fixture(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", filepath.FromSlash(name)))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestSplitNEVRA(t *testing.T) {
	cases := map[string][3]string{
		"acl-2.4.0-1.el9_8.x86_64":                       {"acl", "2.4.0-1.el9_8", "x86_64"},
		"vim-common-2:8.2.2637-26.el9_8.23.x86_64":       {"vim-common", "2:8.2.2637-26.el9_8.23", "x86_64"},
		"openssh-9.9p1-13.el9_8.alma.1.x86_64":           {"openssh", "9.9p1-13.el9_8.alma.1", "x86_64"},
		"python-unversioned-command-3.9.25-7.el9.noarch": {"python-unversioned-command", "3.9.25-7.el9", "noarch"},
	}
	for in, want := range cases {
		n, evr, arch, ok := SplitNEVRA(in)
		if !ok || [3]string{n, evr, arch} != want {
			t.Errorf("%s → %s %s %s", in, n, evr, arch)
		}
	}
	if _, _, _, ok := SplitNEVRA("semponto"); ok {
		t.Error("entrada inválida aceita")
	}
}

func TestMergeRPMFixtures(t *testing.T) {
	adv := ParseUpdateinfo(fixture(t, "alma9/dnf-updateinfo-security.txt"))
	if len(adv) != 94 {
		t.Fatalf("avisos: %d", len(adv))
	}
	cves := ParseUpdateinfo(fixture(t, "alma9/dnf-updateinfo-security-cve.txt"))
	upd := ParseCheckUpdate(fixture(t, "alma9/dnf-check-update.txt"))
	if len(upd) != 49 || upd[0].Name != "acl" || upd[0].Arch != "x86_64" || upd[0].Available != "2.4.0-1.el9_8" || upd[0].Repo != "baseos" {
		t.Fatalf("check-update: %d %+v", len(upd), upd[0])
	}
	installed := ParseRPMInstalled([]byte("acl\tx86_64\t0\t2.3.1\t4.el9\nvim-common\tx86_64\t2\t8.2.2637\t20.el9_1\n"))
	sec, other := MergeRPM(upd, adv, cves, installed)
	if len(sec) != 42 || len(other) != 7 {
		t.Fatalf("segurança %d, outras %d", len(sec), len(other))
	}
	byName := map[string]Update{}
	for _, u := range append(append([]Update{}, sec...), other...) {
		byName[u.Name] = u
	}
	acl := byName["acl"]
	if !acl.Security || acl.Severity != SevImportant || acl.Installed != "2.3.1-4.el9" ||
		!slices.Equal(acl.Advisories, []string{"ALSA-2026:42736"}) || !slices.Equal(acl.CVEs, []string{"CVE-2026-54369", "CVE-2026-54370"}) {
		t.Fatalf("acl: %+v", acl)
	}
	vim := byName["vim-common"]
	if vim.Severity != SevImportant || len(vim.Advisories) != 6 || vim.Installed != "2:8.2.2637-20.el9_1" {
		t.Fatalf("vim-common: %+v", vim)
	}
	if tz := byName["tzdata"]; tz.Security || tz.Available != "2026e-1.el9_8" {
		t.Fatalf("tzdata não é correção de segurança: %+v", tz)
	}
	if sec[0].Severity != SevImportant {
		t.Fatalf("ordem por gravidade: %+v", sec[0])
	}
	counts := CountBySeverity(sec)
	if counts[SevImportant]+counts[SevModerate]+counts[SevLow] != 42 || counts[SevCritical] != 0 {
		t.Fatalf("contagem: %v", counts)
	}
}

func TestParseAptSimulateFixtures(t *testing.T) {
	sec, other := ParseAptSimulate(fixture(t, "debian/apt-s-ubuntu2404.txt"))
	if len(sec) != 1 || len(other) != 0 {
		t.Fatalf("ubuntu 24.04: %+v / %+v", sec, other)
	}
	z := sec[0]
	if z.Name != "zlib1g" || z.Installed != "1:1.3.dfsg-3.1ubuntu2.2" || z.Available != "1:1.3.dfsg-3.1ubuntu2.3" ||
		z.Arch != "amd64" || !strings.Contains(z.Repo, "noble-security") || z.Severity != SevUnknown {
		t.Fatalf("zlib1g: %+v", z)
	}
	sec, _ = ParseAptSimulate(fixture(t, "debian/apt-s-ubuntu2204.txt"))
	if len(sec) != 2 || sec[0].Name != "liblzma5" || sec[1].Name != "libudev1" {
		t.Fatalf("ubuntu 22.04: %+v", sec)
	}
	sec, other = ParseAptSimulate(fixture(t, "debian/apt-s-debian13.txt"))
	if len(sec) != 0 || len(other) != 1 || other[0].Name != "tzdata" || other[0].Arch != "all" {
		t.Fatalf("debian 13 (stable-updates não é segurança): %+v / %+v", sec, other)
	}
	sec, other = ParseAptSimulate(fixture(t, "debian/apt-s-debian12.txt"))
	if len(sec)+len(other) != 0 {
		t.Fatal("debian 12 em dia")
	}
	// Debian com a suíte de segurança.
	sec, _ = ParseAptSimulate([]byte("Inst openssl [3.0.15-1~deb12u1] (3.0.17-1~deb12u2 Debian-Security:12/oldstable-security [amd64])\n"))
	if len(sec) != 1 {
		t.Fatalf("Debian-Security: %+v", sec)
	}
}

func TestNeedsRestartingAndNeedrestart(t *testing.T) {
	req, pkgs := NeedsRestartingReboot(fixture(t, "alma9/dnf-needs-restarting-r-ok.txt"), 0)
	if req || len(pkgs) != 0 {
		t.Fatalf("sem reinício: %v %v", req, pkgs)
	}
	out := "Core libraries or services have been updated since boot-up:\n  * glibc\n  * kernel\n\nReboot is required to fully utilize these updates.\nMore information: https://access.redhat.com/solutions/27943\n"
	req, pkgs = NeedsRestartingReboot([]byte(out), 1)
	if !req || !slices.Equal(pkgs, []string{"glibc", "kernel"}) {
		t.Fatalf("com reinício: %v %v", req, pkgs)
	}
	units := ParseUnitList(fixture(t, "alma9/dnf-needs-restarting-s.txt"))
	if !slices.Equal(units, []string{"e22-sleep.service"}) {
		t.Fatalf("unidades: %v", units)
	}
	nr := ParseNeedrestart(fixture(t, "debian/needrestart-b-container.txt"))
	if nr.Version != "3.6" || nr.KernelStatus != 0 || len(nr.Services) != 0 {
		t.Fatalf("needrestart em contêiner: %+v", nr)
	}
	nr = ParseNeedrestart([]byte("NEEDRESTART-VER: 3.6\nNEEDRESTART-KCUR: 6.1.0-25-amd64\nNEEDRESTART-KEXP: 6.1.0-28-amd64\nNEEDRESTART-KSTA: 3\nNEEDRESTART-SVC: nginx.service\nNEEDRESTART-SVC: ssh.service\n"))
	if nr.KernelStatus != 3 || nr.KernelLatest != "6.1.0-28-amd64" || !slices.Equal(nr.Services, []string{"nginx.service", "ssh.service"}) {
		t.Fatalf("needrestart: %+v", nr)
	}
}

func TestDeletedMappingsFixtures(t *testing.T) {
	got := DeletedMappings(fixture(t, "alma9/proc-maps-deleted.txt"))
	if !slices.Equal(got, []string{"/usr/bin/sleep"}) {
		t.Fatalf("alma: %v", got)
	}
	got = DeletedMappings(fixture(t, "debian/proc-maps-deleted.txt"))
	if !slices.Equal(got, []string{"/usr/bin/sleep"}) {
		t.Fatalf("debian: %v", got)
	}
	// memfd, /dev/shm e locale apagados não são biblioteca de pacote.
	got = DeletedMappings([]byte("7f00-7f01 r-xp 0 00:01 9 /memfd:x (deleted)\n7f00-7f01 r--p 0 08:01 3 /dev/shm/y (deleted)\n" +
		"7f00-7f01 r--p 0 08:01 4 /usr/lib/locale/C.utf8/LC_CTYPE (deleted)\n7f00-7f01 r-xp 0 08:01 5 /usr/lib64/libssl.so.3 (deleted)\n"))
	if !slices.Equal(got, []string{"/usr/lib64/libssl.so.3"}) {
		t.Fatalf("filtro: %v", got)
	}
	if u := UnitFromCgroup(fixture(t, "alma9/proc-cgroup.txt")); u != "e22-sleep.service" {
		t.Fatalf("unidade: %q", u)
	}
}

func TestCompareKernel(t *testing.T) {
	if CompareKernel("5.14.0-570.el9.x86_64", "5.14.0-611.5.1.el9_7.x86_64") >= 0 {
		t.Error("570 < 611")
	}
	if CompareKernel("6.1.0-28-amd64", "6.1.0-28-amd64") != 0 || CompareKernel("6.8.0-50-generic", "6.8.0-45-generic") <= 0 {
		t.Error("comparação Debian/Ubuntu")
	}
}

type fakeRunner struct{ out map[string]string }

func (f fakeRunner) Run(_ context.Context, w io.Writer, name string, args ...string) (string, int, error) {
	key := strings.Join(append([]string{name}, args...), " ")
	for k, v := range f.out {
		if strings.Contains(key, k) {
			code := 0
			if strings.HasPrefix(v, "!") { // código de saída na frente: "!100\n..."
				first, rest, _ := strings.Cut(v, "\n")
				switch first {
				case "!100":
					code = 100
				case "!1":
					code = 1
				}
				v = rest
			}
			_, _ = io.WriteString(w, v)
			return "", code, nil
		}
	}
	return "erro simulado", 1, nil
}

func TestCollectRPMEndToEnd(t *testing.T) {
	root := t.TempDir()
	proc := filepath.Join(root, "proc")
	write := func(p, c string) {
		full := filepath.Join(root, filepath.FromSlash(p))
		_ = os.MkdirAll(filepath.Dir(full), 0o755)
		if err := os.WriteFile(full, []byte(c), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("usr/bin/dnf", "")
	write("var/cache/dnf/baseos-1/repodata/repomd.xml", "")
	old := time.Now().Add(-10 * 24 * time.Hour)
	_ = os.Chtimes(filepath.Join(root, "var/cache/dnf/baseos-1/repodata/repomd.xml"), old, old)
	write("proc/sys/kernel/osrelease", "5.14.0-570.el9.x86_64\n")
	write("proc/293/maps", string(fixture(t, "alma9/proc-maps-deleted.txt")))
	write("proc/293/cgroup", string(fixture(t, "alma9/proc-cgroup.txt")))
	write("proc/400/maps", "7f00-7f01 r-xp 0 08:01 5 /usr/lib64/libssl.so.3 (deleted)\n")
	write("proc/400/cgroup", "0::/user.slice/user-1000.slice/session-3.scope\n")
	write("proc/400/comm", "vim\n")
	write("proc/400/status", "Name:\tvim\nUid:\t1000\t1000\t1000\t1000\n")
	r := fakeRunner{out: map[string]string{
		"updateinfo list --security --with-cve": string(fixture(t, "alma9/dnf-updateinfo-security-cve.txt")),
		"updateinfo list --security":            string(fixture(t, "alma9/dnf-updateinfo-security.txt")),
		"check-update":                          "!100\n" + string(fixture(t, "alma9/dnf-check-update.txt")),
		"needs-restarting -s":                   string(fixture(t, "alma9/dnf-needs-restarting-s.txt")),
		"needs-restarting -r":                   "!1\nCore libraries or services have been updated since boot-up:\n  * kernel\n\nReboot is required to fully utilize these updates.\n",
		"--whatprovides kernel":                 "1760000000\t5.14.0-570.el9.x86_64\n1770000000\t5.14.0-611.5.1.el9_7.x86_64\n",
		"-qa --qf":                              "acl\tx86_64\t0\t2.3.1\t4.el9\n",
	}}
	c := &Collector{Manager: pkgverify.RPM, Runner: r, Root: root, Proc: proc, LogDir: "/run/x"}
	rep := c.Collect(context.Background())
	if rep.Error != "" || len(rep.Security) != 42 || rep.CacheUpdatedAt == nil {
		t.Fatalf("relatório: erro %q, segurança %d, cache %v", rep.Error, len(rep.Security), rep.CacheUpdatedAt)
	}
	if !rep.Reboot.Required || rep.Reboot.LatestKernel != "5.14.0-611.5.1.el9_7.x86_64" || len(rep.Reboot.Reasons) != 2 {
		t.Fatalf("reinício: %+v", rep.Reboot)
	}
	if len(rep.Services) != 1 || rep.Services[0].Unit != "e22-sleep.service" || rep.Services[0].Source != "maps" ||
		!slices.Equal(rep.Services[0].PIDs, []int{293}) {
		t.Fatalf("serviços: %+v", rep.Services)
	}
	if len(rep.Processes) != 1 || rep.Processes[0].Comm != "vim" || rep.Processes[0].UID != 1000 {
		t.Fatalf("processos: %+v", rep.Processes)
	}
	findings := Findings(rep, time.Now())
	sigs := map[string]report.Finding{}
	for _, f := range findings {
		sigs[f.Signature] = f
		if f.Subject == "" || f.Category != report.CategoryUpdate {
			t.Fatalf("achado sem identidade ou categoria: %+v", f)
		}
	}
	if f := sigs["atualizacao.correcoes_de_seguranca_pendentes"]; f.Severity != report.SeverityMedium || f.Evidence["quantidade"] != "42" {
		t.Fatalf("correções: %+v", f)
	}
	if _, ok := sigs["atualizacao.reinicio_pendente"]; !ok {
		t.Fatal("reinício pendente sem achado")
	}
	if _, ok := sigs["atualizacao.servicos_a_reiniciar"]; !ok {
		t.Fatal("serviço a reiniciar sem achado")
	}
	if f := sigs["atualizacao.lista_de_pacotes_antiga"]; f.Evidence["atualizada_ha"] != "10 dias" {
		t.Fatalf("cache antigo: %+v", f)
	}
}

func TestCollectAptWithoutCache(t *testing.T) {
	root := t.TempDir()
	_ = os.MkdirAll(filepath.Join(root, "usr", "bin"), 0o755)
	_ = os.WriteFile(filepath.Join(root, "usr", "bin", "apt-get"), nil, 0o644)
	_ = os.MkdirAll(filepath.Join(root, "run"), 0o755)
	_ = os.WriteFile(filepath.Join(root, "run", "reboot-required"), nil, 0o644)
	_ = os.WriteFile(filepath.Join(root, "run", "reboot-required.pkgs"), []byte("linux-image-6.8.0-50-generic\n"), 0o644)
	r := fakeRunner{out: map[string]string{"dist-upgrade": string(fixture(t, "debian/apt-s-ubuntu2204.txt"))}}
	c := &Collector{Manager: pkgverify.DPKG, Runner: r, Root: root, Proc: filepath.Join(root, "proc")}
	rep := c.Collect(context.Background())
	if len(rep.Security) != 2 || !rep.Reboot.Required || rep.Reboot.Packages[0] != "linux-image-6.8.0-50-generic" {
		t.Fatalf("%+v", rep)
	}
	sigs := map[string]report.Finding{}
	for _, f := range Findings(rep, time.Now()) {
		sigs[f.Signature] = f
	}
	if f := sigs["atualizacao.correcoes_de_seguranca_pendentes"]; f.Severity != report.SeverityMedium {
		t.Fatalf("APT sem gravidade vira médio: %+v", f)
	}
	if _, ok := sigs["atualizacao.lista_de_pacotes_ausente"]; !ok {
		t.Fatalf("sem lista baixada: %+v", sigs)
	}
}

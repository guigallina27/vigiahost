package pkgverify

import (
	"bytes"
	"context"
	"crypto/md5" //nolint:gosec // o dpkg registra MD5
	"encoding/hex"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

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

// fakeRunner responde a cada comando (nome + argumentos) com a saída gravada.
type fakeRunner struct {
	out   map[string]string
	errs  map[string]string
	codes map[string]int
	calls []string
}

func (f *fakeRunner) Run(_ context.Context, stdout io.Writer, name string, args ...string) (string, int, error) {
	key := strings.Join(append([]string{name}, args...), " ")
	f.calls = append(f.calls, key)
	for k, v := range f.out {
		if strings.HasPrefix(key, k) {
			_, _ = io.WriteString(stdout, v)
			return f.errs[k], f.codes[k], nil
		}
	}
	return "", 1, nil
}

func TestParseVerifyRPMFixture(t *testing.T) {
	issues, unparsed := ParseVerify(fixture(t, "alma9/rpm-Va.txt"), "rpm")
	if len(issues) != 11 {
		t.Fatalf("esperava 11 diferenças, veio %d: %+v", len(issues), issues)
	}
	if len(unparsed) != 1 || unparsed[0] != "rc=1" {
		t.Fatalf("linhas não reconhecidas: %q", unparsed)
	}
	byPath := map[string]Issue{}
	for _, is := range issues {
		byPath[is.Path] = is
	}
	tree := byPath["/usr/bin/tree"]
	if tree.Flags != "SM5....T." || !slices.Equal(tree.Changes, []string{ChangeSize, ChangeMode, ChangeDigest, ChangeMtime}) || tree.Config {
		t.Fatalf("binário alterado mal interpretado: %+v", tree)
	}
	if nano := byPath["/etc/nanorc"]; !nano.Config || !nano.ContentChanged() {
		t.Fatalf("configuração alterada mal interpretada: %+v", nano)
	}
	if doc := byPath["/usr/share/doc/tree/README"]; !doc.Doc || !doc.Has(ChangeMissing) {
		t.Fatalf("documentação ausente mal interpretada: %+v", doc)
	}
	if l := byPath["/usr/bin/rnano"]; !l.Has(ChangeLink) || len(l.Changes) != 1 {
		t.Fatalf("link alterado mal interpretado: %+v", l)
	}
	if g := byPath["/usr/libexec/openssh/ssh-keysign"]; !g.Has(ChangeGroup) || len(g.Changes) != 1 {
		t.Fatalf("grupo alterado mal interpretado: %+v", g)
	}
	if root := byPath["/"]; !root.Has(ChangeMode) {
		t.Fatalf("diretório raiz: %+v", root)
	}
}

func TestParseVerifyDpkgFixtures(t *testing.T) {
	issues, unparsed := ParseVerify(fixture(t, "debian12/dpkg-verify.txt"), "dpkg")
	if len(issues) != 3 || len(unparsed) != 1 {
		t.Fatalf("debian 12: %+v / %q", issues, unparsed)
	}
	if !issues[0].Config || issues[0].Path != "/etc/bash.bashrc" || !issues[0].Has(ChangeDigest) || issues[0].Has(ChangeSize) {
		t.Fatalf("configuração do dpkg (só o md5 é conferido, '?' não conta): %+v", issues[0])
	}
	if issues[2].Path != "/usr/share/doc/tree/README.gz" || !issues[2].Has(ChangeMissing) {
		t.Fatalf("ausente: %+v", issues[2])
	}
	// Ubuntu mínimo: o path-exclude apaga a documentação; nada disso pode virar achado.
	issues, _ = ParseVerify(fixture(t, "ubuntu2404/dpkg-verify-head.txt"), "dpkg")
	if len(issues) < 100 {
		t.Fatalf("ubuntu: %d linhas", len(issues))
	}
	for _, is := range issues {
		a := Assess(is, nil)
		if a.Signature != "" && a.Class != ClassConfig && a.Class != ClassConfigSensitive {
			t.Fatalf("ubuntu mínimo gerou achado fora de configuração: %+v → %+v", is, a)
		}
	}
}

func TestParseDebsums(t *testing.T) {
	issues, unparsed := ParseDebsums(string(fixture(t, "debian12/debsums-s.txt")))
	if len(issues) != 2 || len(unparsed) != 1 {
		t.Fatalf("%+v / %q", issues, unparsed)
	}
	if issues[0].Path != "/usr/bin/tree" || issues[0].Packages[0].Name != "tree" || !issues[0].Has(ChangeDigest) {
		t.Fatalf("alterado: %+v", issues[0])
	}
	if issues[1].Flags != "missing" || !issues[1].Has(ChangeMissing) {
		t.Fatalf("ausente: %+v", issues[1])
	}
	merged := mergeIssues([]Issue{{Path: "/usr/bin/tree", Changes: []string{ChangeDigest}, Source: "dpkg"}}, issues)
	if len(merged) != 2 || merged[0].Packages[0].Name != "tree" || merged[0].Source != "dpkg" {
		t.Fatalf("união dpkg + debsums: %+v", merged)
	}
}

func TestAssessSeverityTable(t *testing.T) {
	setuid := &FileState{Mode: fs.ModeSetuid | 0o755}
	cases := []struct {
		is       Issue
		st       *FileState
		sig      string
		sev      report.Severity
		ignored  string
		wantDesc bool
	}{
		{Issue{Path: "/usr/bin/tree", Changes: []string{ChangeSize, ChangeDigest}}, nil, "integridade.binario_alterado", report.SeverityHigh, "", true},
		{Issue{Path: "/usr/bin/ls", Changes: []string{ChangeDigest}}, nil, "integridade.binario_alterado", report.SeverityCritical, "", true},
		{Issue{Path: "/usr/sbin/sshd", Changes: []string{ChangeDigest}}, nil, "integridade.binario_alterado", report.SeverityCritical, "", true},
		{Issue{Path: "/usr/lib64/security/pam_unix.so", Changes: []string{ChangeDigest}}, nil, "integridade.modulo_pam_alterado", report.SeverityCritical, "", true},
		{Issue{Path: "/lib/x86_64-linux-gnu/security/pam_unix.so", Changes: []string{ChangeDigest}}, nil, "integridade.modulo_pam_alterado", report.SeverityCritical, "", true},
		{Issue{Path: "/usr/lib64/libssl.so.3.2.2", Changes: []string{ChangeDigest}}, nil, "integridade.biblioteca_alterada", report.SeverityHigh, "", true},
		{Issue{Path: "/usr/lib64/ld-linux-x86-64.so.2", Changes: []string{ChangeDigest}}, nil, "integridade.biblioteca_alterada", report.SeverityCritical, "", true},
		{Issue{Path: "/usr/lib/python3.9/site-packages/dnf/base.py", Changes: []string{ChangeDigest}}, nil, "integridade.biblioteca_alterada", report.SeverityHigh, "", true},
		{Issue{Path: "/usr/lib/modules/5.14.0/kernel/fs/ext4.ko.xz", Changes: []string{ChangeDigest}}, nil, "integridade.modulo_kernel_alterado", report.SeverityCritical, "", true},
		{Issue{Path: "/etc/nanorc", Config: true, Changes: []string{ChangeDigest}}, nil, "integridade.configuracao_alterada", report.SeverityInfo, "", true},
		{Issue{Path: "/etc/ssh/sshd_config", Config: true, Changes: []string{ChangeDigest}}, nil, "integridade.configuracao_alterada", report.SeverityLow, "", true},
		{Issue{Path: "/etc/hostname", Config: true, Changes: []string{ChangeMode}}, nil, "integridade.permissoes_alteradas", report.SeverityInfo, "", true},
		{Issue{Path: "/usr/bin/rnano", Changes: []string{ChangeLink}}, nil, "integridade.link_alterado", report.SeverityHigh, "", true},
		{Issue{Path: "/usr/libexec/openssh/ssh-keysign", Changes: []string{ChangeGroup}}, nil, "integridade.permissoes_alteradas", report.SeverityMedium, "", true},
		{Issue{Path: "/usr/bin/write", Changes: []string{ChangeMode}}, setuid, "integridade.permissoes_alteradas", report.SeverityHigh, "", true},
		// Caso real do laboratório: programa setgid que ficou com o grupo root (grupo perdido na importação).
		{Issue{Path: "/usr/bin/write", Changes: []string{ChangeGroup}}, &FileState{Mode: fs.ModeSetgid | 0o755}, "integridade.permissoes_alteradas", report.SeverityHigh, "", true},
		{Issue{Path: "/usr/bin/ping", Changes: []string{ChangeCaps}}, nil, "integridade.permissoes_alteradas", report.SeverityHigh, "", true},
		{Issue{Path: "/usr/bin/ping", Changes: []string{ChangeCaps}}, &FileState{Mode: 0o755, CapsKnown: true, Caps: true}, "integridade.permissoes_alteradas", report.SeverityHigh, "", true},
		// Rocky 10 em contêiner: a imagem perdeu as capacidades de arping e newuidmap (menos privilégio).
		{Issue{Path: "/usr/bin/arping", Changes: []string{ChangeCaps}}, &FileState{Mode: 0o755, CapsKnown: true}, "integridade.permissoes_alteradas", report.SeverityLow, "", true},
		{Issue{Path: "/var/cache/apt/archives", Changes: []string{ChangeMissing}}, nil, "integridade.arquivo_ausente", report.SeverityInfo, "", true},
		{Issue{Path: "/usr/bin/tree", Changes: []string{ChangeMissing}}, nil, "integridade.arquivo_ausente", report.SeverityMedium, "", true},
		{Issue{Path: "/usr/share/doc/tree/README", Doc: true, Changes: []string{ChangeMissing}}, nil, "", "", IgnoreDoc, false},
		{Issue{Path: "/usr/share/man/man1/tree.1.gz", Changes: []string{ChangeMissing}}, nil, "", "", IgnoreDoc, false},
		{Issue{Path: "/var/log/x", Ghost: true, Changes: []string{ChangeMissing}}, nil, "", "", IgnoreGhost, false},
		{Issue{Path: "/usr/bin/x", Changes: []string{ChangeMtime}}, nil, "", "", IgnoreMtimeOnly, false},
		{Issue{Path: "/", Changes: []string{ChangeMode}}, &FileState{Mode: fs.ModeDir | 0o555}, "", "", IgnoreDirectory, false},
		{Issue{Path: "/usr/bin/x"}, nil, "", "", IgnoreUnchecked, false},
	}
	for _, c := range cases {
		a := Assess(c.is, c.st)
		if a.Signature != c.sig || a.Severity != c.sev || a.Ignored != c.ignored || (a.Description != "") != c.wantDesc {
			t.Errorf("%s %v: veio %+v", c.is.Path, c.is.Changes, a)
		}
	}
}

func TestParseRPMSignaturesFixture(t *testing.T) {
	sigs := ParseRPMSignatures(fixture(t, "alma9/rpm-qa-sig.txt"))
	if len(sigs) != 319 {
		t.Fatalf("esperava 319 pacotes (sem o gpg-pubkey), veio %d", len(sigs))
	}
	keys := ParseRPMPubkeys(fixture(t, "alma9/rpm-gpg-pubkey.txt"))
	if len(keys) != 1 || keys[0].ID != "b86b3716" || !strings.Contains(keys[0].Summary, "AlmaLinux") {
		t.Fatalf("chaves: %+v", keys)
	}
	rep := SignatureReport{Keys: keys}
	classifyRPMSignatures(&rep, sigs)
	if rep.Signed != 317 || len(rep.Unsigned) != 2 || rep.Unsigned[0].Name != "clamav" || rep.Unsigned[1].Name != "vigiahost" {
		t.Fatalf("assinados %d, sem assinatura %+v", rep.Signed, rep.Unsigned)
	}
	// Pacote assinado por chave não importada.
	rep = SignatureReport{Keys: []Key{{ID: "00000000"}}}
	classifyRPMSignatures(&rep, sigs[:3])
	if len(rep.UnknownKey) != 3 || rep.UnknownKey[0].KeyID != "d36cb86cb86b3716" {
		t.Fatalf("chave desconhecida: %+v", rep.UnknownKey)
	}
	if rep.byPackage[sigs[0].Package.String()] != SigUnknownKey {
		t.Fatalf("situação por pacote: %v", rep.byPackage)
	}
}

func TestRPMOwnersBatchSplitsAmbiguousOutput(t *testing.T) {
	root := t.TempDir()
	for _, p := range []string{"usr/bin/ls", "usr/lib/.build-id", "etc/hostname"} {
		if err := os.MkdirAll(filepath.Join(root, filepath.Dir(p)), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(root, p), []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	f := &fakeRunner{out: map[string]string{
		// Lote com um caminho de dois donos: 4 linhas para 3 caminhos, o verificador divide o lote.
		rpmBin + " -qf --qf " + rpmPkgFormat + " -- /usr/bin/ls /usr/lib/.build-id /etc/hostname": "coreutils\t0\t8.32\t40.el9\tx86_64\ntree\t0\t1.8.0\t10.el9\tx86_64\nnano\t0\t5.6.1\t7.el9\tx86_64\nsystemd\t0\t252\t67.el9\tx86_64\n",
		rpmBin + " -qf --qf " + rpmPkgFormat + " -- /usr/bin/ls":                                  "coreutils\t0\t8.32\t40.el9\tx86_64\n",
		rpmBin + " -qf --qf " + rpmPkgFormat + " -- /usr/lib/.build-id /etc/hostname":             "tree\t0\t1.8.0\t10.el9\tx86_64\nnano\t0\t5.6.1\t7.el9\tx86_64\nsystemd\t0\t252\t67.el9\tx86_64\n",
		rpmBin + " -qf --qf " + rpmPkgFormat + " -- /usr/lib/.build-id":                           "tree\t0\t1.8.0\t10.el9\tx86_64\nnano\t0\t5.6.1\t7.el9\tx86_64\n",
		rpmBin + " -qf --qf " + rpmPkgFormat + " -- /etc/hostname":                                "systemd\t0\t252\t67.el9\tx86_64\n",
		// Arquivo apagado: vem da lista completa do banco.
		rpmBin + " -qa --qf [%{FILENAMES}": "/usr/bin/sumiu\tvim-common\t2\t8.2.2637\t26.el9_8.23\tx86_64\n/usr/bin/outro\tbash\t0\t5.1.8\t9.el9\tx86_64\n",
	}}
	v := &Verifier{Manager: RPM, Runner: f, Root: root}
	got, err := v.Owners(context.Background(), []string{"/usr/bin/ls", "/usr/lib/.build-id", "/etc/hostname", "/usr/bin/sumiu", "/naopertence"})
	if err != nil {
		t.Fatal(err)
	}
	if got["/usr/bin/ls"][0].String() != "coreutils-8.32-40.el9.x86_64" {
		t.Fatalf("ls: %+v", got["/usr/bin/ls"])
	}
	if len(got["/usr/lib/.build-id"]) != 2 || got["/etc/hostname"][0].Name != "systemd" {
		t.Fatalf("divisão do lote: %+v", got)
	}
	if got["/usr/bin/sumiu"][0].String() != "vim-common-2:8.2.2637-26.el9_8.23.x86_64" || got["/naopertence"] != nil {
		t.Fatalf("pela lista do banco: %+v", got)
	}
	calls := len(f.calls)
	if _, err := v.Owners(context.Background(), []string{"/usr/bin/ls"}); err != nil || len(f.calls) != calls {
		t.Fatalf("o cache deveria evitar nova consulta (%d → %d)", calls, len(f.calls))
	}
}

func TestRPMOwnersFixtureLines(t *testing.T) {
	// Saída real do rpm -qf (sem o formato próprio) não casa com o formato e vira "sem dono".
	for _, l := range splitLines(fixture(t, "alma9/rpm-qf.txt")) {
		if _, ok := ParseRPMPackageLine(l); ok {
			t.Fatalf("linha no formato padrão não deveria casar: %q", l)
		}
	}
	p, ok := ParseRPMPackageLine("vim-common\t2\t8.2.2637\t26.el9_8.23\tx86_64")
	if !ok || p.Version != "2:8.2.2637-26.el9_8.23" {
		t.Fatalf("%+v", p)
	}
}

// dpkgRoot monta um banco do dpkg mínimo com os arquivos reais do contêiner Debian 12.
func dpkgRoot(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	info := filepath.Join(root, "var", "lib", "dpkg", "info")
	if err := os.MkdirAll(info, 0o755); err != nil {
		t.Fatal(err)
	}
	status := string(fixture(t, "debian12/dpkg-status-bash.txt")) + "\nPackage: tree\nStatus: install ok installed\nArchitecture: amd64\nVersion: 2.1.0-1\n\nPackage: removido\nStatus: deinstall ok config-files\nArchitecture: amd64\nVersion: 1\n"
	files := map[string]string{
		"var/lib/dpkg/status":            status,
		"var/lib/dpkg/info/tree.list":    string(fixture(t, "debian12/tree.list")),
		"var/lib/dpkg/info/tree.md5sums": string(fixture(t, "debian12/tree.md5sums")),
		"var/lib/dpkg/info/bash.list":    "/.\n/bin\n/bin/bash\n/etc/bash.bashrc\n",
		"var/lib/dpkg/info/bash.md5sums": "",
	}
	for p, c := range files {
		if err := os.WriteFile(filepath.Join(root, filepath.FromSlash(p)), []byte(c), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

func TestDpkgOwnersAndUsrMerge(t *testing.T) {
	v := &Verifier{Manager: DPKG, Root: dpkgRoot(t)}
	got, err := v.Owners(context.Background(), []string{"/usr/bin/tree", "/usr/bin/bash", "/etc/bash.bashrc", "/usr/bin/naoexiste"})
	if err != nil {
		t.Fatal(err)
	}
	if got["/usr/bin/tree"][0] != (Package{Name: "tree", Version: "2.1.0-1", Arch: "amd64"}) {
		t.Fatalf("tree: %+v", got["/usr/bin/tree"])
	}
	// O banco do Debian 12 registra /bin/bash; o processo mostra /usr/bin/bash.
	if len(got["/usr/bin/bash"]) != 1 || got["/usr/bin/bash"][0].Version != "5.2.15-2+b13" {
		t.Fatalf("/usr unificado: %+v", got["/usr/bin/bash"])
	}
	if got["/usr/bin/naoexiste"] != nil {
		t.Fatalf("sem dono: %+v", got["/usr/bin/naoexiste"])
	}
	if n := v.PackageCount(context.Background()); n != 2 {
		t.Fatalf("pacotes instalados: %d", n)
	}
}

func TestCheckFilesDpkg(t *testing.T) {
	root := dpkgRoot(t)
	write := func(p, c string) {
		full := filepath.Join(root, filepath.FromSlash(p))
		_ = os.MkdirAll(filepath.Dir(full), 0o755)
		if err := os.WriteFile(full, []byte(c), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	// O md5sums real do tree não confere com este conteúdo; a configuração confere com o md5 do status.
	write("usr/bin/tree", "binário trocado")
	bashrc := "conteúdo original"
	sum := md5.Sum([]byte(bashrc)) //nolint:gosec // igual ao dpkg
	status, _ := os.ReadFile(filepath.Join(root, "var", "lib", "dpkg", "status"))
	status = bytes.Replace(status, []byte("89269e1298235f1b12b4c16e4065ad0d"), []byte(hex.EncodeToString(sum[:])), 1)
	write("var/lib/dpkg/status", string(status))
	write("etc/bash.bashrc", bashrc)
	write("opt/solto", "x")

	v := &Verifier{Manager: DPKG, Root: root}
	got, err := v.CheckFiles(context.Background(), []string{"/usr/bin/tree", "/etc/bash.bashrc", "/usr/share/doc/tree/README.gz", "/opt/solto"})
	if err != nil {
		t.Fatal(err)
	}
	tree := got["/usr/bin/tree"]
	if tree.Status != StatusMismatch || tree.Algo != "md5" || tree.Expected != "6050710ac1dcb11cfeec58da39685dd9" || len(tree.SHA256) != 64 {
		t.Fatalf("binário trocado: %+v", tree)
	}
	if c := got["/etc/bash.bashrc"]; c.Status != StatusMatch || !c.Config {
		t.Fatalf("configuração: %+v", c)
	}
	if m := got["/usr/share/doc/tree/README.gz"]; m.Status != StatusMissing {
		t.Fatalf("ausente: %+v", m)
	}
	if n := got["/opt/solto"]; n.Status != StatusNotOwned || n.SHA256 == "" {
		t.Fatalf("fora de pacote: %+v", n)
	}
}

func TestCheckFilesRPM(t *testing.T) {
	root := t.TempDir()
	_ = os.MkdirAll(filepath.Join(root, "usr", "bin"), 0o755)
	if err := os.WriteFile(filepath.Join(root, "usr", "bin", "tree"), []byte("abc"), 0o755); err != nil {
		t.Fatal(err)
	}
	// SHA-256 de "abc".
	const abc = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
	f := &fakeRunner{out: map[string]string{
		rpmBin + " -qf --qf " + rpmPkgFormat + " -- /usr/bin/tree": "tree\t0\t1.8.0\t10.el9\tx86_64\n",
		rpmBin + " -q --qf " + rpmDigestFormat + " -- tree-1.8.0-10.el9.x86_64": "tree\t0\t1.8.0\t10.el9\tx86_64\t8\t/usr/bin/tree\t" + strings.ToUpper(abc) + "\t0\n" +
			"tree\t0\t1.8.0\t10.el9\tx86_64\t8\t/usr/lib/.build-id\t\t0\n",
		rpmBin + " -qa --qf " + rpmSigFormat: "tree\t0\t1.8.0\t10.el9\tx86_64\t(none)\t(none)\t(none)\t(none)\n",
		rpmBin + " -q gpg-pubkey":            "b86b3716\t61e69f29\tAlmaLinux OS 9 public key\n",
	}}
	v := &Verifier{Manager: RPM, Runner: f, Root: root}
	got, err := v.CheckFiles(context.Background(), []string{"/usr/bin/tree"})
	if err != nil {
		t.Fatal(err)
	}
	c := got["/usr/bin/tree"]
	if c.Status != StatusMatch || c.Algo != "sha256" || c.Actual != abc || c.Signature != SigUnsigned {
		t.Fatalf("%+v (chamadas %q)", c, f.calls)
	}
}

func TestRPMReposAndAptSources(t *testing.T) {
	root := t.TempDir()
	write := func(p, c string) {
		full := filepath.Join(root, filepath.FromSlash(p))
		_ = os.MkdirAll(filepath.Dir(full), 0o755)
		if err := os.WriteFile(full, []byte(c), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("etc/dnf/dnf.conf", "[main]\ngpgcheck=1\n")
	write("etc/yum.repos.d/a.repo", "[baseos]\nname=BaseOS\ngpgcheck=1\n\n[terceiro]\nname=Terceiro\nbaseurl=https://u:senha@x/\ngpgcheck=0\n\n[desligado]\nenabled=0\ngpgcheck=0\n\n[padrao]\nname=Herda\n")
	repos := RPMRepos(root)
	got := map[string]Repo{}
	for _, r := range repos {
		got[r.ID] = r
	}
	if got["terceiro"].Problem != RepoGPGCheckOff || got["baseos"].Problem != "" || got["desligado"].Problem != "" || !got["padrao"].Verified {
		t.Fatalf("repositórios RPM: %+v", repos)
	}

	write("etc/apt/sources.list.d/debian.sources", string(fixture(t, "debian12/apt-sources.txt")))
	write("etc/apt/sources.list.d/extra.list", "deb [trusted=yes] http://user:segredo@repo.exemplo/apt stable main\n# deb http://comentado/ x main\ndeb http://semassinatura.exemplo/debian bookworm main\n")
	write("etc/apt/apt.conf.d/99inseguro", "APT::Get::AllowUnauthenticated \"true\";\n")
	write("var/lib/apt/lists/deb.debian.org_debian_dists_bookworm_InRelease", "")
	write("var/lib/apt/lists/semassinatura.exemplo_debian_dists_bookworm_Release", "")
	apt := AptRepos(root)
	byID := map[string]Repo{}
	for _, r := range apt {
		byID[r.ID] = r
		if strings.Contains(r.ID, "segredo") {
			t.Fatalf("credencial da URI vazou no relatório: %+v", r)
		}
	}
	if r := byID["http://deb.debian.org/debian bookworm"]; !r.Verified || r.Problem != "" || r.File != "/etc/apt/sources.list.d/debian.sources" {
		t.Fatalf("fonte deb822: %+v", apt)
	}
	if r := byID["http://repo.exemplo/apt stable"]; r.Problem != RepoTrusted || r.Verified {
		t.Fatalf("trusted=yes: %+v", apt)
	}
	if r := byID["http://semassinatura.exemplo/debian bookworm"]; r.Problem != RepoUnsignedList {
		t.Fatalf("lista sem assinatura: %+v", apt)
	}
	if !strings.Contains(apt[len(apt)-1].ID, "AllowUnauthenticated") || apt[len(apt)-1].Problem != RepoAptConfInsecure {
		t.Fatalf("apt.conf inseguro: %+v", apt[len(apt)-1])
	}
	// Fonte deb822 real do Ubuntu 24.04 (com comentários longos antes das estrofes).
	f, _ := os.Open(filepath.Join("testdata", "ubuntu2404", "apt-sources.txt"))
	defer f.Close()
	ub := ParseAptDeb822(f, "/etc/apt/sources.list.d/ubuntu.sources")
	if len(ub) != 4 || ub[3].Suite != "noble-security" {
		t.Fatalf("ubuntu.sources: %+v", ub)
	}
}

func TestVerifyDpkgWithDebsumsAttribution(t *testing.T) {
	root := dpkgRoot(t)
	f := &fakeRunner{out: map[string]string{dpkgBin + " --verify": string(fixture(t, "debian12/dpkg-verify.txt"))}}
	v := &Verifier{Manager: DPKG, Runner: f, Root: root}
	res, err := v.Verify(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Issues) != 3 || res.Tools[0] != "dpkg --verify" {
		t.Fatalf("%+v", res)
	}
	for _, is := range res.Issues {
		if len(is.Packages) == 0 {
			t.Fatalf("sem dono: %+v", is)
		}
	}
}

func TestDetect(t *testing.T) {
	root := t.TempDir()
	if Detect(root) != ManagerNone {
		t.Fatal("raiz vazia")
	}
	for _, p := range []string{"usr/bin/rpm", "var/lib/rpm/rpmdb.sqlite"} {
		_ = os.MkdirAll(filepath.Join(root, filepath.Dir(p)), 0o755)
		_ = os.WriteFile(filepath.Join(root, p), nil, 0o644)
	}
	if Detect(root) != RPM {
		t.Fatal("rpm")
	}
	for _, p := range []string{"usr/bin/dpkg-query", "var/lib/dpkg/status", "etc/debian_version"} {
		_ = os.MkdirAll(filepath.Join(root, filepath.Dir(p)), 0o755)
		_ = os.WriteFile(filepath.Join(root, p), nil, 0o644)
	}
	if Detect(root) != DPKG {
		t.Fatal("Debian com rpm instalado vale o dpkg")
	}
}

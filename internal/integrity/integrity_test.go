package integrity

import (
	"io/fs"
	"os"
	"path/filepath"
	"testing"

	"github.com/guigallina27/vigiahost/internal/pkgverify"
	"github.com/guigallina27/vigiahost/internal/report"
)

func TestFindingsFromRealRpmVa(t *testing.T) {
	b, err := os.ReadFile(filepath.Join("..", "pkgverify", "testdata", "alma9", "rpm-Va.txt"))
	if err != nil {
		t.Fatal(err)
	}
	issues, _ := pkgverify.ParseVerify(b, "rpm")
	pkg := pkgverify.Package{Name: "tree", Version: "1.8.0-10.el9", Arch: "x86_64"}
	for i := range issues {
		if issues[i].Path == "/usr/bin/tree" {
			issues[i].Packages = []pkgverify.Package{pkg}
		}
	}
	stat := func(p string) (*report.Location, *pkgverify.FileState) {
		switch p {
		case "/":
			return &report.Location{Path: p}, &pkgverify.FileState{Mode: fs.ModeDir | 0o555}
		case "/usr/share/doc/tree/README":
			return nil, nil
		}
		return &report.Location{Path: p, Size: 10}, &pkgverify.FileState{Mode: 0o755}
	}
	list, ignored := AssessAll(issues, stat)
	if ignored[pkgverify.IgnoreDirectory] != 1 || ignored[pkgverify.IgnoreDoc] != 1 {
		t.Fatalf("ignorados: %v", ignored)
	}
	if paths := DigestPaths(list); len(paths) != 2 || paths[0] != "/etc/nanorc" || paths[1] != "/usr/bin/tree" {
		t.Fatalf("conferência de resumo: %v", paths)
	}
	checks := map[string]pkgverify.FileCheck{"/usr/bin/tree": {Path: "/usr/bin/tree", Status: pkgverify.StatusMismatch,
		Algo: "sha256", Expected: "aa", Actual: "bb", SHA256: "bb"}}
	findings, files := FileFindings(pkgverify.RPM, list, checks)
	if len(findings) != len(list) || len(files) != 9 {
		t.Fatalf("achados %d, linhas %d", len(findings), len(files))
	}
	var tree report.Finding
	for _, f := range findings {
		if f.Category != report.CategoryIntegrity || f.Engine != Engine || f.Location == nil {
			t.Fatalf("achado fora do padrão: %+v", f)
		}
		if f.Location.Path == "/usr/bin/tree" {
			tree = f
		}
	}
	if tree.Signature != "integridade.binario_alterado" || tree.Severity != report.SeverityHigh || tree.SHA256 != "bb" ||
		tree.Evidence["pacote"] != "tree-1.8.0-10.el9.x86_64" || tree.Evidence["resumo_esperado"] != "sha256:aa" {
		t.Fatalf("tree: %+v", tree)
	}
	if files[0].Path != "/usr/bin/rnano" && files[0].Path != "/usr/bin/tree" {
		t.Fatalf("ordem por gravidade: %+v", files[0])
	}
	if c := CountSeverity(files); c[report.SeverityHigh] != 2 || c[report.SeverityMedium] != 4 || c[report.SeverityInfo] != 3 {
		t.Fatalf("contagem: %v", c)
	}
}

func TestSignatureFindings(t *testing.T) {
	sig := pkgverify.SignatureReport{Manager: pkgverify.RPM,
		Unsigned:   []pkgverify.Package{{Name: "clamav", Version: "1.4.6-1", Arch: "x86_64"}, {Name: "vigiahost", Version: "0.1.7-1"}},
		UnknownKey: []pkgverify.KeyedPackage{{Package: pkgverify.Package{Name: "x"}, KeyID: "abcd"}},
		Repos: []pkgverify.Repo{{ID: "baseos", Verified: true}, {ID: "terceiro", Problem: pkgverify.RepoGPGCheckOff},
			{ID: "AllowUnauthenticated em /etc/apt/apt.conf.d/99x", Problem: pkgverify.RepoAptConfInsecure}}}
	got := SignatureFindings(sig)
	if len(got) != 4 {
		t.Fatalf("%+v", got)
	}
	want := []struct {
		sig, subject string
		sev          report.Severity
	}{
		{"integridade.pacotes_sem_assinatura", "pacotes-sem-assinatura", report.SeverityLow},
		{"integridade.pacotes_chave_desconhecida", "pacotes-chave-desconhecida", report.SeverityMedium},
		{"integridade.repositorio_sem_verificacao", "repo:terceiro", report.SeverityMedium},
		{"integridade.apt_sem_autenticacao", "apt-conf", report.SeverityHigh},
	}
	for i, w := range want {
		if got[i].Signature != w.sig || got[i].Subject != w.subject || got[i].Severity != w.sev || got[i].Location != nil {
			t.Fatalf("%d: %+v", i, got[i])
		}
	}
	if got[0].Evidence["pacotes"] != "clamav-1.4.6-1.x86_64, vigiahost-0.1.7-1" {
		t.Fatalf("lista: %q", got[0].Evidence["pacotes"])
	}
}

package store

import (
	"context"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/guigallina27/vigiahost/internal/report"
)

func TestAtribuicaoDeAchadosEExecucoesPorConta(t *testing.T) {
	ctx := context.Background()
	db, now := openTest(t)
	// Execução da conta ana (1001) e, depois, de ana e bia (1002) juntas.
	if err := db.InsertRun(ctx, &Run{ID: "r1", Kind: report.KindFiles, Origin: "manual", Paths: []string{"/home/ana", "/tmp"},
		Accounts: []uint32{1001}, Owners: map[string][]uint32{"/tmp": {1001}}}); err != nil {
		t.Fatal(err)
	}
	*now = now.Add(time.Minute)
	if err := db.InsertRun(ctx, &Run{ID: "r2", Kind: report.KindFiles, Origin: "manual", Paths: []string{"/home/ana", "/home/bia"},
		Accounts: []uint32{1001, 1002}}); err != nil {
		t.Fatal(err)
	}
	r1, _ := db.GetRun(ctx, "r1")
	if !slices.Equal(r1.Accounts, []uint32{1001}) || !slices.Equal(r1.Owners["/tmp"], []uint32{1001}) {
		t.Fatalf("contas e donos da execução: %+v %+v", r1.Accounts, r1.Owners)
	}
	latest, err := db.LatestRunsByAccount(ctx)
	if err != nil || latest[1001].ID != "r2" || latest[1002].ID != "r2" || len(latest) != 2 {
		t.Fatalf("última execução por conta: %+v %v", latest, err)
	}
	ana := uint32(1001)
	runs, _ := db.ListRuns(ctx, RunFilter{Account: &ana})
	if len(runs) != 2 {
		t.Fatalf("execuções da conta ana: %d", len(runs))
	}

	shaB := strings.Repeat("b", 64)
	// Arquivo de ana; arquivo de root dentro do diretório de bia; processo de bia; persistência de ana; arquivo de
	// outra conta (cris, 1003) num diretório parecido com o de ana ("/home/ana2").
	own := webshell("/home/ana/public_html/up.php", shaA)
	own.Location.UID = 1001
	rootInBia := webshell("/home/bia/www/x.php", shaB)
	proc := report.Finding{Engine: "inspector", Signature: "processo.memfd", Category: report.CategoryProcess,
		Severity: report.SeverityCritical, Process: &report.ProcessEvidence{PID: 42, UID: 1002, Comm: "x"}}
	pers := report.Finding{Engine: "inspector", Signature: "persistencia.cron", Category: report.CategoryPersistence,
		Severity: report.SeverityMedium, Persistence: &report.PersistenceEntry{Kind: "cron", Path: "/var/spool/cron/ana", Owner: "ana"}}
	other := webshell("/home/ana2/up.php", strings.Repeat("c", 64))
	other.Location.UID = 1003
	if _, err := db.IngestFindings(ctx, "r2", []report.Finding{own, rootInBia, proc, pers, other}, 10); err != nil {
		t.Fatal(err)
	}

	count := func(scope AccountScope) int {
		t.Helper()
		list, err := db.ListFindings(ctx, FindingFilter{Account: &scope})
		if err != nil {
			t.Fatal(err)
		}
		return len(list)
	}
	if n := count(AccountScope{UID: 1001, Home: "/home/ana", Name: "ana"}); n != 2 {
		t.Fatalf("achados de ana (arquivo + persistência, sem /home/ana2): %d", n)
	}
	if n := count(AccountScope{UID: 1002, Home: "/home/bia/", Name: "bia"}); n != 2 {
		t.Fatalf("achados de bia (arquivo no diretório pessoal + processo): %d", n)
	}
	if n := count(AccountScope{UID: 1004, Home: "/home/dan", Name: "dan"}); n != 0 {
		t.Fatalf("conta sem achados: %d", n)
	}

	refs, err := db.OpenFindingRefs(ctx)
	if err != nil || len(refs) != 5 {
		t.Fatalf("referências dos achados abertos: %d %v", len(refs), err)
	}
	for _, r := range refs {
		if r.Severity == "critical" && !slices.Contains(r.UIDs, 1002) {
			t.Fatalf("processo sem o UID: %+v", r)
		}
		if r.Severity == "medium" && !slices.Contains(r.Owners, "ana") {
			t.Fatalf("persistência sem o dono: %+v", r)
		}
	}
}

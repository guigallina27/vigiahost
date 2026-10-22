package core

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"

	"github.com/guigallina27/vigiahost/internal/api"
	"github.com/guigallina27/vigiahost/internal/inspect"
	"github.com/guigallina27/vigiahost/internal/integrity"
	"github.com/guigallina27/vigiahost/internal/pkgverify"
	"github.com/guigallina27/vigiahost/internal/report"
	"github.com/guigallina27/vigiahost/internal/store"
	"github.com/guigallina27/vigiahost/internal/updates"
)

func TestVerificacoesDoSistemaPelaAPI(t *testing.T) {
	a := newTestAPI(t)
	ctx := context.Background()
	reader := a.sessionFor(t, store.RoleReader, false)
	for _, path := range []string{"/api/v1/integrity", "/api/v1/updates"} {
		if rec := a.do(t, "GET", path, "", reader, ""); rec.Code != http.StatusNotFound {
			t.Fatalf("%s sem relatório: %d", path, rec.Code)
		}
	}

	// O operador pede as verificações; o leitor não.
	if rec := a.do(t, "POST", "/api/v1/runs", `{"kind":"integrity"}`, reader, ""); rec.Code != http.StatusForbidden {
		t.Fatalf("leitor pediu verificação: %d", rec.Code)
	}
	op := a.sessionFor(t, store.RoleOperator, false)
	for _, kind := range []string{"integrity", "updates"} {
		rec := a.do(t, "POST", "/api/v1/runs", `{"kind":"`+kind+`"}`, op, "")
		if run := decodeBody[api.Run](t, rec); rec.Code >= 300 || string(run.Kind) != kind || len(run.Paths) != 0 {
			t.Fatalf("%s: %d %+v", kind, rec.Code, run)
		}
	}
	if rec := a.do(t, "POST", "/api/v1/runs", `{"kind":"updates","paths":["/etc"]}`, op, ""); rec.Code != http.StatusBadRequest {
		t.Fatalf("verificação do sistema com caminhos: %d", rec.Code)
	}
	admin := a.sessionFor(t, store.RoleAdmin, true)
	rec := a.do(t, "POST", "/api/v1/schedules", `{"name":"correções","kind":"updates","cron":"0 6 * * *","paths":["/srv"]}`, admin, "")
	if sc := decodeBody[api.Schedule](t, rec); rec.Code >= 300 || sc.Kind != api.RunKind("updates") || len(sc.Paths) != 0 {
		t.Fatalf("agendamento: %d %+v", rec.Code, sc)
	}

	for _, id := range []string{"i1", "u1", "p1"} {
		kind := map[string]report.Kind{"i1": report.KindIntegrity, "u1": report.KindUpdates, "p1": report.KindProcesses}[id]
		if err := a.db.InsertRun(ctx, &store.Run{ID: id, Kind: kind, Origin: "manual"}); err != nil {
			t.Fatal(err)
		}
	}
	irep := integrity.Report{Manager: pkgverify.RPM, Packages: 319, Differences: 3,
		Files: []integrity.FileResult{{Path: "/usr/bin/tree", Flags: "S.5....T.", Changes: []string{"size", "digest", "mtime"},
			Class: pkgverify.ClassBinary, Severity: report.SeverityHigh, Signature: "integridade.binario_alterado",
			Packages: []pkgverify.Package{{Name: "tree", Version: "1.8.0-10.el9", Arch: "x86_64"}}}},
		Signatures: &pkgverify.SignatureReport{Manager: pkgverify.RPM, Method: "package", Signed: 317,
			Unsigned: []pkgverify.Package{{Name: "clamav", Version: "1.4.6-1"}}}}
	urep := updates.Report{Manager: "rpm", Security: []updates.Update{{Name: "openssl", Available: "3.5.1-4.el9_7", Security: true,
		Severity: "important", Advisories: []string{"ALSA-2026:1234"}}}, Reboot: updates.Reboot{Known: true, Required: true,
		RunningKernel: "5.14.0-570.el9.x86_64", LatestKernel: "5.14.0-611.el9.x86_64"}}
	hrep := inspect.HiddenReport{Ports: inspect.HiddenPorts{Checked: true, Probed: 130000,
		Found: []inspect.HiddenPort{{PortKey: inspect.PortKey{Proto: "tcp", Port: 31337}, Reason: inspect.PortBindOnly}}}}
	for name, v := range map[string]struct {
		run string
		rep any
	}{store.HostReportIntegrity: {"i1", irep}, store.HostReportUpdates: {"u1", urep}, store.HostReportHidden: {"p1", hrep}} {
		b, _ := json.Marshal(v.rep)
		if err := a.db.SaveHostReport(ctx, store.HostReport{RunID: v.run, Name: name, TakenAt: *a.now, Data: b}); err != nil {
			t.Fatal(err)
		}
	}
	if err := a.db.SaveSnapshot(ctx, store.Snapshot{RunID: "p1", TakenAt: *a.now, Processes: []byte(`[{"pid":1,"ppid":0,"uid":0,"comm":"systemd","exe":"/usr/lib/systemd/systemd","package":"systemd","package_status":"match","cpu_percent":0,"rss_bytes":1,"threads":1}]`),
		Persistence: []byte(`{"baseline":true,"items":[]}`)}); err != nil {
		t.Fatal(err)
	}

	rec = a.do(t, "GET", "/api/v1/integrity", "", reader, "")
	ig := decodeBody[api.IntegrityReport](t, rec)
	if rec.Code != http.StatusOK || ig.RunId != "i1" || len(ig.Runs) != 1 || len(ig.Files) != 1 || ig.Files[0].Class != api.Binary ||
		ig.Signatures == nil || ig.Signatures.Repos == nil || len(*ig.Signatures.Unsigned) != 1 || ig.Ignored == nil {
		t.Fatalf("integridade: %d %+v", rec.Code, ig)
	}
	rec = a.do(t, "GET", "/api/v1/updates?run_id=u1", "", reader, "")
	up := decodeBody[api.UpdatesReport](t, rec)
	if rec.Code != http.StatusOK || len(up.Security) != 1 || up.Other == nil || !up.Reboot.Required || up.Services == nil {
		t.Fatalf("atualizações: %d %+v", rec.Code, up)
	}
	if rec = a.do(t, "GET", "/api/v1/updates?run_id=nao-existe", "", reader, ""); rec.Code != http.StatusNotFound {
		t.Fatalf("execução sem relatório: %d", rec.Code)
	}
	rec = a.do(t, "GET", "/api/v1/inventory/processes", "", reader, "")
	inv := decodeBody[api.ProcessInventory](t, rec)
	if rec.Code != http.StatusOK || inv.Hidden == nil || len(inv.Hidden.Ports.Found) != 1 || inv.Hidden.Processes.Found == nil ||
		inv.Processes[0].PackageStatus == nil || *inv.Processes[0].PackageStatus != api.Match {
		t.Fatalf("processos: %d %+v", rec.Code, inv)
	}

	// Achado do sistema aparece com o assunto na lista.
	if _, err := a.db.IngestFindings(ctx, "u1", []report.Finding{{Engine: "updates", Signature: "atualizacao.reinicio_pendente",
		Category: report.CategoryUpdate, Severity: report.SeverityMedium, Subject: "reboot"}}, 1); err != nil {
		t.Fatal(err)
	}
	rec = a.do(t, "GET", "/api/v1/findings?kind=system", "", reader, "")
	page := decodeBody[api.FindingPage](t, rec)
	if len(page.Findings) != 1 || page.Findings[0].Kind != api.FindingKindSystem || page.Findings[0].Subject == nil {
		t.Fatalf("achado do sistema: %d %+v", rec.Code, page)
	}
}

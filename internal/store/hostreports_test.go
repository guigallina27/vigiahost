package store

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/guigallina27/vigiahost/internal/report"
)

func TestTiposNovosDeExecucaoEAgendamento(t *testing.T) {
	ctx := context.Background()
	db, _ := openTest(t)
	for _, k := range []report.Kind{report.KindIntegrity, report.KindUpdates} {
		if err := db.InsertRun(ctx, &Run{ID: "r-" + string(k), Kind: k, Origin: "manual"}); err != nil {
			t.Fatalf("%s: %v", k, err)
		}
		s := &Schedule{Name: string(k), Kind: k, Cron: "0 3 * * *", Timezone: "UTC", Profile: "padrao", MissedPolicy: "run_once", Enabled: true}
		if err := db.SaveSchedule(ctx, s); err != nil {
			t.Fatalf("agendamento %s: %v", k, err)
		}
	}
	// O banco ainda recusa o que não é um nome de tipo.
	for _, bad := range []string{"", "Files", "files;drop", strings.Repeat("x", 40)} {
		if _, err := db.ExecContext(ctx, `INSERT INTO runs (id, kind, status, origin, created_at) VALUES (?, ?, 'queued', 'manual', 'x')`,
			"bad-"+bad, bad); err == nil {
			t.Errorf("tipo %q aceito", bad)
		}
	}
}

func TestAchadosDoSistemaPorAssuntoEResolucao(t *testing.T) {
	ctx := context.Background()
	db, now := openTest(t)
	sec := func(n string) report.Finding {
		return report.Finding{Engine: "updates", Signature: "atualizacao.correcoes_de_seguranca_pendentes",
			Category: report.CategoryUpdate, Severity: report.SeverityMedium, Subject: "security-updates",
			Description: n + " correções", Evidence: map[string]string{"pacotes": n}}
	}
	repo := report.Finding{Engine: "updates", Signature: "atualizacao.servicos_a_reiniciar", Category: report.CategoryUpdate,
		Severity: report.SeverityLow, Subject: "services"}
	for _, id := range []string{"u1", "u2", "u3"} {
		if err := db.InsertRun(ctx, &Run{ID: id, Kind: report.KindUpdates, Origin: "manual"}); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := db.IngestFindings(ctx, "u1", []report.Finding{sec("42"), repo}, 10); err != nil {
		t.Fatal(err)
	}
	*now = now.Add(time.Hour)
	res, err := db.IngestFindings(ctx, "u2", []report.Finding{sec("40")}, 10)
	if err != nil || res.New != 0 || res.Seen != 1 {
		t.Fatalf("mesmo assunto deveria ser o mesmo achado: %+v %v", res, err)
	}
	list, err := db.ListFindings(ctx, FindingFilter{Kinds: []string{KindSystem}})
	if err != nil || len(list) != 2 {
		t.Fatalf("achados do sistema: %d %v", len(list), err)
	}
	var cur Finding
	for _, f := range list {
		if f.Subject == "security-updates" {
			cur = f
		}
	}
	// A evidência acompanha a execução mais recente.
	if cur.Evidence["pacotes"] != "40" || cur.Description != "40 correções" || cur.Location != nil {
		t.Fatalf("evidência atual: %+v", cur)
	}
	if found, _ := db.ListFindings(ctx, FindingFilter{Query: "security-up"}); len(found) != 1 {
		t.Fatalf("busca pelo assunto: %d", len(found))
	}
	// Serviços a reiniciar sumiu na u2: resolvido; as correções continuam abertas.
	n, err := db.ResolveMissing(ctx, "u2", "updates")
	if err != nil || n != 1 {
		t.Fatalf("resolvidos: %d %v", n, err)
	}
	got, _ := db.GetFinding(ctx, cur.ID)
	if got.State != StateNew {
		t.Fatalf("achado presente foi resolvido: %s", got.State)
	}
	// Volta a aparecer: reabre com histórico.
	res, err = db.IngestFindings(ctx, "u3", []report.Finding{repo}, 20)
	if err != nil || res.Reopened != 1 {
		t.Fatalf("reabertura: %+v %v", res, err)
	}
}

func TestFingerprintDosTiposNovos(t *testing.T) {
	loc := &report.Location{Path: "/usr/bin/ls"}
	a := report.Finding{Engine: "pkgverify", Signature: "integridade.binario_alterado", Category: report.CategoryIntegrity,
		SHA256: shaA, Location: loc}
	b := a
	b.SHA256 = "b"
	ka, fa := Fingerprint(a)
	_, fb := Fingerprint(b)
	if ka != "file" || fa != fb {
		t.Fatalf("integridade deveria ser pelo caminho: %s %s %s", ka, fa, fb)
	}
	h1 := report.Finding{Engine: "inspect", Signature: "processo.oculto", Subject: "pid:10", Process: &report.ProcessEvidence{PID: 10}}
	h2 := h1
	h2.Subject, h2.Process = "pid:11", &report.ProcessEvidence{PID: 11}
	k1, f1 := Fingerprint(h1)
	_, f2 := Fingerprint(h2)
	if k1 != "process" || f1 == f2 {
		t.Fatalf("processos ocultos distintos: %s %s", f1, f2)
	}
	// Sem assunto, o processo continua com a identidade de antes (achados já gravados não mudam).
	p := report.Finding{Engine: "inspect", Signature: "s", Process: &report.ProcessEvidence{Exe: "/x"}}
	_, fp := Fingerprint(p)
	p.Subject = ""
	if _, again := Fingerprint(p); again != fp {
		t.Fatal("identidade instável")
	}
	if k, _ := Fingerprint(report.Finding{Engine: "inspect", Signature: "rede.porta_oculta", Subject: "tcp/31337"}); k != KindSystem {
		t.Fatalf("porta oculta: %s", k)
	}
}

func TestRelatoriosDoSistemaGuardamOsMaisRecentes(t *testing.T) {
	ctx := context.Background()
	db, now := openTest(t)
	if _, err := db.GetHostReport(ctx, HostReportIntegrity, ""); !errors.Is(err, ErrNotFound) {
		t.Fatalf("sem relatório: %v", err)
	}
	for i := range HostReportsKept + 2 {
		id := fmt.Sprintf("i%02d", i)
		if err := db.InsertRun(ctx, &Run{ID: id, Kind: report.KindIntegrity, Origin: "manual"}); err != nil {
			t.Fatal(err)
		}
		*now = now.Add(time.Minute)
		if err := db.SaveHostReport(ctx, HostReport{RunID: id, Name: HostReportIntegrity, TakenAt: *now, Data: []byte(`{"n":` + fmt.Sprint(i) + `}`)}); err != nil {
			t.Fatal(err)
		}
	}
	if err := db.SaveHostReport(ctx, HostReport{RunID: "i00", Name: HostReportHidden, TakenAt: *now, Data: []byte(`{}`)}); err != nil {
		t.Fatal(err)
	}
	last, err := db.GetHostReport(ctx, HostReportIntegrity, "")
	if err != nil || last.RunID != fmt.Sprintf("i%02d", HostReportsKept+1) {
		t.Fatalf("mais recente: %+v %v", last, err)
	}
	if _, err := db.GetHostReport(ctx, HostReportIntegrity, "i00"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("o mais antigo deveria ter saído: %v", err)
	}
	if h, err := db.GetHostReport(ctx, HostReportHidden, "i00"); err != nil || string(h.Data) != "{}" {
		t.Fatalf("relatório de outro nome não sai: %v", err)
	}
	runs, _ := db.HostReportRuns(ctx, HostReportIntegrity)
	if len(runs) != HostReportsKept {
		t.Fatalf("execuções: %d", len(runs))
	}
}

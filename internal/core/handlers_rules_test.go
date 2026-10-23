package core

import (
	"context"
	"net/http"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/guigallina27/vigiahost/internal/api"
	"github.com/guigallina27/vigiahost/internal/engines/lmd"
	"github.com/guigallina27/vigiahost/internal/ipc"
	"github.com/guigallina27/vigiahost/internal/rules"
	"github.com/guigallina27/vigiahost/internal/store"
)

func rulesFixture() ipc.RulesStatus {
	at := time.Date(2026, 10, 22, 11, 0, 0, 0, time.UTC)
	ok := true
	return ipc.RulesStatus{UserDir: rules.UserDir, Sources: []rules.SourceInfo{
		{Name: "controle", Origin: rules.OriginBuiltin, Mandatory: true, Files: 1, Rules: 1, Hash: "c1", License: "GPL-3.0-only"},
		{Name: "vigiahost", Origin: rules.OriginBuiltin, Files: 1, Rules: 15, Hash: "v1", License: "GPL-3.0-only"},
		{Name: "loja", Origin: rules.OriginLocal, Path: "/etc/vigiahost/rules.d/loja", Files: 2, Rules: 4, Hash: "l2", UpdatedAt: at},
		{Name: "quebrada", Origin: rules.OriginLocal, Files: 1, Rules: 1, Hash: "q1"},
		{Name: "aberta", Origin: rules.OriginLocal, Problem: "permissões inseguras"},
	}, Last: &rules.CompileStatus{At: at, Trigger: "manual", YRVersion: "1.21.0", SetVersion: "abc", OK: true, SelfTest: &ok,
		Sources: []rules.SourceResult{
			{Name: "controle", Hash: "c1", State: rules.StateOK, Rules: 1},
			{Name: "vigiahost", Hash: "v1", State: rules.StateOK, Rules: 15},
			{Name: "loja", Hash: "l1", State: rules.StateOK, Rules: 3},
			{Name: "quebrada", Hash: "q1", State: rules.StateError, Error: "linha 3: erro de sintaxe"},
		}}}
}

func sourceByName(t *testing.T, ov api.RulesOverview, name string) api.RuleSource {
	t.Helper()
	for _, s := range ov.Yara.Sources {
		if s.Name == name {
			return s
		}
	}
	t.Fatalf("fonte %s ausente", name)
	return api.RuleSource{}
}

func lastAudit(t *testing.T, a *testAPI) store.AuditEntry {
	t.Helper()
	list, err := a.db.ListAudit(context.Background(), 0, 1)
	if err != nil || len(list) == 0 {
		t.Fatalf("auditoria vazia: %v", err)
	}
	return list[0]
}

func TestRegrasEFontes(t *testing.T) {
	a := newTestAPI(t)
	a.exec.rules = rulesFixture()
	admin := a.sessionFor(t, store.RoleAdmin, true)
	reader := a.sessionFor(t, store.RoleReader, true)

	rec := a.do(t, "GET", "/api/v1/rules", "", reader, "")
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /rules: %d %s", rec.Code, rec.Body.String())
	}
	ov := decodeBody[api.RulesOverview](t, rec)
	if ov.ExecutorError != nil {
		t.Fatalf("erro do executor inesperado: %s", *ov.ExecutorError)
	}
	want := map[string]api.RuleSourceState{"controle": api.RuleSourceStateOk, "vigiahost": api.RuleSourceStateOk,
		"loja": api.RuleSourceStatePending, "quebrada": api.RuleSourceStateError, "aberta": api.RuleSourceStateRefused}
	for name, st := range want {
		if got := sourceByName(t, ov, name); got.State != st {
			t.Errorf("fonte %s: estado %s, esperado %s", name, got.State, st)
		}
	}
	if p := sourceByName(t, ov, "quebrada").Problem; p == nil || !strings.Contains(*p, "sintaxe") {
		t.Errorf("erro de compilação não repassado: %v", p)
	}
	if ov.Yara.LastCompile == nil || !ov.Yara.LastCompile.Ok || ov.Yara.LastCompile.Selftest == nil {
		t.Errorf("última compilação: %+v", ov.Yara.LastCompile)
	}
	if ov.Lmd.Installed || ov.Lmd.Enabled || ov.Lmd.State != api.EngineStateNotInstalled {
		t.Errorf("LMD ausente deveria aparecer como não instalado: %+v", ov.Lmd)
	}
	if ov.Clamav.State != api.EngineStateDegraded || len(ov.Clamav.LmdSignatures) != 0 {
		t.Errorf("ClamAV: %+v", ov.Clamav)
	}

	// Ligar o LMD sem instalação é recusado.
	if rec := a.do(t, "PUT", "/api/v1/rules/lmd", `{"enabled":true}`, admin, ""); rec.Code != http.StatusConflict {
		t.Fatalf("ligar LMD ausente: %d %s", rec.Code, rec.Body.String())
	}

	// Desativar uma fonte grava a lista, audita e pede compilação com a lista nova.
	rec = a.do(t, "PUT", "/api/v1/rules/sources/loja", `{"enabled":false}`, admin, "")
	if rec.Code != http.StatusOK {
		t.Fatalf("desativar fonte: %d %s", rec.Code, rec.Body.String())
	}
	ov = decodeBody[api.RulesOverview](t, rec)
	if s := sourceByName(t, ov, "loja"); s.Enabled || s.State != api.RuleSourceStateDisabled {
		t.Errorf("fonte desativada: %+v", s)
	}
	if !ov.Yara.Compiling || len(a.exec.compiles) != 1 || !slices.Equal(a.exec.compiles[0], []string{"loja"}) {
		t.Errorf("compilação pedida: %v (compilando %v)", a.exec.compiles, ov.Yara.Compiling)
	}
	if e := lastAudit(t, a); e.Action != "rule_source_disabled" || e.Target != "loja" {
		t.Errorf("auditoria: %+v", e)
	}
	if list, _ := a.db.DisabledRuleSources(context.Background()); !slices.Equal(list, []string{"loja"}) {
		t.Errorf("lista gravada: %v", list)
	}

	// O controle positivo não pode ser desativado; fonte inexistente é 404.
	if rec := a.do(t, "PUT", "/api/v1/rules/sources/controle", `{"enabled":false}`, admin, ""); rec.Code != http.StatusBadRequest {
		t.Errorf("desativar controle: %d", rec.Code)
	}
	if rec := a.do(t, "PUT", "/api/v1/rules/sources/nada", `{"enabled":false}`, admin, ""); rec.Code != http.StatusNotFound {
		t.Errorf("fonte inexistente: %d", rec.Code)
	}

	// Compilação em andamento: reativar a fonte grava mesmo assim; compilar de novo devolve 409.
	a.exec.compileBusy = true
	if rec := a.do(t, "PUT", "/api/v1/rules/sources/loja", `{"enabled":true}`, admin, ""); rec.Code != http.StatusOK {
		t.Fatalf("reativar fonte: %d %s", rec.Code, rec.Body.String())
	}
	if list, _ := a.db.DisabledRuleSources(context.Background()); len(list) != 0 {
		t.Errorf("lista deveria esvaziar: %v", list)
	}
	if rec := a.do(t, "POST", "/api/v1/rules/compile", "", admin, ""); rec.Code != http.StatusConflict {
		t.Errorf("compilação simultânea: %d", rec.Code)
	}
	a.exec.compileBusy = false
	if rec := a.do(t, "POST", "/api/v1/rules/compile", "", admin, ""); rec.Code != http.StatusOK {
		t.Fatalf("compilar: %d %s", rec.Code, rec.Body.String())
	}
	if e := lastAudit(t, a); e.Action != "rules_compile_requested" {
		t.Errorf("auditoria da compilação: %+v", e)
	}
}

func TestLMDLigaDesligaEEstados(t *testing.T) {
	a := newTestAPI(t)
	a.exec.rules = rulesFixture()
	a.exec.lmd = &lmd.Install{Dir: "/usr/local/maldetect", Version: "2.0.1", SigVersion: "2026052490478", SigDate: "2026-05-24",
		Signatures: lmd.Counts{SHA256: 42634, HEX: 2373, CSIG: 86, YARA: 3706}, ClamAVLinked: []string{"/var/lib/clamav/rfxn.ndb"}}
	admin := a.sessionFor(t, store.RoleAdmin, true)

	ov := decodeBody[api.RulesOverview](t, a.do(t, "GET", "/api/v1/rules", "", admin, ""))
	if !ov.Lmd.Installed || !ov.Lmd.Usable || ov.Lmd.Enabled || ov.Lmd.State != api.EngineStateDisabled {
		t.Fatalf("LMD instalado e desligado: %+v", ov.Lmd)
	}
	if ov.Lmd.Signatures == nil || ov.Lmd.Signatures.Sha256 != 42634 || len(ov.Clamav.LmdSignatures) != 1 {
		t.Errorf("assinaturas: %+v %v", ov.Lmd.Signatures, ov.Clamav.LmdSignatures)
	}
	rec := a.do(t, "PUT", "/api/v1/rules/lmd", `{"enabled":true}`, admin, "")
	if rec.Code != http.StatusOK {
		t.Fatalf("ligar LMD: %d %s", rec.Code, rec.Body.String())
	}
	if ov := decodeBody[api.RulesOverview](t, rec); !ov.Lmd.Enabled || ov.Lmd.State != api.EngineStateOperational {
		t.Errorf("LMD ligado: %+v", ov.Lmd)
	}
	if e := lastAudit(t, a); e.Action != "lmd_enabled" {
		t.Errorf("auditoria: %+v", e)
	}
	eng := decodeBody[api.EngineStatus](t, a.do(t, "GET", "/api/v1/engines", "", admin, ""))
	if len(eng.Engines) != 3 || eng.Engines[2].Id != api.Lmd || eng.Engines[2].State != api.EngineStateOperational {
		t.Errorf("saúde dos motores: %+v", eng.Engines)
	}

	// Execução de arquivos leva a configuração vigente ao executor.
	if on, _ := a.db.LMDEnabled(context.Background()); !on {
		t.Fatal("LMD não gravado")
	}

	// Instalação que deixou de servir com o LMD ligado: indisponível, com o motivo.
	a.srv.engCache = nil
	a.exec.lmdErr = "instalação do LMD insegura"
	ov = decodeBody[api.RulesOverview](t, a.do(t, "GET", "/api/v1/rules", "", admin, ""))
	if ov.Lmd.Usable || ov.Lmd.State != api.EngineStateUnavailable || ov.Lmd.Detail == nil {
		t.Errorf("LMD inutilizável e ligado: %+v", ov.Lmd)
	}
	if rec := a.do(t, "PUT", "/api/v1/rules/lmd", `{"enabled":false}`, admin, ""); rec.Code != http.StatusOK {
		t.Fatalf("desligar LMD: %d", rec.Code)
	}
	if e := lastAudit(t, a); e.Action != "lmd_disabled" {
		t.Errorf("auditoria: %+v", e)
	}
}

func TestRegrasComExecutorFora(t *testing.T) {
	a := newTestAPI(t)
	a.srv.Exec = nil
	admin := a.sessionFor(t, store.RoleAdmin, true)
	rec := a.do(t, "GET", "/api/v1/rules", "", admin, "")
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /rules sem executor: %d", rec.Code)
	}
	ov := decodeBody[api.RulesOverview](t, rec)
	if ov.ExecutorError == nil || ov.Lmd.State != api.EngineStateUnavailable || len(ov.Yara.Sources) != 0 {
		t.Errorf("visão sem executor: %+v", ov)
	}
}

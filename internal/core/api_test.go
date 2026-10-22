package core

import (
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	altcha "github.com/altcha-org/altcha-lib-go/v2"

	"github.com/guigallina27/vigiahost/internal/api"
	"github.com/guigallina27/vigiahost/internal/auth"
	"github.com/guigallina27/vigiahost/internal/ipc"
	"github.com/guigallina27/vigiahost/internal/orchestrator"
	"github.com/guigallina27/vigiahost/internal/report"
	"github.com/guigallina27/vigiahost/internal/store"
)

// fakeExec responde como um executor mínimo: hardware, início e estado das execuções.
type fakeExec struct{ started []string }

func (f *fakeExec) Call(_ context.Context, op ipc.Op, in, out any) error {
	set := func(v any) {
		if out != nil {
			b, _ := json.Marshal(v)
			_ = json.Unmarshal(b, out)
		}
	}
	switch op {
	case ipc.OpHardware:
		set(ipc.Hardware{CPUs: 4, MemoryBytes: 8 << 30, Freezer: true, Systemd: "252"})
	case ipc.OpRunStart:
		id := in.(ipc.RunStart).Request.RunID
		f.started = append(f.started, id)
		set(ipc.RunState{RunID: id, Active: "active"})
	case ipc.OpRunStatus:
		set(ipc.RunState{RunID: in.(ipc.RunRef).RunID, Active: "active"})
	case ipc.OpEngines:
		set(map[string]any{"yr": "/usr/bin/yr", "yr_version": "1.21.0", "clamscan": "/usr/bin/clamscan",
			"clam_version": map[string]any{"Engine": "1.4.6", "Database": "27800"}})
	default:
		return &ipc.Error{Code: ipc.CodeNotFound, Message: "desconhecida"}
	}
	return nil
}

type testAPI struct {
	srv  *Server
	h    http.Handler
	db   *store.DB
	now  *time.Time
	exec *fakeExec
}

func newTestAPI(t *testing.T) *testAPI {
	t.Helper()
	ctx := context.Background()
	raw, err := store.Open(ctx, filepath.Join(t.TempDir(), "core.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = raw.Close() })
	if _, err := store.Migrate(ctx, raw); err != nil {
		t.Fatal(err)
	}
	db := store.New(raw)
	now := time.Date(2026, 10, 22, 12, 0, 0, 0, time.UTC)
	db.Now = func() time.Time { return now }
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	fx := &fakeExec{}
	hub := orchestrator.NewHub()
	captcha := auth.NewCaptcha()
	captcha.Cost, captcha.CounterMin, captcha.CounterMax = 10, 5, 20
	s := &Server{Captcha: captcha, Logger: logger, Version: "0.0.1", DB: db, Hub: hub, Exec: fx,
		BackupDir: filepath.Join(t.TempDir(), "backups"),
		Probe:     func(context.Context) ExecutorStatus { return ExecutorStatus{Connected: true} },
		Auth:      &auth.Service{DB: db, Logger: logger, FailLog: io.Discard, Config: auth.Config{Sleep: func(time.Duration) {}}},
		Orch:      &orchestrator.Service{DB: db, Exec: fx, Hub: hub, Logger: logger}}
	return &testAPI{srv: s, h: s.Handler(), db: db, now: &now, exec: fx}
}

// solveCaptcha busca um desafio na API e o resolve como o widget faria.
func (a *testAPI) solveCaptcha(t *testing.T) string {
	t.Helper()
	ch := decodeBody[altcha.Challenge](t, a.do(t, "GET", "/api/v1/auth/challenge", "", "", ""))
	sol, err := altcha.SolveChallenge(altcha.SolveChallengeOptions{Challenge: ch, DeriveKey: altcha.DeriveKeyPBKDF2()})
	if err != nil || sol == nil {
		t.Fatalf("desafio não resolvido: %v", err)
	}
	b, _ := json.Marshal(altcha.Payload{Challenge: ch, Solution: *sol})
	return base64.StdEncoding.EncodeToString(b)
}

// do faz a requisição como se viesse do túnel SSH (endereço local).
func (a *testAPI) do(t *testing.T, method, path, body, cookie, bearer string) *httptest.ResponseRecorder {
	t.Helper()
	var rd io.Reader
	if body != "" {
		rd = strings.NewReader(body)
	}
	req := httptest.NewRequest(method, path, rd)
	req.Host = "127.0.0.1:8743"
	req.RemoteAddr = "127.0.0.1:40000"
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	if cookie != "" {
		req.AddCookie(&http.Cookie{Name: sessionCookie, Value: cookie})
	}
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	rec := httptest.NewRecorder()
	a.h.ServeHTTP(rec, req)
	return rec
}

// sessionFor cria usuário e sessão completa direto no banco (a matriz não precisa passar pelo segundo fator).
func (a *testAPI) sessionFor(t *testing.T, role string, reauth bool) string {
	t.Helper()
	ctx := context.Background()
	u := store.User{Username: "u-" + role, Role: role, PasswordHash: "x"}
	if existing, err := a.db.GetUserByName(ctx, u.Username); err == nil {
		u = existing
	} else if err := a.db.CreateUser(ctx, &u); err != nil {
		t.Fatal(err)
	}
	tok := auth.RandomToken(16)
	sess := store.Session{IDHash: store.HashToken(tok), UserID: u.ID, Stage: store.StageFull, CreatedAt: *a.now,
		LastSeen: *a.now, ExpiresAt: a.now.Add(time.Hour)}
	if reauth {
		at := *a.now
		sess.ReauthAt = &at
	}
	if err := a.db.CreateSession(ctx, sess); err != nil {
		t.Fatal(err)
	}
	return tok
}

// specRoutes lê as rotas do contrato (caminho e método).
func specRoutes(t *testing.T) []string {
	t.Helper()
	f, err := os.Open(filepath.Join("..", "..", "api", "openapi.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	pathRe := regexp.MustCompile(`^  (/api/v1/\S+):\s*$`)
	methodRe := regexp.MustCompile(`^    (get|post|put|patch|delete):\s*$`)
	var out []string
	cur := ""
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		if m := pathRe.FindStringSubmatch(sc.Text()); m != nil {
			cur = m[1]
		} else if m := methodRe.FindStringSubmatch(sc.Text()); m != nil && cur != "" {
			out = append(out, strings.ToUpper(m[1])+" "+cur)
		} else if strings.HasPrefix(sc.Text(), "components:") {
			break
		}
	}
	return out
}

func concrete(route string) (string, string) {
	method, p, _ := strings.Cut(route, " ")
	p = strings.NewReplacer("{runId}", "nao-existe", "{findingId}", "999999", "{id}", "999999", "{name}", "leve").Replace(p)
	return method, p
}

func TestMatrizCobreTodasAsRotasDoContrato(t *testing.T) {
	spec := specRoutes(t)
	if len(spec) < 40 {
		t.Fatalf("leitura do contrato encontrou só %d rotas", len(spec))
	}
	inSpec := map[string]bool{}
	for _, r := range spec {
		inSpec[r] = true
		if _, ok := routes[r]; !ok {
			t.Errorf("rota do contrato sem regra de acesso: %s", r)
		}
	}
	for r := range routes {
		if !inSpec[r] {
			t.Errorf("regra para rota que não existe no contrato: %s", r)
		}
	}
}

func TestMatrizDeAutorizacaoPorPerfil(t *testing.T) {
	a := newTestAPI(t)
	roles := []string{store.RoleAdmin, store.RoleOperator, store.RoleReader, store.RoleAuditor}
	for _, route := range specRoutes(t) {
		rl := routes[route]
		// Sessões novas a cada rota: logout, troca de senha e reautenticação encerram ou trocam a sessão usada.
		cookies := map[string]string{}
		for _, role := range roles {
			cookies[role] = a.sessionFor(t, role, true)
		}
		noReauth := a.sessionFor(t, store.RoleAdmin, false)
		if route == "GET /api/v1/events" {
			continue // fluxo contínuo; a autorização é a mesma das outras rotas de leitura
		}
		method, p := concrete(route)
		body := ""
		if method != http.MethodGet && method != http.MethodDelete {
			body = "{}"
		}
		if rl.access != accessPublic {
			if rec := a.do(t, method, p, body, "", ""); rec.Code != http.StatusUnauthorized {
				t.Errorf("%s sem sessão: %d, esperado 401", route, rec.Code)
			}
		}
		for _, role := range roles {
			rec := a.do(t, method, p, body, cookies[role], "")
			denied := rec.Code == http.StatusForbidden && strings.Contains(rec.Body.String(), `"forbidden"`)
			if want := !allowed(rl.access, role); denied != want {
				t.Errorf("%s com perfil %s: status %d (%s), negado esperado %v", route, role, rec.Code,
					strings.TrimSpace(rec.Body.String()), want)
			}
			// 401 por credencial errada (senha de teste) é resposta do handler, não da autorização.
			if rec.Code == http.StatusUnauthorized && rl.access != accessPublic && !strings.Contains(rec.Body.String(), "invalid_credentials") {
				t.Errorf("%s com sessão completa (%s) recebeu 401", route, role)
			}
		}
		if rl.reauth {
			rec := a.do(t, method, p, body, noReauth, "")
			if rec.Code != http.StatusForbidden || !strings.Contains(rec.Body.String(), "reauth_required") {
				t.Errorf("%s sem reautenticação: %d %s", route, rec.Code, rec.Body.String())
			}
		}
	}
}

func decodeBody[T any](t *testing.T, rec *httptest.ResponseRecorder) T {
	t.Helper()
	var v T
	dec := json.NewDecoder(bytes.NewReader(rec.Body.Bytes()))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&v); err != nil {
		t.Fatalf("resposta fora do contrato (%d): %v — %s", rec.Code, err, rec.Body.String())
	}
	return v
}

func cookieFrom(t *testing.T, rec *httptest.ResponseRecorder) string {
	t.Helper()
	for _, c := range rec.Result().Cookies() {
		if c.Name == sessionCookie {
			if !c.Secure || !c.HttpOnly || c.SameSite != http.SameSiteStrictMode || c.Path != "/" {
				t.Fatalf("cookie sem os atributos exigidos: %+v", c)
			}
			return c.Value
		}
	}
	t.Fatalf("resposta sem cookie de sessão: %d %s", rec.Code, rec.Body.String())
	return ""
}

func TestFluxoCompletoPeloHTTP(t *testing.T) {
	a := newTestAPI(t)
	ctx := context.Background()

	sess := decodeBody[api.Session](t, a.do(t, "GET", "/api/v1/auth/session", "", "", ""))
	if !sess.SetupRequired || sess.Authenticated || !sess.SecureTransport {
		t.Fatalf("primeiro acesso: %+v", sess)
	}
	tok, err := a.srv.Auth.NewFirstAccessToken(ctx)
	if err != nil {
		t.Fatal(err)
	}
	// Login fora do endereço local e sem TLS é recusado.
	req := httptest.NewRequest("POST", "/api/v1/auth/login", strings.NewReader(`{"username":"a","password":"b"}`))
	rec := httptest.NewRecorder()
	a.h.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "insecure_transport") {
		t.Fatalf("login sem transporte seguro: %d %s", rec.Code, rec.Body.String())
	}

	// Sem a caixa "não sou um robô" (ou com solução reaproveitada) o token nem é conferido.
	setupBody := func(captcha string) string {
		return `{"token":"` + tok + `","username":"ana","password":"senha-muito-longa","altcha":"` + captcha + `"}`
	}
	if rec := a.do(t, "POST", "/api/v1/auth/setup", setupBody(""), "", ""); rec.Code != http.StatusBadRequest ||
		!strings.Contains(rec.Body.String(), "captcha_failed") {
		t.Fatalf("setup sem captcha: %d %s", rec.Code, rec.Body.String())
	}
	captcha := a.solveCaptcha(t)
	rec = a.do(t, "POST", "/api/v1/auth/setup", setupBody(captcha), "", "")
	cookie := cookieFrom(t, rec)
	if rec := a.do(t, "POST", "/api/v1/auth/login", `{"username":"ana","password":"senha-muito-longa","altcha":"`+captcha+`"}`,
		"", ""); rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "captcha_failed") {
		t.Fatalf("captcha reaproveitado: %d %s", rec.Code, rec.Body.String())
	}
	sess = decodeBody[api.Session](t, rec)
	if sess.Stage == nil || *sess.Stage != api.SessionStageMfaSetup || sess.Authenticated {
		t.Fatalf("depois do primeiro acesso falta o segundo fator: %+v", sess)
	}
	if rec := a.do(t, "GET", "/api/v1/overview", "", cookie, ""); rec.Code != http.StatusUnauthorized ||
		!strings.Contains(rec.Body.String(), "mfa_setup_required") {
		t.Fatalf("sem segundo fator não acessa o painel: %d %s", rec.Code, rec.Body.String())
	}
	setup := decodeBody[api.MfaSetup](t, a.do(t, "POST", "/api/v1/auth/mfa/setup", "", cookie, ""))
	code, _ := auth.TOTPCode(setup.Secret, auth.Step(*a.now))
	rec = a.do(t, "POST", "/api/v1/auth/mfa/enable", `{"code":"`+code+`"}`, cookie, "")
	cookie = cookieFrom(t, rec)
	en := decodeBody[api.MfaEnabled](t, rec)
	if !en.Session.Authenticated || len(en.RecoveryCodes) != 10 {
		t.Fatalf("segundo fator ativo: %+v", en.Session)
	}

	ov := decodeBody[api.Overview](t, a.do(t, "GET", "/api/v1/overview", "", cookie, ""))
	if ov.HasRuns || ov.OpenFindings.Total != 0 || len(ov.Engines) != 2 {
		t.Fatalf("visão geral vazia: %+v", ov)
	}

	rec = a.do(t, "POST", "/api/v1/runs", `{"kind":"files","paths":["/home"],"profile":"leve"}`, cookie, "")
	if rec.Code != http.StatusCreated {
		t.Fatalf("criar execução: %d %s", rec.Code, rec.Body.String())
	}
	run := decodeBody[api.Run](t, rec)
	if run.Status != api.Queued || run.Profile.Name != "leve" || run.RequestedBy != "ana" {
		t.Fatalf("execução: %+v", run)
	}
	a.srv.Orch.Step(ctx)
	detail := decodeBody[api.RunDetail](t, a.do(t, "GET", "/api/v1/runs/"+run.Id, "", cookie, ""))
	if detail.Run.Status != api.Running || len(a.exec.started) != 1 {
		t.Fatalf("execução entregue ao executor: %+v", detail.Run)
	}
	page := decodeBody[api.RunPage](t, a.do(t, "GET", "/api/v1/runs?status=running", "", cookie, ""))
	if len(page.Runs) != 1 {
		t.Fatalf("filtro por estado: %d", len(page.Runs))
	}

	// Achado ingerido e ciclo de vida pela API.
	f := report.Finding{Engine: "yara-x", Signature: "vh_php_upload_direto", Category: report.CategoryWebshell,
		Severity: report.SeverityHigh, SHA256: strings.Repeat("d", 64), Location: &report.Location{Path: "/home/a/up.php"}}
	if _, err := a.db.IngestFindings(ctx, run.Id, []report.Finding{f}, 10); err != nil {
		t.Fatal(err)
	}
	fp := decodeBody[api.FindingPage](t, a.do(t, "GET", "/api/v1/findings?state=new&severity=high", "", cookie, ""))
	if len(fp.Findings) != 1 {
		t.Fatalf("achados: %d", len(fp.Findings))
	}
	id := fp.Findings[0].Id
	fd := decodeBody[api.FindingDetail](t, a.do(t, "POST", "/api/v1/findings/"+itoa(id)+"/transition",
		`{"to":"confirmed","note":"conferido"}`, cookie, ""))
	if fd.Finding.State != api.Confirmed || len(fd.Events) != 2 {
		t.Fatalf("transição: %+v", fd.Finding.State)
	}

	// Exceção exige reautenticação recente: a do segundo fator já passou de 5 minutos.
	*a.now = a.now.Add(10 * time.Minute)
	exc := `{"scope":"hash","finding_id":` + itoa(id) + `,"reason":"arquivo de teste interno"}`
	if rec := a.do(t, "POST", "/api/v1/exceptions", exc, cookie, ""); rec.Code != http.StatusForbidden ||
		!strings.Contains(rec.Body.String(), "reauth_required") {
		t.Fatalf("exceção sem reautenticação: %d %s", rec.Code, rec.Body.String())
	}
	code, _ = auth.TOTPCode(setup.Secret, auth.Step(*a.now))
	rec = a.do(t, "POST", "/api/v1/auth/reauth", `{"password":"senha-muito-longa","code":"`+code+`"}`, cookie, "")
	cookie = cookieFrom(t, rec)
	if rec := a.do(t, "POST", "/api/v1/exceptions", exc, cookie, ""); rec.Code != http.StatusCreated {
		t.Fatalf("exceção: %d %s", rec.Code, rec.Body.String())
	}

	// Agendamento com prévia dos horários.
	pv := decodeBody[api.CronPreview](t, a.do(t, "POST", "/api/v1/schedules/preview",
		`{"cron":"0 3 * * *","timezone":"America/Sao_Paulo"}`, cookie, ""))
	if len(pv.Next) != 5 || pv.Next[0].UTC().Hour() != 6 {
		t.Fatalf("prévia: %+v", pv.Next)
	}
	rec = a.do(t, "POST", "/api/v1/schedules", `{"name":"diária","kind":"files","cron":"0 3 * * *",`+
		`"timezone":"America/Sao_Paulo","paths":["/home"]}`, cookie, "")
	if rec.Code != http.StatusCreated {
		t.Fatalf("agendamento: %d %s", rec.Code, rec.Body.String())
	}
	if rec := a.do(t, "POST", "/api/v1/schedules", `{"name":"x","kind":"files","cron":"0 3 * *"}`, cookie, ""); rec.Code != http.StatusBadRequest {
		t.Fatalf("cron inválido: %d", rec.Code)
	}

	res := decodeBody[api.Resources](t, a.do(t, "GET", "/api/v1/resources", "", cookie, ""))
	if res.Hardware == nil || res.Hardware.Cpus != 4 || len(res.Profiles) != 3 {
		t.Fatalf("recursos: %+v", res)
	}
	big := `{"name":"x","cpu_quota_percent":400,"memory_max_bytes":1073741824,"io_read_bytes_per_sec":0,"io_weight":100,` +
		`"workers":2,"clamd_concurrency":2,"max_runtime_sec":3600,"nice":10,"max_file_bytes":0}`
	if rec := a.do(t, "PUT", "/api/v1/resources/profiles/leve", big, cookie, ""); rec.Code != http.StatusBadRequest {
		t.Fatalf("perfil com todos os núcleos deveria ser recusado pela trava: %d %s", rec.Code, rec.Body.String())
	}

	// Token de API de leitura não cria execução.
	tk := decodeBody[api.ApiTokenCreated](t, a.do(t, "POST", "/api/v1/tokens", `{"name":"monitor","role":"reader","expires_in_days":30}`, cookie, ""))
	if rec := a.do(t, "GET", "/api/v1/findings", "", "", tk.Token); rec.Code != http.StatusOK {
		t.Fatalf("token de leitura lê achados: %d", rec.Code)
	}
	if rec := a.do(t, "POST", "/api/v1/runs", `{"kind":"processes"}`, "", tk.Token); rec.Code != http.StatusForbidden {
		t.Fatalf("token de leitura não cria execução: %d", rec.Code)
	}

	audit := decodeBody[api.AuditPage](t, a.do(t, "GET", "/api/v1/audit", "", cookie, ""))
	if !audit.ChainOk || len(audit.Entries) < 5 {
		t.Fatalf("auditoria: ok=%v entradas=%d", audit.ChainOk, len(audit.Entries))
	}
	if rec := a.do(t, "POST", "/api/v1/auth/logout", "", cookie, ""); rec.Code != http.StatusNoContent {
		t.Fatalf("logout: %d", rec.Code)
	}
	if rec := a.do(t, "GET", "/api/v1/overview", "", cookie, ""); rec.Code != http.StatusUnauthorized {
		t.Fatalf("sessão encerrada: %d", rec.Code)
	}
}

func itoa(v int64) string { return strconv.FormatInt(v, 10) }

func TestCopiaManualDoBancoPelaAPI(t *testing.T) {
	a := newTestAPI(t)
	cookie := a.sessionFor(t, store.RoleAdmin, true)
	rec := a.do(t, "POST", "/api/v1/backups", "", cookie, "")
	if rec.Code != http.StatusCreated {
		t.Fatalf("criar cópia: %d %s", rec.Code, rec.Body)
	}
	info := decodeBody[api.BackupInfo](t, rec)
	if info.Origin != api.BackupInfoOriginManual || len(info.Sha256) != 64 || info.SchemaVersion < 1 {
		t.Fatalf("cópia: %+v", info)
	}
	rec = a.do(t, "GET", "/api/v1/backups", "", cookie, "")
	list := decodeBody[api.BackupList](t, rec)
	if rec.Code != http.StatusOK || len(list.Backups) != 1 || list.Backups[0].Name != info.Name {
		t.Fatalf("lista: %d %+v", rec.Code, list)
	}
	page, err := a.db.ListAudit(context.Background(), 0, 10)
	if err != nil || len(page) == 0 || page[0].Action != "backup.create" {
		t.Fatalf("auditoria da cópia: %+v (%v)", page, err)
	}
}

func TestSSEEntregaEventos(t *testing.T) {
	a := newTestAPI(t)
	cookie := a.sessionFor(t, store.RoleReader, false)
	srv := httptest.NewServer(a.h)
	defer srv.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, "GET", srv.URL+"/api/v1/events", nil)
	req.AddCookie(&http.Cookie{Name: sessionCookie, Value: cookie})
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK || !strings.HasPrefix(resp.Header.Get("Content-Type"), "text/event-stream") {
		t.Fatalf("SSE: %d %s", resp.StatusCode, resp.Header.Get("Content-Type"))
	}
	br := bufio.NewReader(resp.Body)
	for a.srv.Hub.Subscribers() == 0 {
		time.Sleep(10 * time.Millisecond)
	}
	a.srv.Hub.Publish(orchestrator.Event{Type: "run", ID: "abc"})
	for {
		line, err := br.ReadString('\n')
		if err != nil {
			t.Fatal(err)
		}
		if strings.HasPrefix(line, "data: ") {
			if !strings.Contains(line, `"id":"abc"`) {
				t.Fatalf("evento: %s", line)
			}
			return
		}
	}
}

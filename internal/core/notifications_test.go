package core

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/guigallina27/vigiahost/internal/api"
	"github.com/guigallina27/vigiahost/internal/notify"
	"github.com/guigallina27/vigiahost/internal/store"
)

const hookSecret = "whsec_MfKQ9r8GKYqrTwjUPD8ILPZIo2LaLaSw"

func TestNotificacoesPelaAPI(t *testing.T) {
	a := newTestAPI(t)
	ctx := context.Background()
	admin := a.sessionFor(t, store.RoleAdmin, true)
	key, _ := notify.WebhookKey(hookSecret)
	var mu sync.Mutex
	status, got := http.StatusOK, 0
	hook := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		mu.Lock()
		defer mu.Unlock()
		if err := notify.Verify(key, r.Header, body, *a.now, notify.DefaultTolerance); err != nil {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		got++
		w.WriteHeader(status)
	}))
	t.Cleanup(hook.Close)

	webhookBody := func(name, url, extra string) string {
		return fmt.Sprintf(`{"name":%q,"kind":"webhook","enabled":true,"webhook":{"url":%q,"allow_private_network":true}%s}`, name, url, extra)
	}
	// Segredo obrigatório, destino de metadados recusado, nome repetido em conflito.
	if rec := a.do(t, "POST", "/api/v1/notifications/channels", webhookBody("SOC", hook.URL, ""), admin, ""); rec.Code != http.StatusBadRequest ||
		!strings.Contains(rec.Body.String(), "segredo") {
		t.Fatalf("webhook sem segredo: %d %s", rec.Code, rec.Body.String())
	}
	if rec := a.do(t, "POST", "/api/v1/notifications/channels", webhookBody("meta", "http://169.254.169.254/latest", `,"secret":"`+hookSecret+`"`), admin, ""); rec.Code != http.StatusBadRequest ||
		!strings.Contains(rec.Body.String(), "metadados") {
		t.Fatalf("destino de metadados: %d %s", rec.Code, rec.Body.String())
	}
	rec := a.do(t, "POST", "/api/v1/notifications/channels", webhookBody("SOC", hook.URL, `,"secret":"`+hookSecret+`"`), admin, "")
	if rec.Code != http.StatusCreated || strings.Contains(rec.Body.String(), hookSecret) || strings.Contains(rec.Body.String(), "MfKQ9r8") {
		t.Fatalf("criação do webhook (o segredo nunca volta): %d %s", rec.Code, rec.Body.String())
	}
	ch := decodeBody[api.NotificationChannel](t, rec)
	if !ch.SecretConfigured || !ch.SecretReadable || ch.Webhook == nil || ch.CreatedBy != "u-admin" {
		t.Fatalf("canal criado: %+v", ch)
	}
	if rec := a.do(t, "POST", "/api/v1/notifications/channels", webhookBody("soc", hook.URL, `,"secret":"`+hookSecret+`"`), admin, ""); rec.Code != http.StatusConflict {
		t.Fatalf("nome repetido: %d", rec.Code)
	}
	// Alterar sem segredo mantém o atual; o tipo não muda.
	path := fmt.Sprintf("/api/v1/notifications/channels/%d", ch.Id)
	rec = a.do(t, "PUT", path, webhookBody("SOC principal", hook.URL, `,"include_details":false`), admin, "")
	upd := decodeBody[api.NotificationChannel](t, rec)
	if rec.Code != http.StatusOK || !upd.SecretConfigured || upd.Name != "SOC principal" || upd.IncludeDetails {
		t.Fatalf("alteração: %d %+v", rec.Code, upd)
	}
	if rec := a.do(t, "PUT", path, `{"name":"x","kind":"email","enabled":true,"email":{"host":"smtp.example.com","port":587,"security":"starttls","from":"a@example.com","to":["b@example.com"]}}`, admin, ""); rec.Code != http.StatusBadRequest {
		t.Fatalf("troca de tipo: %d %s", rec.Code, rec.Body.String())
	}

	// Botão de teste: resultado real do envio, nos dois sentidos.
	res := decodeBody[api.NotificationTestResult](t, a.do(t, "POST", path+"/test", "", admin, ""))
	if !res.Ok || res.Entry.State != api.OutboxSent || res.Entry.Event != api.OutboxEventTest || got != 1 {
		t.Fatalf("teste com sucesso: %+v (recebidas %d)", res, got)
	}
	mu.Lock()
	status = http.StatusInternalServerError
	mu.Unlock()
	res = decodeBody[api.NotificationTestResult](t, a.do(t, "POST", path+"/test", "", admin, ""))
	if res.Ok || res.Error == nil || !strings.Contains(*res.Error, "HTTP 500") || res.Entry.State != api.OutboxFailed {
		t.Fatalf("teste com falha: %+v", res)
	}

	// E-mail: usuário exige senha; a senha não volta.
	emailBody := func(extra string) string {
		return `{"name":"E-mail","kind":"email","enabled":true,"email":{"host":"smtp.example.com","port":587,"security":"starttls","username":"alertas","from":"VigiaHost <vigia@example.com>","to":["soc@example.com"]}` + extra + `}`
	}
	if rec := a.do(t, "POST", "/api/v1/notifications/channels", emailBody(""), admin, ""); rec.Code != http.StatusBadRequest ||
		!strings.Contains(rec.Body.String(), "senha") {
		t.Fatalf("e-mail sem senha: %d %s", rec.Code, rec.Body.String())
	}
	rec = a.do(t, "POST", "/api/v1/notifications/channels", emailBody(`,"secret":"senha-smtp-secreta"`), admin, "")
	if rec.Code != http.StatusCreated || strings.Contains(rec.Body.String(), "senha-smtp-secreta") {
		t.Fatalf("e-mail com senha: %d %s", rec.Code, rec.Body.String())
	}
	email := decodeBody[api.NotificationChannel](t, rec)
	if email.Email == nil || email.Email.Port != 587 || !email.SecretConfigured {
		t.Fatalf("e-mail criado: %+v", email)
	}
	list := decodeBody[[]api.NotificationChannel](t, a.do(t, "GET", "/api/v1/notifications/channels", "", admin, ""))
	if len(list) != 2 || list[1].LastState == nil || *list[1].LastState != api.OutboxFailed {
		t.Fatalf("lista de canais com o último estado: %+v", list)
	}

	// Regras: padrão de janela por evento, repetição em conflito, canal inexistente recusado.
	rec = a.do(t, "POST", "/api/v1/notifications/rules", fmt.Sprintf(`{"channel_id":%d,"event":"finding_new","min_severity":"critical"}`, ch.Id), admin, "")
	rule := decodeBody[api.NotificationRule](t, rec)
	if rec.Code != http.StatusCreated || rule.DedupMinutes != 1440 || !rule.Enabled || rule.MinSeverity != api.Critical {
		t.Fatalf("regra: %d %+v", rec.Code, rule)
	}
	if rec := a.do(t, "POST", "/api/v1/notifications/rules", fmt.Sprintf(`{"channel_id":%d,"event":"finding_new"}`, ch.Id), admin, ""); rec.Code != http.StatusConflict {
		t.Fatalf("regra repetida: %d", rec.Code)
	}
	if rec := a.do(t, "POST", "/api/v1/notifications/rules", `{"channel_id":999,"event":"backup_failed"}`, admin, ""); rec.Code != http.StatusBadRequest {
		t.Fatalf("canal inexistente: %d", rec.Code)
	}
	if rec := a.do(t, "POST", "/api/v1/notifications/rules", fmt.Sprintf(`{"channel_id":%d,"event":"x"}`, ch.Id), admin, ""); rec.Code != http.StatusBadRequest {
		t.Fatalf("evento inválido: %d", rec.Code)
	}
	rulePath := fmt.Sprintf("/api/v1/notifications/rules/%d", rule.Id)
	rec = a.do(t, "PUT", rulePath, fmt.Sprintf(`{"channel_id":%d,"event":"finding_new","min_severity":"high","dedup_minutes":30}`, ch.Id), admin, "")
	if rule = decodeBody[api.NotificationRule](t, rec); rule.DedupMinutes != 30 || rule.MinSeverity != api.High {
		t.Fatalf("alteração da regra: %+v", rule)
	}

	// Caixa de saída: achado entra pendente; reenviar antecipa; teste não reenvia.
	if err := a.srv.Notify.Emit(ctx, notify.Event{Item: notify.Item{Event: store.EventFindingNew, Severity: "critical",
		Title: "YARA-X: Webshell", FindingID: 7}, Key: "finding:7"}); err != nil {
		t.Fatal(err)
	}
	page := decodeBody[api.OutboxPage](t, a.do(t, "GET", "/api/v1/notifications/outbox?state=pending", "", admin, ""))
	if len(page.Entries) != 1 || page.Entries[0].Summary != "achado novo de severidade crítica" || page.Entries[0].NextAttemptAt == nil ||
		page.Entries[0].Items[0].FindingId == nil || *page.Entries[0].Items[0].FindingId != 7 {
		t.Fatalf("caixa de saída pendente: %+v", page)
	}
	pending := page.Entries[0]
	rec = a.do(t, "POST", fmt.Sprintf("/api/v1/notifications/outbox/%d/retry", pending.Id), "", admin, "")
	if again := decodeBody[api.OutboxEntry](t, rec); rec.Code != http.StatusOK || !again.NextAttemptAt.Equal(*a.now) {
		t.Fatalf("reenviar agora: %d %+v", rec.Code, again)
	}
	all := decodeBody[api.OutboxPage](t, a.do(t, "GET", "/api/v1/notifications/outbox?limit=2", "", admin, ""))
	if len(all.Entries) != 2 || all.NextBefore == nil {
		t.Fatalf("paginação: %+v", all)
	}
	if rec := a.do(t, "POST", fmt.Sprintf("/api/v1/notifications/outbox/%d/retry", res.Entry.Id), "", admin, ""); rec.Code != http.StatusConflict {
		t.Fatalf("teste não reenvia: %d", rec.Code)
	}

	// Remover o canal leva as regras junto e mantém o histórico.
	if rec := a.do(t, "DELETE", path, "", admin, ""); rec.Code != http.StatusNoContent {
		t.Fatalf("remoção: %d", rec.Code)
	}
	if rules := decodeBody[[]api.NotificationRule](t, a.do(t, "GET", "/api/v1/notifications/rules", "", admin, "")); len(rules) != 0 {
		t.Fatalf("regras do canal removido: %+v", rules)
	}
	hist := decodeBody[api.OutboxPage](t, a.do(t, "GET", "/api/v1/notifications/outbox", "", admin, ""))
	if len(hist.Entries) != 3 || hist.Entries[0].ChannelId != nil || hist.Entries[0].State != api.OutboxFailed {
		t.Fatalf("histórico depois da remoção: %+v", hist.Entries)
	}

	// Auditoria de cada alteração e dos testes, sem segredo em lugar nenhum.
	entries, err := a.db.ListAudit(ctx, 0, 100)
	if err != nil {
		t.Fatal(err)
	}
	actions := map[string]int{}
	for _, e := range entries {
		actions[e.Action]++
		if strings.Contains(e.Detail, "MfKQ9r8") || strings.Contains(e.Detail, "senha-smtp-secreta") {
			t.Fatalf("segredo na auditoria: %+v", e)
		}
	}
	for _, want := range []string{"notification_channel_created", "notification_channel_updated", "notification_channel_deleted",
		"notification_test", "notification_rule_created", "notification_rule_updated", "notification_retry"} {
		if actions[want] == 0 {
			t.Errorf("auditoria sem %s: %v", want, actions)
		}
	}
	if actions["notification_test"] != 2 {
		t.Errorf("os dois testes deveriam estar na auditoria: %v", actions)
	}
}

func TestNotificacoesExigemAdministradorEReautenticacao(t *testing.T) {
	a := newTestAPI(t)
	op := a.sessionFor(t, store.RoleOperator, true)
	if rec := a.do(t, "GET", "/api/v1/notifications/channels", "", op, ""); rec.Code != http.StatusForbidden {
		t.Fatalf("operador lendo canais: %d", rec.Code)
	}
	noReauth := a.sessionFor(t, store.RoleAdmin, false)
	body := `{"name":"x","kind":"webhook","enabled":true,"webhook":{"url":"https://hooks.example.com/x","allow_private_network":false},"secret":"` + hookSecret + `"}`
	if rec := a.do(t, "POST", "/api/v1/notifications/channels", body, noReauth, ""); rec.Code != http.StatusForbidden ||
		!strings.Contains(rec.Body.String(), "reauth_required") {
		t.Fatalf("criar canal sem reautenticação: %d %s", rec.Code, rec.Body.String())
	}
	// Sem reautenticação ainda dá para ver, testar e reenviar.
	if rec := a.do(t, "GET", "/api/v1/notifications/outbox", "", noReauth, ""); rec.Code != http.StatusOK {
		t.Fatalf("ler a caixa de saída: %d", rec.Code)
	}
}

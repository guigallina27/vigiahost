// Etapas da Fase 1B: notificações por webhook assinado (E1.12), regras YARA e LMD (E1.10) e ajuste de recursos com
// as métricas de desempenho (E1.13). Tudo o que estas etapas criam leva e2eTag e é desfeito no fim, inclusive em
// falha (onFailure), para a instalação compartilhada do laboratório voltar ao estado anterior.
package main

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/guigallina27/vigiahost/internal/api"
)

const (
	engineLMD = "lmd"
	// notifyWait é o prazo para a mensagem agrupada de achados chegar: 60 s de agrupamento (docs/notificacoes.md,
	// seção 1), o ciclo de 5 s do despachante e folga para o envio.
	notifyWait = 3 * time.Minute
	// notifyQuiet é quanto esperar sem mensagem nova para concluir que a repetição não duplicou.
	notifyQuiet = 90 * time.Second
	// notifyDirPrefix é o diretório do marcador da etapa de notificações (limpo também em cleanupLeftovers).
	notifyDirPrefix = "/var/tmp/vh-e2e-notif-"
)

// ---------------------------------------------------------------------------------------------------------------
// Receptor de webhook (Standard Webhooks), local em 127.0.0.1

// webhookBody segue docs/notificacoes.md, seção 3.3. Sem DisallowUnknownFields: o documento avisa que campos novos
// podem aparecer e que o receptor deve ignorá-los.
type webhookBody struct {
	Type      string    `json:"type"`
	Timestamp time.Time `json:"timestamp"`
	Data      struct {
		ID             string         `json:"id"`
		Server         string         `json:"server"`
		Version        string         `json:"version"`
		Test           bool           `json:"test"`
		Summary        string         `json:"summary"`
		Count          int            `json:"count"`
		SeverityCounts map[string]int `json:"severity_counts"`
		Items          []webhookItem  `json:"items"`
		ItemsTruncated bool           `json:"items_truncated"`
	} `json:"data"`
}

type webhookItem struct {
	Event     string `json:"event"`
	Severity  string `json:"severity"`
	Title     string `json:"title"`
	FindingID int64  `json:"finding_id"`
	RunID     string `json:"run_id"`
	Engine    string `json:"engine"`
	Path      string `json:"path"`
	SHA256    string `json:"sha256"`
}

type webhookMsg struct {
	id   string
	at   time.Time
	body webhookBody
}

// webhookReceiver confere cada requisição como o receptor de um cliente deve fazer (docs/notificacoes.md, 3.4):
// corpo bruto, os três cabeçalhos, carimbo de tempo a até 5 minutos, HMAC-SHA256 comparado em tempo constante e
// descarte de webhook-id repetido. Só as mensagens aprovadas ficam em msgs; os motivos das recusas ficam em bad.
type webhookReceiver struct {
	key  []byte
	srv  *http.Server
	url  string
	mu   sync.Mutex
	msgs []webhookMsg
	seen map[string]bool
	dups int
	bad  []string
}

func startWebhookReceiver(key []byte) *webhookReceiver {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		fatalf("receptor de webhook do teste não abriu porta em 127.0.0.1: %v", err)
	}
	wr := &webhookReceiver{key: key, seen: map[string]bool{},
		url: fmt.Sprintf("http://%s/vh-e2e-webhook", ln.Addr().String())}
	wr.srv = &http.Server{Handler: wr, ReadHeaderTimeout: 10 * time.Second}
	go func() { _ = wr.srv.Serve(ln) }()
	return wr
}

func (wr *webhookReceiver) stop() { _ = wr.srv.Close() }

func (wr *webhookReceiver) reject(w http.ResponseWriter, code int, format string, a ...any) {
	wr.mu.Lock()
	wr.bad = append(wr.bad, fmt.Sprintf(format, a...))
	wr.mu.Unlock()
	http.Error(w, "recusado", code)
}

func (wr *webhookReceiver) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost || r.URL.Path != "/vh-e2e-webhook" {
		wr.reject(w, http.StatusNotFound, "%s %s inesperado", r.Method, r.URL.Path)
		return
	}
	raw, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil {
		wr.reject(w, http.StatusBadRequest, "corpo não lido: %v", err)
		return
	}
	if ct := r.Header.Get("Content-Type"); !strings.HasPrefix(ct, "application/json") {
		wr.reject(w, http.StatusUnsupportedMediaType, "Content-Type %q", ct)
		return
	}
	if ua := r.Header.Get("User-Agent"); !strings.HasPrefix(ua, "VigiaHost/") {
		wr.reject(w, http.StatusBadRequest, "User-Agent %q", ua)
		return
	}
	id, tsRaw, sigs := r.Header.Get("webhook-id"), r.Header.Get("webhook-timestamp"), r.Header.Get("webhook-signature")
	if id == "" || tsRaw == "" || sigs == "" {
		wr.reject(w, http.StatusUnauthorized, "cabeçalhos do Standard Webhooks ausentes")
		return
	}
	ts, err := strconv.ParseInt(tsRaw, 10, 64)
	if err != nil || time.Since(time.Unix(ts, 0)).Abs() > 5*time.Minute {
		wr.reject(w, http.StatusUnauthorized, "webhook-timestamp %q fora da tolerância de 5 minutos", tsRaw)
		return
	}
	mac := hmac.New(sha256.New, wr.key)
	mac.Write([]byte(id + "." + tsRaw + "."))
	mac.Write(raw)
	want := mac.Sum(nil)
	valid := false
	for _, s := range strings.Fields(sigs) {
		v, found := strings.CutPrefix(s, "v1,")
		if !found {
			continue
		}
		got, err := base64.StdEncoding.DecodeString(v)
		if err == nil && hmac.Equal(got, want) {
			valid = true
		}
	}
	if !valid {
		wr.reject(w, http.StatusUnauthorized, "assinatura de %s não confere com o segredo do canal", id)
		return
	}
	var body webhookBody
	if err := json.Unmarshal(raw, &body); err != nil {
		wr.reject(w, http.StatusBadRequest, "corpo de %s não é JSON válido: %v", id, err)
		return
	}
	if body.Data.ID != id {
		wr.reject(w, http.StatusBadRequest, "data.id %q diferente do webhook-id %q", body.Data.ID, id)
		return
	}
	wr.mu.Lock()
	defer wr.mu.Unlock()
	if wr.seen[id] {
		// Repetido: responde 2xx para o core não tentar de novo, mas não conta como mensagem nova.
		wr.dups++
		w.WriteHeader(http.StatusNoContent)
		return
	}
	wr.seen[id] = true
	wr.msgs = append(wr.msgs, webhookMsg{id: id, at: time.Now(), body: body})
	w.WriteHeader(http.StatusNoContent)
}

// snapshot devolve uma cópia das mensagens aprovadas, das recusas e dos repetidos.
func (wr *webhookReceiver) snapshot() ([]webhookMsg, []string, int) {
	wr.mu.Lock()
	defer wr.mu.Unlock()
	return append([]webhookMsg(nil), wr.msgs...), append([]string(nil), wr.bad...), wr.dups
}

// waitFor espera uma mensagem aprovada que satisfaça match, até o prazo; recusas do receptor encerram o teste.
func (wr *webhookReceiver) waitFor(match func(webhookMsg) bool, timeout time.Duration) (webhookMsg, bool) {
	deadline := time.Now().Add(timeout)
	for {
		msgs, bad, _ := wr.snapshot()
		if len(bad) > 0 {
			fatalf("o receptor do teste recusou requisição(ões) do core: %s", strings.Join(bad, "; "))
		}
		for _, m := range msgs {
			if match(m) {
				return m, true
			}
		}
		if time.Now().After(deadline) {
			return webhookMsg{}, false
		}
		time.Sleep(time.Second)
	}
}

func (m webhookMsg) item(findingID int64) *webhookItem {
	for i := range m.body.Data.Items {
		if m.body.Data.Items[i].FindingID == findingID {
			return &m.body.Data.Items[i]
		}
	}
	return nil
}

func (m webhookMsg) hasFinding(id int64) bool { return m.item(id) != nil }

// ---------------------------------------------------------------------------------------------------------------
// Notificações (E1.12)

func (t *tester) channelByID(id int64) *api.NotificationChannel {
	var list []api.NotificationChannel
	t.get("/api/v1/notifications/channels", &list)
	for i := range list {
		if list[i].Id == id {
			return &list[i]
		}
	}
	return nil
}

func (t *tester) stepNotifications(sr scanResult) {
	// Segredo no formato recomendado: whsec_ + base64 de 32 bytes aleatórios (a chave do HMAC são os bytes).
	keyBytes := make([]byte, 32)
	if _, err := rand.Read(keyBytes); err != nil {
		fatalf("gerador aleatório: %v", err)
	}
	secret := "whsec_" + base64.StdEncoding.EncodeToString(keyBytes)
	recv := startWebhookReceiver(keyBytes)
	defer recv.stop()

	name := e2eTag + "-webhook-" + randHex(3)
	in := api.NotificationChannelInput{Name: name, Kind: api.Webhook, Enabled: true, IncludeDetails: ptrTo(true),
		Secret: &secret, Webhook: &api.WebhookSettings{Url: recv.url, AllowPrivateNetwork: true}}

	if time.Now().After(t.reauthUntil) {
		r := t.send(http.MethodPost, "/api/v1/notifications/channels", in, reqOpts{})
		if r.status != http.StatusForbidden || r.errCode() != "reauth_required" {
			fatalf("canal de notificação sem reautenticação recente deveria responder 403 reauth_required: %s", r.describe())
		}
		info("canal de notificação sem reautenticação recente recusado (403 reauth_required)")
	}
	t.ensureReauth("criar o canal de notificação")

	// Política de rede (SSRF): metadados de nuvem recusados mesmo com rede privada liberada; loopback só com ela.
	meta := in
	meta.Name = name + "-meta"
	meta.Webhook = &api.WebhookSettings{Url: "http://169.254.169.254/latest/meta-data/", AllowPrivateNetwork: true}
	if r := t.send(http.MethodPost, "/api/v1/notifications/channels", meta, reqOpts{}); r.status != http.StatusBadRequest {
		fatalf("webhook para 169.254.169.254 (metadados de nuvem) deveria ser recusado com 400: %s", r.describe())
	}
	local := in
	local.Name = name + "-local"
	local.Webhook = &api.WebhookSettings{Url: recv.url, AllowPrivateNetwork: false}
	if r := t.send(http.MethodPost, "/api/v1/notifications/channels", local, reqOpts{}); r.status != http.StatusBadRequest {
		fatalf("webhook para 127.0.0.1 sem \"permitir rede privada\" deveria ser recusado com 400: %s", r.describe())
	}

	var ch api.NotificationChannel
	t.call(http.MethodPost, "/api/v1/notifications/channels", in, reqOpts{}, http.StatusCreated, &ch)
	removeChannel := onFailure(func() { t.dropChannel(ch.Id) })
	if ch.Name != name || ch.Kind != api.Webhook || !ch.Enabled || !ch.SecretConfigured || !ch.SecretReadable ||
		ch.Webhook == nil || ch.Webhook.Url != recv.url || !ch.Webhook.AllowPrivateNetwork || ch.CreatedBy != t.creds.Username {
		fatalf("canal de webhook criado com dados inesperados (configurado=%v, legível=%v)", ch.SecretConfigured, ch.SecretReadable)
	}

	// A lista nunca devolve o segredo: nem o texto informado, nem a chave em base64, nem um campo "secret".
	r := t.call(http.MethodGet, "/api/v1/notifications/channels", nil, reqOpts{}, http.StatusOK, nil)
	b64 := strings.TrimPrefix(secret, "whsec_")
	if strings.Contains(string(r.body), b64) || strings.Contains(string(r.body), `"secret"`) {
		fatalf("GET /api/v1/notifications/channels devolveu o segredo do webhook")
	}
	var list []api.NotificationChannel
	r.decode(&list)
	if got := t.channelByID(ch.Id); got == nil || !got.SecretConfigured {
		fatalf("canal %d ausente da lista ou sem \"segredo configurado\"", ch.Id)
	}
	info("canal %d criado; a lista mostra só secret_configured=true; 169.254.169.254 e loopback sem liberação recusados",
		ch.Id)

	// Enviar teste: síncrono, com o resultado real; a mensagem chega assinada ao receptor. O webhook-id do teste é
	// msg_test_<aleatório> (internal/notify), não o número da caixa de saída das mensagens de eventos.
	testStart := time.Now()
	var tr api.NotificationTestResult
	t.call(http.MethodPost, fmt.Sprintf("/api/v1/notifications/channels/%d/test", ch.Id), nil, reqOpts{}, http.StatusOK, &tr)
	if !tr.Ok || tr.Entry.Event != api.OutboxEventTest || tr.Entry.State != api.OutboxSent {
		fatalf("envio de teste do canal %d: ok=%v, evento %s, estado %s, erro %q", ch.Id, tr.Ok, tr.Entry.Event,
			tr.Entry.State, deref(tr.Error))
	}
	tm, found := recv.waitFor(func(m webhookMsg) bool { return m.body.Type == "test" && !m.at.Before(testStart) },
		10*time.Second)
	if !found {
		fatalf("o envio de teste %d foi dado como entregue, mas não chegou ao receptor", tr.Entry.Id)
	}
	testID := tm.id
	if !strings.HasPrefix(testID, "msg_") {
		fatalf("mensagem de teste com webhook-id fora do formato msg_...: %q", testID)
	}
	if tm.body.Type != "test" || !tm.body.Data.Test || tm.body.Data.Summary == "" || tm.body.Data.Server == "" {
		fatalf("mensagem de teste %s com corpo inesperado: tipo %q, test=%v, resumo %q", testID, tm.body.Type,
			tm.body.Data.Test, tm.body.Data.Summary)
	}
	ok("notificações: canal de webhook %d com segredo whsec_ (só \"configurado\" na API); envio de teste %s entregue com "+
		"assinatura Standard Webhooks conferida pelo receptor local; metadados de nuvem (169.254.169.254) recusados", ch.Id, testID)

	// Regra: achado novo a partir da severidade do marcador de controle.
	sev := t.finding(sr.markerID).Finding.Severity
	t.ensureReauth("criar a regra de notificação")
	var rule api.NotificationRule
	t.call(http.MethodPost, "/api/v1/notifications/rules", api.NotificationRuleInput{ChannelId: ch.Id,
		Event: api.NotificationEventFindingNew, MinSeverity: &sev, Enabled: ptrTo(true)}, reqOpts{}, http.StatusCreated, &rule)
	removeRule := onFailure(func() { t.dropRule(rule.Id) })
	if rule.ChannelId != ch.Id || rule.Event != api.NotificationEventFindingNew || rule.MinSeverity != sev || !rule.Enabled ||
		rule.DedupMinutes <= 0 {
		fatalf("regra de notificação criada com dados inesperados: %+v", rule)
	}

	// Marcador inerte novo (conteúdo inédito = achado novo) num diretório só do teste.
	dir := notifyDirPrefix + randHex(4)
	file := filepath.Join(dir, "marcador.txt")
	if err := os.MkdirAll(dir, 0o750); err != nil {
		fatalf("criar %s: %v", dir, err)
	}
	removeDir := onFailure(func() { _ = os.RemoveAll(dir) })
	defer func() { _ = os.RemoveAll(dir); removeDir() }()
	data := fmt.Sprintf("VIGIAHOST-CONTROLE-POSITIVO-INERTE-7f3c9a1e %s notificacao %s\n", e2eTag, randHex(8))
	if err := os.WriteFile(file, []byte(data), 0o640); err != nil {
		fatalf("criar %s: %v", file, err)
	}

	scan := func(label string) (api.RunDetail, int64) {
		body := api.RunCreate{Kind: "files", Paths: &[]string{dir}, Profile: ptrTo(profileName), Incremental: ptrTo(false)}
		run := t.createRun(body, label)
		d := t.waitRun(run.Id, label)
		requireCompleted(d, label)
		var id int64
		for _, f := range t.runFindings(run.Id) {
			if f.Engine == engineYARA && f.Signature == sigControl {
				for _, l := range t.finding(f.Id).Locations {
					if locPath(l) == file {
						id = f.Id
					}
				}
			}
		}
		if id == 0 {
			fatalf("%s %s não detectou o marcador em %s", label, run.Id, file)
		}
		return d, id
	}
	d1, fid := scan("varredura com notificação")
	sent := time.Now()
	f := t.finding(fid).Finding
	if f.State != "new" || f.Severity != sev {
		fatalf("achado %d do marcador novo deveria estar new com severidade %s (estado %s, severidade %s)", fid, sev,
			f.State, f.Severity)
	}
	msg, found := recv.waitFor(func(m webhookMsg) bool { return m.body.Type == "finding_new" && m.hasFinding(fid) }, notifyWait)
	if !found {
		fatalf("a mensagem de achado novo do achado %d (execução %s) não chegou ao webhook em %s", fid, d1.Run.Id, notifyWait)
	}
	item := msg.item(fid)
	if msg.body.Data.Test || msg.body.Data.Count < 1 || msg.body.Data.Count < len(msg.body.Data.Items) ||
		msg.body.Data.SeverityCounts[string(sev)] < 1 || item == nil || item.Event != "finding_new" ||
		item.Severity != string(sev) || item.Engine != engineYARA || item.RunID != d1.Run.Id || item.Path != file ||
		f.Sha256 == nil || item.SHA256 != *f.Sha256 {
		fatalf("mensagem agrupada %s com dados inesperados: contagem %d, severidades %v, item %+v", msg.id,
			msg.body.Data.Count, msg.body.Data.SeverityCounts, item)
	}
	var outbox api.OutboxPage
	t.get(fmt.Sprintf("/api/v1/notifications/outbox?channel_id=%d&limit=50", ch.Id), &outbox)
	var entry *api.OutboxEntry
	for i := range outbox.Entries {
		if fmt.Sprintf("msg_%d", outbox.Entries[i].Id) == msg.id {
			entry = &outbox.Entries[i]
		}
	}
	if entry == nil || entry.Event != api.OutboxEventFindingNew || entry.State != api.OutboxSent || entry.SentAt == nil {
		fatalf("caixa de saída sem a mensagem %s enviada (finding_new, sent)", msg.id)
	}
	info("mensagem agrupada %s chegou %s depois do fim da varredura: %d achado(s), severidades %v, resumo %q",
		msg.id, msg.at.Sub(sent).Round(time.Second), msg.body.Data.Count, msg.body.Data.SeverityCounts, msg.body.Data.Summary)

	// Repetir a varredura revê o mesmo achado: nenhuma mensagem nova com ele.
	cut := time.Now()
	d2, again := scan("varredura repetida com notificação")
	if again != fid {
		fatalf("a varredura repetida %s criou outro achado (%d) para o mesmo marcador (%d)", d2.Run.Id, again, fid)
	}
	info("aguardando %s (janela de agrupamento e envio) para confirmar que a repetição não notifica", notifyQuiet)
	if dup, found := recv.waitFor(func(m webhookMsg) bool { return m.at.After(cut) && m.hasFinding(fid) },
		notifyQuiet); found {
		fatalf("a varredura repetida %s notificou de novo o achado %d (mensagem %s)", d2.Run.Id, fid, dup.id)
	}
	if _, bad, dups := recv.snapshot(); len(bad) > 0 || dups > 0 {
		fatalf("receptor com %d recusa(s) e %d webhook-id repetido(s): %v", len(bad), dups, bad)
	}

	// Limpeza: regra, canal, achado e marcador.
	t.ensureReauth("apagar a regra e o canal de notificação")
	t.call(http.MethodDelete, fmt.Sprintf("/api/v1/notifications/rules/%d", rule.Id), nil, reqOpts{}, http.StatusNoContent, nil)
	removeRule()
	t.call(http.MethodDelete, fmt.Sprintf("/api/v1/notifications/channels/%d", ch.Id), nil, reqOpts{}, http.StatusNoContent, nil)
	removeChannel()
	if t.channelByID(ch.Id) != nil {
		fatalf("canal %d continua na lista depois de apagado", ch.Id)
	}
	t.transition(fid, "resolved", e2eTag+": marcador da etapa de notificações removido")
	t.auditExtra = append(t.auditExtra, "notification_channel_created", "notification_test", "notification_rule_created",
		"notification_rule_deleted", "notification_channel_deleted")
	ok("notificações: regra \"achado novo a partir de %s\" %d; varredura %s gerou o achado %d e uma mensagem agrupada "+
		"%s assinada (agrupamento de 60 s); a varredura repetida %s não duplicou; regra, canal e achado desfeitos",
		sev, rule.Id, d1.Run.Id, fid, msg.id, d2.Run.Id)
}

// dropRule e dropChannel desfazem o que a etapa criou quando o teste falha no meio (melhor esforço, sem fatalf).
func (t *tester) dropRule(id int64) {
	t.ensureReauth("apagar a regra de notificação do teste")
	_ = t.send(http.MethodDelete, fmt.Sprintf("/api/v1/notifications/rules/%d", id), nil, reqOpts{})
}

func (t *tester) dropChannel(id int64) {
	t.ensureReauth("apagar o canal de notificação do teste")
	_ = t.send(http.MethodDelete, fmt.Sprintf("/api/v1/notifications/channels/%d", id), nil, reqOpts{})
}

// ---------------------------------------------------------------------------------------------------------------
// Regras YARA e LMD (E1.10)

func (t *tester) rules() api.RulesOverview {
	var ro api.RulesOverview
	t.get("/api/v1/rules", &ro)
	if ro.ExecutorError != nil {
		fatalf("regras: executor respondeu com erro: %s", *ro.ExecutorError)
	}
	return ro
}

func (t *tester) setLMD(enabled bool) api.RulesOverview {
	t.ensureReauth("ligar ou desligar o LMD")
	var ro api.RulesOverview
	t.call(http.MethodPut, "/api/v1/rules/lmd", api.ToggleInput{Enabled: enabled}, reqOpts{}, http.StatusOK, &ro)
	if ro.Lmd.Enabled != enabled {
		fatalf("PUT /api/v1/rules/lmd enabled=%v devolveu enabled=%v", enabled, ro.Lmd.Enabled)
	}
	return ro
}

func (t *tester) stepRules(pos string) {
	ro := t.rules()
	var compiled, rulesN int
	var control *api.RuleSource
	for i := range ro.Yara.Sources {
		s := &ro.Yara.Sources[i]
		if s.State == api.RuleSourceStateOk {
			compiled++
			rulesN += s.Rules
		}
		if s.Mandatory {
			control = s
		}
	}
	if compiled == 0 || rulesN == 0 {
		fatalf("regras: nenhuma fonte YARA compilada (%d fontes listadas)", len(ro.Yara.Sources))
	}
	if control == nil || control.State != api.RuleSourceStateOk || !control.Enabled {
		fatalf("regras: fonte obrigatória do controle positivo ausente ou fora do conjunto compilado")
	}
	lmd := ro.Lmd
	if !lmd.Installed || !lmd.Usable || lmd.Version == nil || !strings.HasPrefix(*lmd.Version, "2.") {
		fatalf("regras: LMD 2.x deveria aparecer instalado e utilizável em %s (instalado=%v, utilizável=%v, versão %q, %s)",
			lmd.Path, lmd.Installed, lmd.Usable, deref(lmd.Version), deref(lmd.Detail))
	}
	sigs := 0
	if lmd.Signatures != nil {
		s := lmd.Signatures
		sigs = s.Md5 + s.Hex + s.Sha256 + s.Yara + s.Csig + s.User
	}
	if sigs == 0 {
		fatalf("regras: LMD %s sem assinaturas contadas", *lmd.Version)
	}
	orig := lmd.Enabled
	ok("regras: %d fonte(s) YARA compilada(s) com %d regras (controle positivo obrigatório no conjunto, yr %s); LMD %s "+
		"instalado em %s com %d assinaturas, ligado=%v", compiled, rulesN, deref(ro.Yara.YrVersion), *lmd.Version, lmd.Path,
		sigs, orig)

	// Ligar o LMD exige reautenticação; o estado original volta no fim (ou na falha).
	if time.Now().After(t.reauthUntil) {
		r := t.send(http.MethodPut, "/api/v1/rules/lmd", api.ToggleInput{Enabled: true}, reqOpts{})
		if r.status != http.StatusForbidden || r.errCode() != "reauth_required" {
			fatalf("ligar o LMD sem reautenticação recente deveria responder 403 reauth_required: %s", r.describe())
		}
		info("ligar o LMD sem reautenticação recente recusado (403 reauth_required)")
	}
	restore := onFailure(func() {
		t.ensureReauth("devolver o LMD ao estado original")
		_ = t.send(http.MethodPut, "/api/v1/rules/lmd", api.ToggleInput{Enabled: orig}, reqOpts{})
	})
	on := t.setLMD(true)
	if on.Lmd.State == api.EngineStateDisabled || on.Lmd.State == api.EngineStateNotInstalled {
		fatalf("LMD ligado com estado %s", on.Lmd.State)
	}

	label := "varredura com o LMD"
	body := api.RunCreate{Kind: "files", Paths: &[]string{pos}, Profile: ptrTo(profileName), Incremental: ptrTo(false)}
	run := t.createRun(body, label)
	d := t.waitRun(run.Id, label)
	requireCompleted(d, label)
	checkFilesCoverage(d, label)
	var cov *api.EngineCoverage
	for i := range d.Engines {
		if d.Engines[i].Engine == engineLMD {
			cov = &d.Engines[i]
		}
	}
	if cov == nil {
		fatalf("%s %s sem cobertura do motor %s (%s)", label, run.Id, engineLMD, describeRun(d))
	}
	if !cov.Available || !cov.SelftestPassed || cov.Error != "" || cov.Analyzed <= 0 || cov.Analyzed > cov.Eligible {
		fatalf("%s %s: motor lmd disponível=%v autoteste=%v (%s) erro=%q, %d de %d analisados", label, run.Id,
			cov.Available, cov.SelftestPassed, cov.SelftestDetail, cov.Error, cov.Analyzed, cov.Eligible)
	}
	var lmdHits []string
	negativos := filepath.Join(pos, "negativos") + "/"
	for _, f := range t.runFindings(run.Id) {
		if f.Engine != engineLMD {
			continue
		}
		p := ""
		if f.Location != nil {
			p = locPath(*f.Location)
		}
		if strings.HasPrefix(p, negativos) {
			fatalf("o LMD acusou o controle negativo %q (achado %d, %s)", p, f.Id, f.Signature)
		}
		lmdHits = append(lmdHits, f.Signature)
	}
	if len(lmdHits) == 0 {
		fatalf("%s %s sem achados do motor lmd nos positivos", label, run.Id)
	}
	info("lmd %s: %d de %d elegíveis analisados (%d pelo cache), %.1f s, autoteste aprovado; assinaturas %v",
		cov.Version, cov.Analyzed, cov.Eligible, cov.FromCache, cov.Seconds, lmdHits)

	off := t.setLMD(orig)
	restore()
	if !orig && off.Lmd.State != api.EngineStateDisabled {
		fatalf("LMD desligado com estado %s (esperado disabled)", off.Lmd.State)
	}
	t.auditExtra = append(t.auditExtra, "lmd_enabled")
	if !orig {
		t.auditExtra = append(t.auditExtra, "lmd_disabled")
	}
	ok("LMD ligado com reautenticação; varredura completa %s dos positivos com cobertura do lmd (autoteste aprovado) e "+
		"%d achado(s) do motor lmd; LMD devolvido ao estado original (ligado=%v)", run.Id, len(lmdHits), orig)

	// Compilação manual: responde na hora e termina com validação e controle positivo no conjunto.
	asked := time.Now().Add(-2 * time.Second)
	var cr api.RulesOverview
	deadline := time.Now().Add(5 * time.Minute)
	for {
		r := t.send(http.MethodPost, "/api/v1/rules/compile", nil, reqOpts{})
		if r.status == http.StatusOK {
			r.decode(&cr)
			break
		}
		if r.status != http.StatusConflict || time.Now().After(deadline) {
			fatalf("POST /api/v1/rules/compile: %s", r.describe())
		}
		info("já há uma compilação de regras em andamento; tentando de novo")
		time.Sleep(5 * time.Second)
	}
	for {
		cr = t.rules()
		lc := cr.Yara.LastCompile
		if !cr.Yara.Compiling && lc != nil && lc.Trigger == api.RulesCompileResultTriggerManual && !lc.At.Before(asked) {
			if !lc.Ok || lc.Selftest == nil || !*lc.Selftest || lc.SetVersion == nil {
				fatalf("compilação manual das regras falhou: ok=%v, controle positivo=%v, erro %q, %s", lc.Ok,
					lc.Selftest != nil && *lc.Selftest, deref(lc.Error), deref(lc.Detail))
			}
			detail := ""
			if lc.Detail != nil && *lc.Detail != "" {
				detail = " (" + *lc.Detail + ")"
			}
			ok("compilação manual das regras: concluída com validação, controle positivo detectado no conjunto %s%s",
				*lc.SetVersion, detail)
			break
		}
		if time.Now().After(deadline) {
			fatalf("a compilação manual das regras não terminou em 5 minutos (compilando=%v)", cr.Yara.Compiling)
		}
		time.Sleep(2 * time.Second)
	}
	t.auditExtra = append(t.auditExtra, "rules_compile_requested")
}

// ---------------------------------------------------------------------------------------------------------------
// Recursos e desempenho (E1.13)

// unitCPUMax lê o cpu.max do cgroup da unidade da execução (o programa roda como root no próprio laboratório).
func unitCPUMax(runID string) (string, string, error) {
	unit := "vigiahost-run-" + runID + ".service"
	out, err := exec.Command("systemctl", "show", "-P", "ControlGroup", unit).Output()
	if err != nil {
		return "", "", fmt.Errorf("systemctl show %s: %w", unit, err)
	}
	cg := strings.TrimSpace(string(out))
	if cg == "" {
		return "", "", fmt.Errorf("unidade %s sem cgroup (não está rodando)", unit)
	}
	p := filepath.Join("/sys/fs/cgroup", cg, "cpu.max")
	data, err := os.ReadFile(p)
	if err != nil {
		return p, "", err
	}
	return p, strings.TrimSpace(string(data)), nil
}

// cpuPercent converte "quota período" do cpu.max em % de um núcleo ("max" = sem limite, -1).
func cpuPercent(v string) int {
	f := strings.Fields(v)
	if len(f) != 2 || f[0] == "max" {
		return -1
	}
	q, err1 := strconv.ParseInt(f[0], 10, 64)
	per, err2 := strconv.ParseInt(f[1], 10, 64)
	if err1 != nil || err2 != nil || per <= 0 {
		return -1
	}
	return int((q*100 + per/2) / per)
}

func (t *tester) stepResources(dirs []string) {
	var res api.Resources
	t.get("/api/v1/resources", &res)
	if res.ExecutorError != nil || res.Hardware == nil || res.Hardware.Cpus <= 0 || len(res.Profiles) == 0 {
		fatalf("recursos: hardware ou perfis ausentes (erro do executor %q)", deref(res.ExecutorError))
	}
	var sg api.ProfileSuggestion
	t.get("/api/v1/resources/suggestion", &sg)
	if len(sg.Reasons) == 0 || sg.Basis.Cpus <= 0 || sg.Basis.MemoryBytes <= 0 || sg.Profile.CpuQuotaPercent <= 0 ||
		sg.Profile.Workers <= 0 {
		fatalf("sugestão de perfil sem explicação ou incompleta (%d explicações, %d CPUs, CPU %d%%, %d workers)",
			len(sg.Reasons), sg.Basis.Cpus, sg.Profile.CpuQuotaPercent, sg.Profile.Workers)
	}
	var codes []string
	for _, r := range sg.Reasons {
		codes = append(codes, string(r.Code))
	}
	ok("recursos: %d CPUs, %d MiB, %d perfis; sugestão %q (CPU %d%%, %d workers, %d MiB) com %d explicação(ões): %s",
		res.Hardware.Cpus, res.Hardware.MemoryBytes>>20, len(res.Profiles), sg.Profile.Name, sg.Profile.CpuQuotaPercent,
		sg.Profile.Workers, sg.Profile.MemoryMaxBytes>>20, len(sg.Reasons), strings.Join(codes, ", "))

	for i, dir := range dirs {
		if t.adjustDuringScan(dir, i == len(dirs)-1) {
			return
		}
	}
}

// adjustDuringScan roda uma varredura completa de dir e, enquanto ela roda, reduz a CPU pela API. Devolve false
// quando a varredura terminou antes do ajuste e ainda há outra pasta para tentar (last=false).
func (t *tester) adjustDuringScan(dir string, last bool) bool {
	label := "varredura grande"
	// Reautentica antes de enfileirar: o ajuste precisa sair enquanto a execução ainda roda.
	t.ensureReauth("ajustar os limites da execução")
	body := api.RunCreate{Kind: "files", Paths: &[]string{dir}, Profile: ptrTo(profileName), Incremental: ptrTo(false)}
	run := t.createRun(body, label)
	cancel := onFailure(func() {
		_ = t.send(http.MethodPost, "/api/v1/runs/"+run.Id+"/cancel", nil, reqOpts{})
	})
	defer cancel()

	// Espera a execução rodar com a unidade e o cgroup no ar.
	var cur api.Run
	var cgPath, before string
	for deadline := time.Now().Add(t.cfg.runTimeout); ; {
		var d api.RunDetail
		t.get("/api/v1/runs/"+run.Id, &d)
		cur = d.Run
		if terminal(cur.Status) {
			break
		}
		if cur.Status == "running" {
			if p, v, err := unitCPUMax(run.Id); err == nil {
				cgPath, before = p, v
				break
			}
		}
		if time.Now().After(deadline) {
			fatalf("%s %s não começou a rodar em %s (estado %s)", label, run.Id, t.cfg.runTimeout, cur.Status)
		}
		time.Sleep(300 * time.Millisecond)
	}
	if terminal(cur.Status) {
		if last {
			fatalf("%s %s de %s terminou (%s) antes de dar tempo de ajustar os limites", label, run.Id, dir, cur.Status)
		}
		warn("%s %s de %s terminou antes do ajuste; tentando uma pasta maior", label, run.Id, dir)
		return false
	}

	oldCPU := cur.Profile.CpuQuotaPercent
	newCPU := oldCPU / 2
	switch {
	case oldCPU == 0:
		newCPU = 100
	case newCPU < 10:
		newCPU = oldCPU + 10
	}
	if cpuPercent(before) != oldCPU && oldCPU != 0 {
		warn("cpu.max antes do ajuste (%q) não corresponde ao perfil (%d%%)", before, oldCPU)
	}
	r := t.send(http.MethodPost, "/api/v1/runs/"+run.Id+"/adjust", api.RunAdjustRequest{CpuQuotaPercent: &newCPU}, reqOpts{})
	if (r.status == http.StatusConflict || r.status == http.StatusNotFound) && !last {
		warn("%s %s de %s terminou durante o ajuste (%s); tentando uma pasta maior", label, run.Id, dir, r.describe())
		t.waitRun(run.Id, label)
		return false
	}
	if r.status != http.StatusOK {
		fatalf("ajuste de CPU da execução %s: %s", run.Id, r.describe())
	}
	var adj api.Run
	r.decode(&adj)
	if adj.Profile.CpuQuotaPercent != newCPU || adj.Adjustments == nil || len(*adj.Adjustments) == 0 {
		fatalf("ajuste de CPU da execução %s não registrado (CPU %d%%, ajustes %v)", run.Id, adj.Profile.CpuQuotaPercent,
			adj.Adjustments)
	}
	last1 := (*adj.Adjustments)[len(*adj.Adjustments)-1]
	if last1.Before.CpuQuotaPercent != oldCPU || last1.After.CpuQuotaPercent != newCPU || last1.Actor != t.creds.Username {
		fatalf("histórico de ajustes da execução %s inesperado: %+v", run.Id, last1)
	}
	// O cgroup reflete o ajuste (systemd aplica CPUQuotaPerSecUSec como cpu.max "quota período").
	var after string
	for deadline := time.Now().Add(10 * time.Second); ; {
		_, v, err := unitCPUMax(run.Id)
		if err == nil && cpuPercent(v) == newCPU {
			after = v
			break
		}
		if err != nil || time.Now().After(deadline) {
			var d api.RunDetail
			t.get("/api/v1/runs/"+run.Id, &d)
			if terminal(d.Run.Status) && !last {
				warn("%s %s terminou antes de conferir o cgroup; tentando uma pasta maior", label, run.Id)
				return false
			}
			fatalf("cpu.max da execução %s não mudou para %d%% (%q, erro %v)", run.Id, newCPU, v, err)
		}
		time.Sleep(300 * time.Millisecond)
	}
	info("CPU da execução %s ajustada de %d%% para %d%% durante a varredura: %s de %q para %q", run.Id, oldCPU, newCPU,
		cgPath, before, after)

	d := t.waitRun(run.Id, label)
	requireCompleted(d, label)
	checkFilesCoverage(d, label)
	cancel()
	sm := d.Run.Summary
	m := sm.Metrics
	if m == nil {
		fatalf("%s %s concluída sem métricas de desempenho", label, run.Id)
	}
	if m.Source != api.RunMetricsSourceCgroup || m.CpuSeconds <= 0 || m.MemoryPeakBytes <= 0 || len(m.Phases) == 0 ||
		sm.FilesPerSecond <= 0 {
		fatalf("métricas da execução %s incompletas: fonte %s, CPU %.2f s, memória %d, %d etapas, %.1f arquivos/s", run.Id,
			m.Source, m.CpuSeconds, m.MemoryPeakBytes, len(m.Phases), sm.FilesPerSecond)
	}
	var phases []string
	for _, p := range m.Phases {
		if p.Phase == "" || p.Seconds < 0 {
			fatalf("métricas da execução %s com etapa inválida: %+v", run.Id, p)
		}
		phases = append(phases, fmt.Sprintf("%s %.1f s", p.Phase, p.Seconds))
	}
	if d.Run.Adjustments == nil || len(*d.Run.Adjustments) == 0 {
		fatalf("detalhe da execução %s sem o histórico de ajustes", run.Id)
	}

	var cmp api.RunComparison
	t.get("/api/v1/runs/"+run.Id+"/comparison", &cmp)
	var mine *api.RunPerformance
	for i := range cmp.Runs {
		p := &cmp.Runs[i]
		if p.Id == run.Id {
			mine = p
		}
	}
	if cmp.Kind != "files" || len(cmp.Runs) < 2 || mine == nil || !mine.Current || mine.FilesPerSecond <= 0 ||
		mine.CpuSeconds == nil || *mine.CpuSeconds <= 0 || mine.MemoryPeakBytes == nil || *mine.MemoryPeakBytes <= 0 {
		fatalf("comparativo da execução %s incompleto (%d execuções, tipo %s, atual %+v)", run.Id, len(cmp.Runs), cmp.Kind, mine)
	}
	took := "?"
	if sm.StartedAt != nil && sm.FinishedAt != nil {
		took = sm.FinishedAt.Sub(*sm.StartedAt).Round(time.Second).String()
	}
	t.auditExtra = append(t.auditExtra, "run_limits_adjusted")
	ok("recursos: varredura completa %s de %s com CPU ajustada pela API de %d%% para %d%% em andamento (cpu.max %q, "+
		"auditoria run_limits_adjusted); métricas pelo cgroup: %d arquivos em %s, %.1f arquivos/s, CPU %.1f s, pico de "+
		"memória %d MiB, etapas [%s]; comparativo com %d execuções de arquivos", run.Id, dir, oldCPU, newCPU, after,
		d.Run.FilesEligible, took, sm.FilesPerSecond, m.CpuSeconds,
		m.MemoryPeakBytes>>20, strings.Join(phases, ", "), len(cmp.Runs))
	return true
}

// cleanupFase1B remove o que uma execução anterior interrompida deixou das etapas da Fase 1B.
func (t *tester) cleanupFase1B() int {
	n := 0
	var chs []api.NotificationChannel
	t.get("/api/v1/notifications/channels", &chs)
	for _, c := range chs {
		if strings.HasPrefix(c.Name, e2eTag) {
			t.ensureReauth("apagar canal de notificação deixado por execução anterior")
			t.call(http.MethodDelete, fmt.Sprintf("/api/v1/notifications/channels/%d", c.Id), nil, reqOpts{}, http.StatusNoContent, nil)
			n++
		}
	}
	if old, err := filepath.Glob(notifyDirPrefix + "*"); err == nil {
		for _, d := range old {
			if os.RemoveAll(d) == nil {
				n++
			}
		}
	}
	return n
}

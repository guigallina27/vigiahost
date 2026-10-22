package notify

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"mime"
	"mime/quotedprintable"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/guigallina27/vigiahost/internal/report"
	"github.com/guigallina27/vigiahost/internal/store"
)

const testSecret = "whsec_MfKQ9r8GKYqrTwjUPD8ILPZIo2LaLaSw" // 24 bytes depois do base64

// hookServer é um receptor de webhook que confere a assinatura como a documentação manda.
type hookServer struct {
	*httptest.Server
	mu     sync.Mutex
	status int
	got    []Payload
	ids    []string
	errs   []error
}

func newHook(t *testing.T, key []byte, now func() time.Time) *hookServer {
	t.Helper()
	h := &hookServer{status: http.StatusNoContent}
	h.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body := readAll(r.Body)
		h.mu.Lock()
		defer h.mu.Unlock()
		if err := Verify(key, r.Header, body, now(), DefaultTolerance); err != nil {
			h.errs = append(h.errs, err)
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		var p Payload
		if err := json.Unmarshal(body, &p); err != nil {
			h.errs = append(h.errs, err)
		}
		h.got = append(h.got, p)
		h.ids = append(h.ids, r.Header.Get(HeaderID))
		w.WriteHeader(h.status)
	}))
	t.Cleanup(h.Close)
	return h
}

func (h *hookServer) setStatus(code int) {
	h.mu.Lock()
	h.status = code
	h.mu.Unlock()
}

func (h *hookServer) received() ([]Payload, []string, []error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	return append([]Payload(nil), h.got...), append([]string(nil), h.ids...), append([]error(nil), h.errs...)
}

func findingEvent(id int64, sev string) Event {
	return Event{Item: Item{Event: store.EventFindingNew, Severity: sev, Title: fmt.Sprintf("ClamAV: Php.Webshell.%d", id),
		FindingID: id, RunID: "r1", Path: fmt.Sprintf("/home/ana/public_html/x%d.php", id), SHA256: strings.Repeat("a", 64)},
		Key: fmt.Sprintf("finding:%d", id)}
}

func TestWebhookAssinadoComDeduplicacaoEAgrupamento(t *testing.T) {
	ctx := context.Background()
	env := newEnv(t)
	key, err := WebhookKey(testSecret)
	if err != nil {
		t.Fatal(err)
	}
	hook := newHook(t, key, func() time.Time { return *env.now })
	ch := env.channel(t, "SOC", store.ChannelWebhook, WebhookConfig{URL: hook.URL + "/vigiahost", AllowPrivateNetwork: true}, testSecret)
	env.rule(t, ch.ID, store.EventFindingNew, "high", 1440)

	// 500 achados de uma vez (e um médio, abaixo do mínimo da regra) viram uma mensagem só.
	var events []Event
	for i := int64(1); i <= 500; i++ {
		sev := "high"
		if i == 1 {
			sev = "critical"
		}
		events = append(events, findingEvent(i, sev))
	}
	events = append(events, findingEvent(9999, "medium"))
	if err := env.svc.Emit(ctx, events...); err != nil {
		t.Fatal(err)
	}
	box := env.outbox(t)
	if len(box) != 1 || box[0].ItemCount != 500 || len(box[0].Items) != store.OutboxSampleItems {
		t.Fatalf("agrupamento: %d mensagens, %+v", len(box), box)
	}
	// Dentro da janela de agrupamento nada sai.
	env.svc.Step(ctx)
	if got, _, _ := hook.received(); len(got) != 0 {
		t.Fatal("a mensagem não deveria sair antes da janela de agrupamento")
	}
	env.advance(2 * time.Minute)
	env.svc.Step(ctx)
	got, ids, errs := hook.received()
	if len(errs) > 0 || len(got) != 1 {
		t.Fatalf("envio: %d mensagens, erros %v", len(got), errs)
	}
	p := got[0]
	if p.Type != store.EventFindingNew || p.Data.Count != 500 || !p.Data.ItemsTruncated || len(p.Data.Items) != 25 ||
		p.Data.SeverityCounts["critical"] != 1 || p.Data.SeverityCounts["high"] != 499 || p.Data.Server != "web01" {
		t.Fatalf("conteúdo do resumo: %+v", p.Data)
	}
	if !strings.Contains(p.Data.Summary, "500 achados novos") || ids[0] != fmt.Sprintf("msg_%d", box[0].ID) {
		t.Fatalf("resumo %q, id %q", p.Data.Summary, ids[0])
	}
	if e, _ := env.db.GetOutboxEntry(ctx, box[0].ID); e.State != store.OutboxSent || e.SentAt == nil || e.Attempts != 1 {
		t.Fatalf("estado depois do envio: %+v", e)
	}

	// O mesmo achado de novo dentro da janela de deduplicação não notifica; depois dela, sim.
	if err := env.svc.Emit(ctx, findingEvent(7, "high")); err != nil {
		t.Fatal(err)
	}
	if n := len(env.outbox(t)); n != 1 {
		t.Fatalf("achado repetido na janela entrou na caixa: %d mensagens", n)
	}
	env.advance(25 * time.Hour)
	if err := env.svc.Emit(ctx, findingEvent(7, "high")); err != nil {
		t.Fatal(err)
	}
	if n := len(env.outbox(t)); n != 2 {
		t.Fatalf("depois da janela o achado deveria notificar: %d mensagens", n)
	}
}

func TestWebhookRecuoExponencialEFalhaDefinitiva(t *testing.T) {
	ctx := context.Background()
	env := newEnv(t)
	env.svc.MaxAttempts = 3
	key, _ := WebhookKey(testSecret)
	hook := newHook(t, key, func() time.Time { return *env.now })
	hook.setStatus(http.StatusServiceUnavailable)
	ch := env.channel(t, "SOC", store.ChannelWebhook, WebhookConfig{URL: hook.URL, AllowPrivateNetwork: true}, testSecret)
	env.rule(t, ch.ID, store.EventRunFailed, "info", 60)
	if err := env.svc.Emit(ctx, Event{Item: Item{Event: store.EventRunFailed, Severity: "high", Title: "Execução r9 terminou com falha", RunID: "r9"}, Key: "run:r9"}); err != nil {
		t.Fatal(err)
	}
	env.svc.Step(ctx)
	e := env.outbox(t)[0]
	if e.State != store.OutboxPending || e.Attempts != 1 || !strings.Contains(e.LastError, "HTTP 503") {
		t.Fatalf("primeira falha deveria reagendar: %+v", e)
	}
	wait := e.NextAttemptAt.Sub(*env.now)
	if wait < 30*time.Second || wait > 33*time.Second {
		t.Fatalf("primeiro recuo deveria ser ~30 s: %v", wait)
	}
	// Antes do horário não tenta de novo.
	env.svc.Step(ctx)
	if got, _, _ := hook.received(); len(got) != 1 {
		t.Fatalf("tentou antes do recuo: %d", len(got))
	}
	env.advance(wait)
	env.svc.Step(ctx)
	e = env.outbox(t)[0]
	if wait2 := e.NextAttemptAt.Sub(*env.now); e.Attempts != 2 || wait2 < 60*time.Second || wait2 > 66*time.Second {
		t.Fatalf("segundo recuo deveria dobrar: %+v (%v)", e, wait2)
	}
	env.advance(2 * time.Minute)
	env.svc.Step(ctx)
	e = env.outbox(t)[0]
	if e.State != store.OutboxFailed || e.Attempts != 3 || e.NextAttemptAt != nil {
		t.Fatalf("no máximo de tentativas a falha é definitiva: %+v", e)
	}
	_, ids, _ := hook.received()
	if len(ids) != 3 || ids[0] != ids[2] {
		t.Fatalf("o webhook-id deve ser o mesmo em todas as tentativas: %v", ids)
	}

	// Reenviar põe de volta com as tentativas zeradas; com o receptor bom, sai.
	hook.setStatus(http.StatusOK)
	if _, err := env.db.RetryNotification(ctx, e.ID); err != nil {
		t.Fatal(err)
	}
	env.svc.Step(ctx)
	if e, _ = env.db.GetOutboxEntry(ctx, e.ID); e.State != store.OutboxSent || e.Attempts != 1 {
		t.Fatalf("reenvio: %+v", e)
	}
	if _, err := env.db.RetryNotification(ctx, e.ID); !errors.Is(err, store.ErrConflict) {
		t.Fatalf("mensagem enviada não reenvia: %v", err)
	}

	// 4xx (exceto 408/429) é recusa do receptor: falha definitiva na hora.
	hook.setStatus(http.StatusBadRequest)
	if err := env.svc.Emit(ctx, Event{Item: Item{Event: store.EventRunFailed, Severity: "high", Title: "x"}, Key: "run:r10"}); err != nil {
		t.Fatal(err)
	}
	env.svc.Step(ctx)
	if e := env.outbox(t)[0]; e.State != store.OutboxFailed || e.Attempts != 1 {
		t.Fatalf("4xx deveria ser definitivo: %+v", e)
	}
}

func TestWebhookPoliticaDeRede(t *testing.T) {
	for _, tc := range []struct {
		url          string
		allowPrivate bool
		ok           bool
	}{
		{"https://hooks.example.com/x", false, true},
		{"http://203.0.113.10:8080/x", false, true},
		{"ftp://example.com/x", false, false},
		{"https://user:pass@example.com/x", false, false},
		{"http://169.254.169.254/latest/meta-data", true, false},
		{"http://[fe80::1]/x", true, false},
		{"http://100.100.100.200/x", true, false},
		{"http://10.0.0.5/x", false, false},
		{"http://10.0.0.5/x", true, true},
		{"http://127.0.0.1:9000/x", false, false},
		{"http://localhost:9000/x", false, false},
		{"http://localhost:9000/x", true, true},
		{"http://[::ffff:169.254.169.254]/x", true, false},
	} {
		err := WebhookConfig{URL: tc.url, AllowPrivateNetwork: tc.allowPrivate}.Validate()
		if (err == nil) != tc.ok {
			t.Errorf("%s (privada %v): erro %v, esperado aceito=%v", tc.url, tc.allowPrivate, err, tc.ok)
		}
	}
	// O IP resolvido é conferido na conexão: nome que aponta para rede privada é recusado sem a opção.
	ctx := context.Background()
	env := newEnv(t)
	key, _ := WebhookKey(testSecret)
	hook := newHook(t, key, func() time.Time { return *env.now })
	url := strings.Replace(hook.URL, "127.0.0.1", "localhost", 1)
	ch := env.channel(t, "local", store.ChannelWebhook, WebhookConfig{URL: url, AllowPrivateNetwork: true}, testSecret)
	cfg, _ := json.Marshal(WebhookConfig{URL: url})
	ch.Config = string(cfg) // gravado sem a opção (como se a validação tivesse sido contornada)
	_, err := env.svc.SendTest(ctx, ch, "ana")
	if err == nil || !Permanent(err) || !strings.Contains(err.Error(), "rede privada") {
		t.Fatalf("destino local sem permissão deveria ser recusado na conexão: %v", err)
	}
	if got, _, _ := hook.received(); len(got) != 0 {
		t.Fatal("nada deveria chegar ao destino recusado")
	}
	for _, ip := range []string{"169.254.169.254", "fe80::1", "0.0.0.0", "::ffff:169.254.1.1"} {
		if err := checkAddr(netip.MustParseAddr(ip), true); err == nil {
			t.Errorf("%s deveria ser sempre recusado", ip)
		}
	}
}

func TestWebhookNaoSegueRedirecionamento(t *testing.T) {
	env := newEnv(t)
	var hits int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		http.Redirect(w, r, "http://169.254.169.254/latest", http.StatusFound)
	}))
	t.Cleanup(srv.Close)
	ch := env.channel(t, "redir", store.ChannelWebhook, WebhookConfig{URL: srv.URL, AllowPrivateNetwork: true}, testSecret)
	_, err := env.svc.SendTest(context.Background(), ch, "ana")
	if err == nil || !Permanent(err) || hits != 1 || !strings.Contains(err.Error(), "redirecionamento") {
		t.Fatalf("redirecionamento deveria falhar sem ser seguido: %v (%d)", err, hits)
	}
}

func TestAssinaturaConfereTempoECorpo(t *testing.T) {
	key, err := WebhookKey(testSecret)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1792670400, 0)
	body := []byte(`{"type":"test"}`)
	h := http.Header{}
	h.Set(HeaderID, "msg_1")
	h.Set(HeaderTimestamp, fmt.Sprint(now.Unix()))
	h.Set(HeaderSignature, Sign(key, "msg_1", now, body))
	if err := Verify(key, h, body, now.Add(time.Minute), DefaultTolerance); err != nil {
		t.Fatalf("assinatura válida recusada: %v", err)
	}
	if err := Verify(key, h, []byte(`{"type":"tampered"}`), now, DefaultTolerance); !errors.Is(err, ErrSignatureMismatch) {
		t.Fatalf("corpo alterado: %v", err)
	}
	if err := Verify(key, h, body, now.Add(10*time.Minute), DefaultTolerance); !errors.Is(err, ErrSignatureExpired) {
		t.Fatalf("repetição fora da tolerância: %v", err)
	}
	if err := Verify([]byte(strings.Repeat("k", 32)), h, body, now, DefaultTolerance); !errors.Is(err, ErrSignatureMismatch) {
		t.Fatalf("chave errada: %v", err)
	}
	// Vetor conhecido: HMAC-SHA256 de "msg_1.1792670400.{"type":"test"}" com a chave decodificada.
	if got := Sign(key, "msg_1", now, body); !strings.HasPrefix(got, "v1,") || len(got) != 47 {
		t.Fatalf("formato da assinatura: %q", got)
	}
	for _, bad := range []string{"", "curto", "whsec_!!!", "whsec_" + "YWJj"} {
		if _, err := WebhookKey(bad); err == nil {
			t.Errorf("segredo %q deveria ser recusado", bad)
		}
	}
	if k, err := WebhookKey(strings.Repeat("s", 32)); err != nil || len(k) != 32 {
		t.Fatalf("segredo de texto: %v", err)
	}
}

func TestEmailComSTARTTLSAutenticacaoEConteudo(t *testing.T) {
	ctx := context.Background()
	env := newEnv(t)
	cert, pool := testCert(t)
	env.svc.RootCAs = pool
	smtpSrv := startSMTP(t, cert, func(f *fakeSMTP) { f.starttls, f.user, f.pass = true, "alertas", "s3nh@-smtp" })
	cfg := EmailConfig{Host: "127.0.0.1", Port: smtpSrv.port, Security: SecuritySTARTTLS, Username: "alertas",
		From: "VigiaHost <vigia@example.com>", To: []string{"soc@example.com", "Ana <ana@example.com>"}}
	ch := env.channel(t, "E-mail do SOC", store.ChannelEmail, cfg, "s3nh@-smtp")
	env.rule(t, ch.ID, store.EventFindingNew, "high", 1440)

	ev := findingEvent(42, "critical")
	ev.Path = "/home/ana/public_html/a\u202egnp.php\nBcc: x@evil"
	if err := env.svc.Emit(ctx, ev); err != nil {
		t.Fatal(err)
	}
	env.advance(2 * time.Minute)
	env.svc.Step(ctx)
	mails := smtpSrv.received()
	if len(mails) != 1 {
		t.Fatalf("e-mails recebidos: %d; caixa: %+v", len(mails), env.outbox(t))
	}
	m := mails[0]
	if !m.TLS || m.User != "alertas" || m.Pass != "s3nh@-smtp" || m.From != "vigia@example.com" ||
		strings.Join(m.To, ",") != "soc@example.com,ana@example.com" || m.Greeting != "web01" {
		t.Fatalf("sessão SMTP: %+v", m)
	}
	// O DotReader do servidor falso entrega as linhas com \n.
	head, body, _ := strings.Cut(strings.ReplaceAll(m.Data, "\r\n", "\n"), "\n\n")
	var subject string
	for _, l := range strings.Split(head, "\n") {
		if v, ok := strings.CutPrefix(l, "Subject: "); ok {
			subject, _ = new(mime.WordDecoder).DecodeHeader(v)
		}
		if strings.HasPrefix(l, "Bcc:") {
			t.Fatal("injeção de cabeçalho pelo caminho")
		}
	}
	if subject != "[VigiaHost] web01: achado novo de severidade crítica" {
		t.Fatalf("assunto: %q", subject)
	}
	plain := readAll(quotedprintable.NewReader(strings.NewReader(body)))
	text := string(plain)
	if !strings.Contains(text, `a\u202egnp.php\u000aBcc: x@evil`) || !strings.Contains(text, "ClamAV: Php.Webshell.42") ||
		!strings.Contains(text, strings.Repeat("a", 64)) || strings.Contains(text, "\u202e") {
		t.Fatalf("corpo do e-mail sem os escapes esperados:\n%s", text)
	}
}

func TestEmailTLSImplicitoERecusas(t *testing.T) {
	ctx := context.Background()
	env := newEnv(t)
	cert, pool := testCert(t)
	env.svc.RootCAs = pool

	implicit := startSMTP(t, cert, func(f *fakeSMTP) { f.implicit = true })
	ch := env.channel(t, "465", store.ChannelEmail, EmailConfig{Host: "127.0.0.1", Port: implicit.port, Security: SecurityTLS,
		From: "vigia@example.com", To: []string{"soc@example.com"}}, "")
	if e, err := env.svc.SendTest(ctx, ch, "ana"); err != nil || e.State != store.OutboxSent {
		t.Fatalf("TLS implícito: %v %+v", err, e)
	}
	if m := implicit.received(); len(m) != 1 || !m[0].TLS || !strings.Contains(m[0].Data, "X-VigiaHost-Event: test") {
		t.Fatalf("mensagem de teste: %+v", m)
	}

	// Servidor sem STARTTLS: recusa definitiva, sem cair para texto puro (a senha nunca sai).
	plain := startSMTP(t, cert, func(f *fakeSMTP) { f.user, f.pass = "u", "p" })
	ch = env.channel(t, "sem-starttls", store.ChannelEmail, EmailConfig{Host: "127.0.0.1", Port: plain.port,
		Security: SecuritySTARTTLS, Username: "u", From: "vigia@example.com", To: []string{"soc@example.com"}}, "p")
	e, err := env.svc.SendTest(ctx, ch, "ana")
	if err == nil || !Permanent(err) || !strings.Contains(e.LastError, "STARTTLS") || e.State != store.OutboxFailed {
		t.Fatalf("sem STARTTLS: %v %+v", err, e)
	}
	if strings.Contains(e.LastError, "p\"") || len(plain.received()) != 0 {
		t.Fatal("nada deveria ser enviado")
	}

	// Credencial errada (535) é definitiva; destinatário recusado temporariamente (450) tenta de novo.
	auth := startSMTP(t, cert, func(f *fakeSMTP) { f.starttls, f.user, f.pass = true, "u", "certa" })
	ch = env.channel(t, "senha-errada", store.ChannelEmail, EmailConfig{Host: "127.0.0.1", Port: auth.port,
		Security: SecuritySTARTTLS, Username: "u", From: "vigia@example.com", To: []string{"soc@example.com"}}, "errada")
	if _, err := env.svc.SendTest(ctx, ch, "ana"); err == nil || !Permanent(err) || !strings.Contains(err.Error(), "535") {
		t.Fatalf("senha errada: %v", err)
	}
	busy := startSMTP(t, cert, func(f *fakeSMTP) { f.starttls, f.rcptCode = true, 450 })
	ch = env.channel(t, "ocupado", store.ChannelEmail, EmailConfig{Host: "127.0.0.1", Port: busy.port,
		Security: SecuritySTARTTLS, From: "vigia@example.com", To: []string{"soc@example.com"}}, "")
	if _, err := env.svc.SendTest(ctx, ch, "ana"); err == nil || Permanent(err) {
		t.Fatalf("4xx do SMTP deveria ser temporário: %v", err)
	}

	// Certificado que não confere: falha (sem aceitar qualquer certificado).
	env.svc.RootCAs = nil
	if _, err := env.svc.SendTest(ctx, mustChannel(t, env, "465"), "ana"); err == nil {
		t.Fatal("certificado não confiável deveria falhar")
	}
}

func mustChannel(t *testing.T, env *testEnv, name string) store.NotificationChannel {
	t.Helper()
	list, _ := env.db.ListNotificationChannels(context.Background())
	for _, c := range list {
		if c.Name == name {
			return c
		}
	}
	t.Fatalf("canal %q não existe", name)
	return store.NotificationChannel{}
}

func TestValidacaoDoEmail(t *testing.T) {
	ok := EmailConfig{Host: "smtp.example.com", Port: 587, Security: SecuritySTARTTLS, From: "a@example.com", To: []string{"b@example.com"}}
	if err := ok.Validate(false); err != nil {
		t.Fatal(err)
	}
	cases := map[string]func(*EmailConfig){
		"esquema no host":        func(c *EmailConfig) { c.Host = "smtp://x" },
		"texto puro remoto":      func(c *EmailConfig) { c.Security = SecurityNone },
		"usuário sem senha":      func(c *EmailConfig) { c.Username = "u" },
		"remetente inválido":     func(c *EmailConfig) { c.From = "não é e-mail" },
		"sem destinatário":       func(c *EmailConfig) { c.To = nil },
		"injeção no destino":     func(c *EmailConfig) { c.To = []string{"b@example.com\r\nBcc: c@example.com"} },
		"porta fora da faixa":    func(c *EmailConfig) { c.Port = 70000 },
		"destinatários demais":   func(c *EmailConfig) { c.To = make([]string, 21) },
		"segurança desconhecida": func(c *EmailConfig) { c.Security = "ssl3" },
	}
	for name, mut := range cases {
		c := ok
		c.To = append([]string(nil), ok.To...)
		mut(&c)
		if err := c.Validate(false); err == nil {
			t.Errorf("%s: deveria ser recusado", name)
		}
	}
	local := ok
	local.Host, local.Security = "localhost", SecurityNone
	if err := local.Validate(false); err != nil {
		t.Fatalf("relé local sem TLS deveria ser aceito: %v", err)
	}
}

func TestRegrasFiltramPrivacidadeECanalDesativado(t *testing.T) {
	ctx := context.Background()
	env := newEnv(t)
	key, _ := WebhookKey(testSecret)
	hook := newHook(t, key, func() time.Time { return *env.now })
	ch := env.channel(t, "privado", store.ChannelWebhook, WebhookConfig{URL: hook.URL, AllowPrivateNetwork: true}, testSecret)
	ch.IncludeDetails = false
	if err := env.db.UpdateNotificationChannel(ctx, &ch); err != nil {
		t.Fatal(err)
	}
	env.rule(t, ch.ID, store.EventFindingNew, "critical", 0)
	// Evento sem regra não entra; severidade abaixo do mínimo também não.
	if err := env.svc.Emit(ctx, findingEvent(1, "high"), Event{Item: Item{Event: store.EventBackupFailed, Severity: "high", Title: "x"}, Key: "backup:failed"}); err != nil {
		t.Fatal(err)
	}
	if n := len(env.outbox(t)); n != 0 {
		t.Fatalf("nada deveria entrar: %d", n)
	}
	if err := env.svc.Emit(ctx, findingEvent(2, "critical")); err != nil {
		t.Fatal(err)
	}
	env.advance(2 * time.Minute)
	env.svc.Step(ctx)
	got, _, _ := hook.received()
	if len(got) != 1 || got[0].Data.Items[0].Path != "" || got[0].Data.Items[0].SHA256 != "" {
		t.Fatalf("sem detalhes o caminho e o hash não saem: %+v", got)
	}
	// Mensagem pendente de canal desativado vira falha definitiva, sem envio.
	if err := env.svc.Emit(ctx, findingEvent(3, "critical")); err != nil {
		t.Fatal(err)
	}
	ch.Enabled = false
	if err := env.db.UpdateNotificationChannel(ctx, &ch); err != nil {
		t.Fatal(err)
	}
	env.advance(2 * time.Minute)
	env.svc.Step(ctx)
	if e := env.outbox(t)[0]; e.State != store.OutboxFailed || !strings.Contains(e.LastError, "desativado") {
		t.Fatalf("canal desativado: %+v", e)
	}
	// Remover o canal mantém o histórico e falha o que estava pendente.
	ch.Enabled = true
	_ = env.db.UpdateNotificationChannel(ctx, &ch)
	if err := env.svc.Emit(ctx, findingEvent(4, "critical")); err != nil {
		t.Fatal(err)
	}
	if err := env.db.DeleteNotificationChannel(ctx, ch.ID); err != nil {
		t.Fatal(err)
	}
	box := env.outbox(t)
	if len(box) != 3 || box[0].ChannelID != nil || box[0].State != store.OutboxFailed || box[0].ChannelName != "privado" {
		t.Fatalf("histórico depois de remover o canal: %+v", box)
	}
}

func TestExecutorIndisponivelEVolta(t *testing.T) {
	ctx := context.Background()
	env := newEnv(t)
	key, _ := WebhookKey(testSecret)
	hook := newHook(t, key, func() time.Time { return *env.now })
	ch := env.channel(t, "ops", store.ChannelWebhook, WebhookConfig{URL: hook.URL, AllowPrivateNetwork: true}, testSecret)
	env.rule(t, ch.ID, store.EventExecutorUnavailable, "info", 60)
	down := true
	env.svc.ProbeEvery = time.Nanosecond
	env.svc.ExecutorProbe = func(context.Context) error {
		if down {
			return errors.New("dial unix executor.sock: connection refused")
		}
		return nil
	}
	env.svc.Step(ctx) // primeira falha: ainda não avisa
	if n := len(env.outbox(t)); n != 0 {
		t.Fatalf("uma falha isolada não deveria avisar: %d", n)
	}
	time.Sleep(time.Millisecond)
	env.svc.Step(ctx)
	env.svc.Step(ctx)
	got, _, _ := hook.received()
	if len(got) != 1 || got[0].Data.Items[0].Severity != "critical" || !strings.Contains(got[0].Data.Items[0].Detail, "connection refused") {
		t.Fatalf("aviso de executor indisponível: %+v", got)
	}
	down = false
	time.Sleep(time.Millisecond)
	env.svc.Step(ctx)
	env.svc.Step(ctx)
	got, _, _ = hook.received()
	if len(got) != 2 || !got[1].Data.Items[0].Resolved {
		t.Fatalf("aviso de volta: %+v", got)
	}
}

func TestEventosDeExecucaoEMotor(t *testing.T) {
	fin := time.Date(2026, 10, 22, 12, 0, 0, 0, time.UTC)
	r := store.Run{ID: "20261022-120000-abcd", Kind: report.KindFiles, Status: string(report.StatusPartial), FinishedAt: &fin}
	sum := &report.Summary{Engines: []report.EngineCoverage{
		{Engine: "yara-x", Available: true, SelfTest: report.SelfTest{Ran: true, Positive: false, Negative: true, Detail: "controle positivo não detectado"}},
		{Engine: "clamav", Available: false, Error: "clamd não respondeu"},
		{Engine: "outro", Available: true, SelfTest: report.SelfTest{Ran: true, Positive: true, Negative: true}},
	}}
	evs := RunEvents(r, sum)
	if len(evs) != 3 || evs[0].Event != store.EventRunPartial || evs[1].Key != "engine:yara-x" || evs[2].Key != "engine:clamav" {
		t.Fatalf("eventos: %+v", evs)
	}
	r.Status = string(report.StatusCanceled)
	if evs := RunEvents(r, nil); len(evs) != 0 {
		t.Fatalf("cancelada pelo operador não notifica: %+v", evs)
	}
	r.Status = string(report.StatusInterrupted)
	if evs := RunEvents(r, nil); len(evs) != 1 || evs[0].Event != store.EventRunFailed || !strings.Contains(evs[0].Title, "interrompida") {
		t.Fatalf("interrompida: %+v", evs)
	}
}

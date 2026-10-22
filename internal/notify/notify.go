// Package notify envia notificações por e-mail (SMTP) e webhook assinado (E1.12; escopo, seção 16).
//
// Fluxo: o orquestrador e o core chamam Emit com eventos (achado novo, execução com falha, motor, executor, cópia do
// banco). Emit aplica as regras de cada canal e grava na caixa de saída do banco — só gravação local, sem rede, para
// não segurar a fila de execuções. O laço Run envia o que venceu, com tempo limite por envio, novas tentativas com
// recuo exponencial e falha definitiva depois do máximo de tentativas. Achados que chegam juntos viram um resumo.
package notify

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"math/rand/v2"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/guigallina27/vigiahost/internal/report"
	"github.com/guigallina27/vigiahost/internal/secrets"
	"github.com/guigallina27/vigiahost/internal/store"
)

// Item é um acontecimento dentro de uma mensagem. Nunca leva conteúdo de arquivo; caminho e hash saem quando o
// canal desliga os detalhes.
type Item struct {
	Event     string    `json:"event"`
	Severity  string    `json:"severity"`
	Title     string    `json:"title"`
	Detail    string    `json:"detail,omitempty"`
	FindingID int64     `json:"finding_id,omitempty"`
	RunID     string    `json:"run_id,omitempty"`
	Engine    string    `json:"engine,omitempty"`
	Path      string    `json:"path,omitempty"`
	SHA256    string    `json:"sha256,omitempty"`
	Resolved  bool      `json:"resolved,omitempty"`
	At        time.Time `json:"at"`
}

// Event é o que os produtores entregam a Emit: o item e a chave de deduplicação (mesmo achado, mesma execução...).
type Event struct {
	Item
	Key string
}

// Severidades em ordem crescente; info também serve para avisos de normalização (executor voltou).
var severityRank = map[string]int{
	string(report.SeverityInfo): 1, string(report.SeverityLow): 2, string(report.SeverityMedium): 3,
	string(report.SeverityHigh): 4, string(report.SeverityCritical): 5,
}

// SeverityAtLeast indica se sev alcança o mínimo da regra.
func SeverityAtLeast(sev, minimum string) bool { return severityRank[sev] >= severityRank[minimum] }

// ValidSeverity aceita as severidades do produto.
func ValidSeverity(s string) bool { _, ok := severityRank[s]; return ok }

// Erros de configuração (viram 400 na API).
var ErrInvalid = errors.New("configuração inválida")

func invalid(format string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrInvalid, fmt.Sprintf(format, args...))
}

// permanent marca falhas que não melhoram com nova tentativa (configuração, destino recusado, 4xx/5xx definitivo).
type permanent struct{ err error }

func (p permanent) Error() string { return p.err.Error() }
func (p permanent) Unwrap() error { return p.err }

// Permanent indica falha definitiva.
func Permanent(err error) bool {
	var p permanent
	return errors.As(err, &p)
}

// Service guarda a configuração do envio. Zero nos campos numéricos usa os padrões.
type Service struct {
	DB     *store.DB
	Box    *secrets.Box
	Logger *slog.Logger
	// Hostname identifica o servidor nas mensagens; Version é a versão do produto.
	Hostname string
	Version  string
	// RootCAs nil usa as autoridades do sistema (os testes usam o certificado do servidor falso).
	RootCAs *x509.CertPool

	Timeout     time.Duration // por envio (padrão 20 s)
	GroupWindow time.Duration // quanto esperar por mais achados antes do primeiro envio (padrão 60 s)
	MaxAttempts int           // tentativas até a falha definitiva (padrão 8)
	BaseBackoff time.Duration // primeiro intervalo entre tentativas (padrão 30 s), dobra a cada falha
	MaxBackoff  time.Duration // teto do intervalo (padrão 1 h)
	Tick        time.Duration // intervalo do laço (padrão 5 s)
	Lease       time.Duration // reserva de uma mensagem em envio (padrão 5 min)
	Retention   time.Duration // histórico de mensagens resolvidas (padrão 30 dias)

	// ExecutorProbe confere o executor; nil desliga o aviso de executor indisponível.
	ExecutorProbe func(ctx context.Context) error
	ProbeEvery    time.Duration // padrão 60 s
	ProbeFailures int           // falhas seguidas antes do aviso (padrão 2)

	mu        sync.Mutex
	wake      chan struct{}
	execFails int
	execDown  bool
	lastProbe time.Time
	lastPurge time.Time
}

func (s *Service) defaults() {
	if s.Timeout <= 0 {
		s.Timeout = 20 * time.Second
	}
	if s.GroupWindow <= 0 {
		s.GroupWindow = time.Minute
	}
	if s.MaxAttempts <= 0 {
		s.MaxAttempts = 8
	}
	if s.BaseBackoff <= 0 {
		s.BaseBackoff = 30 * time.Second
	}
	if s.MaxBackoff <= 0 {
		s.MaxBackoff = time.Hour
	}
	if s.Tick <= 0 {
		s.Tick = 5 * time.Second
	}
	if s.Lease <= 0 {
		s.Lease = 5 * time.Minute
	}
	if s.Retention <= 0 {
		s.Retention = 30 * 24 * time.Hour
	}
	if s.ProbeEvery <= 0 {
		s.ProbeEvery = time.Minute
	}
	if s.ProbeFailures <= 0 {
		s.ProbeFailures = 2
	}
	if s.Hostname == "" {
		s.Hostname = "servidor"
	}
	if s.Logger == nil {
		s.Logger = slog.New(slog.DiscardHandler)
	}
}

func (s *Service) now() time.Time { return s.DB.Now().UTC() }

// Emit aplica as regras ativas de cada evento e grava as mensagens na caixa de saída. Não usa a rede.
func (s *Service) Emit(ctx context.Context, events ...Event) error {
	if s == nil || len(events) == 0 {
		return nil
	}
	s.defaults()
	byType := map[string][]Event{}
	var order []string
	for _, ev := range events {
		if !slices.Contains(store.NotificationEvents, ev.Event) {
			return fmt.Errorf("evento de notificação desconhecido: %q", ev.Event)
		}
		if _, ok := byType[ev.Event]; !ok {
			order = append(order, ev.Event)
		}
		byType[ev.Event] = append(byType[ev.Event], ev)
	}
	var list []store.NotificationEnqueue
	for _, typ := range order {
		targets, err := s.DB.NotificationTargets(ctx, typ)
		if err != nil {
			return err
		}
		for _, t := range targets {
			for _, ev := range byType[typ] {
				if typ == store.EventFindingNew && !SeverityAtLeast(ev.Severity, t.Rule.MinSeverity) {
					continue
				}
				item := ev.Item
				if item.At.IsZero() {
					item.At = s.now()
				}
				if !t.Channel.IncludeDetails {
					item.Path, item.SHA256 = "", ""
				}
				raw, err := json.Marshal(item)
				if err != nil {
					return err
				}
				e := store.NotificationEnqueue{ChannelID: t.Channel.ID, ChannelName: t.Channel.Name,
					ChannelKind: t.Channel.Kind, Event: typ, DedupKey: ev.Key,
					DedupWindow: time.Duration(t.Rule.DedupMinutes) * time.Minute, Severity: item.Severity,
					Item: raw, MaxAttempts: s.MaxAttempts}
				if typ == store.EventFindingNew {
					e.GroupWindow = s.GroupWindow
				}
				list = append(list, e)
			}
		}
	}
	if len(list) == 0 {
		return nil
	}
	res, err := s.DB.EnqueueNotifications(ctx, list)
	if err != nil {
		return err
	}
	if res.Queued+res.Grouped+res.Suppressed > 0 {
		s.Logger.Info("notificações na caixa de saída", "novas", res.Queued, "agrupadas", res.Grouped,
			"suprimidas_dedup", res.Suppressed)
	}
	s.Wake()
	return nil
}

// Wake antecipa o próximo ciclo do laço de envio.
func (s *Service) Wake() {
	s.mu.Lock()
	w := s.wake
	s.mu.Unlock()
	if w == nil {
		return
	}
	select {
	case w <- struct{}{}:
	default:
	}
}

// Run envia as mensagens vencidas até o contexto acabar. Roda numa goroutine própria: envio lento não atrasa a fila.
func (s *Service) Run(ctx context.Context) {
	s.defaults()
	s.mu.Lock()
	if s.wake == nil {
		s.wake = make(chan struct{}, 1)
	}
	w := s.wake
	s.mu.Unlock()
	t := time.NewTicker(s.Tick)
	defer t.Stop()
	for {
		s.Step(ctx)
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		case <-w:
		}
	}
}

// Step é um ciclo do laço (exportado para os testes): confere o executor, envia o que venceu e limpa o histórico.
func (s *Service) Step(ctx context.Context) {
	s.defaults()
	s.watchExecutor(ctx)
	entries, err := s.DB.ClaimDueNotifications(ctx, s.Lease, 20)
	if err != nil {
		if ctx.Err() == nil {
			s.Logger.Error("caixa de saída: falha ao reservar mensagens", "erro", err)
		}
		return
	}
	// Um canal lento não atrasa os outros: cada canal envia em paralelo, em ordem dentro dele.
	byChannel := map[int64][]store.OutboxEntry{}
	for _, e := range entries {
		var id int64
		if e.ChannelID != nil {
			id = *e.ChannelID
		}
		byChannel[id] = append(byChannel[id], e)
	}
	var wg sync.WaitGroup
	for _, list := range byChannel {
		wg.Go(func() {
			for _, e := range list {
				s.deliverEntry(ctx, e)
			}
		})
	}
	wg.Wait()
	if time.Since(s.lastPurge) > time.Hour {
		s.lastPurge = time.Now()
		now := s.now()
		if n, err := s.DB.PurgeNotifications(ctx, now.Add(-s.Retention), now.Add(-8*24*time.Hour)); err != nil {
			s.Logger.Warn("limpeza da caixa de saída falhou", "erro", err)
		} else if n > 0 {
			s.Logger.Info("mensagens antigas removidas da caixa de saída", "quantidade", n)
		}
	}
}

// backoff é o intervalo antes da próxima tentativa: base × 2^(tentativas−1), com teto e até 10% de variação para
// não sincronizar envios.
func (s *Service) backoff(attempts int) time.Duration {
	d := s.BaseBackoff
	for i := 1; i < attempts && d < s.MaxBackoff; i++ {
		d *= 2
	}
	d = min(d, s.MaxBackoff)
	return d + time.Duration(rand.Int64N(int64(d)/10+1)) //nolint:gosec // variação de horário, não segredo
}

func (s *Service) deliverEntry(ctx context.Context, e store.OutboxEntry) {
	fail := func(msg string) {
		if err := s.DB.MarkNotificationError(ctx, e.ID, msg, nil); err != nil {
			s.Logger.Error("caixa de saída: falha ao registrar erro", "mensagem", e.ID, "erro", err)
		}
	}
	if e.ChannelID == nil {
		fail("canal removido antes do envio")
		return
	}
	ch, err := s.DB.GetNotificationChannel(ctx, *e.ChannelID)
	if errors.Is(err, store.ErrNotFound) {
		fail("canal removido antes do envio")
		return
	}
	if err != nil {
		_ = s.DB.MarkNotificationError(ctx, e.ID, "falha ao ler o canal: "+err.Error(), ptrTime(s.now().Add(s.backoff(e.Attempts))))
		return
	}
	if !ch.Enabled {
		fail("canal desativado antes do envio")
		return
	}
	m := MessageFrom(e, s.Hostname, s.Version)
	sctx, cancel := context.WithTimeout(ctx, s.Timeout)
	err = s.Deliver(sctx, ch, m)
	cancel()
	if err == nil {
		if err := s.DB.MarkNotificationSent(ctx, e.ID); err != nil {
			s.Logger.Error("caixa de saída: falha ao registrar envio", "mensagem", e.ID, "erro", err)
		}
		s.Logger.Info("notificação enviada", "mensagem", e.ID, "canal", ch.Name, "evento", e.Event, "itens", e.ItemCount)
		return
	}
	if ctx.Err() != nil {
		// Serviço parando: a reserva vence e a mensagem sai no próximo início.
		return
	}
	msg := cleanError(err)
	if Permanent(err) || e.Attempts >= e.MaxAttempts {
		fail(msg)
		s.Logger.Warn("notificação não enviada (falha definitiva)", "mensagem", e.ID, "canal", ch.Name,
			"tentativas", e.Attempts, "erro", msg)
		return
	}
	next := s.now().Add(s.backoff(e.Attempts))
	if err := s.DB.MarkNotificationError(ctx, e.ID, msg, &next); err != nil {
		s.Logger.Error("caixa de saída: falha ao registrar erro", "mensagem", e.ID, "erro", err)
	}
	s.Logger.Warn("notificação não enviada; nova tentativa agendada", "mensagem", e.ID, "canal", ch.Name,
		"tentativas", e.Attempts, "proxima", next, "erro", msg)
}

func ptrTime(t time.Time) *time.Time { return &t }

// Deliver envia a mensagem pelo canal (usado pelo laço e pelo botão de teste).
func (s *Service) Deliver(ctx context.Context, ch store.NotificationChannel, m Message) error {
	s.defaults()
	secret, err := s.openSecret(ch)
	if err != nil {
		return permanent{err}
	}
	switch ch.Kind {
	case store.ChannelEmail:
		cfg, err := ParseEmailConfig(ch.Config)
		if err != nil {
			return permanent{err}
		}
		if err := cfg.Validate(len(secret) > 0); err != nil {
			return permanent{err}
		}
		return s.sendEmail(ctx, cfg, string(secret), m)
	case store.ChannelWebhook:
		cfg, err := ParseWebhookConfig(ch.Config)
		if err != nil {
			return permanent{err}
		}
		if err := cfg.Validate(); err != nil {
			return permanent{err}
		}
		key, err := WebhookKey(string(secret))
		if err != nil {
			return permanent{err}
		}
		return s.sendWebhook(ctx, cfg, key, m)
	}
	return permanent{fmt.Errorf("tipo de canal desconhecido: %q", ch.Kind)}
}

// SecretContext liga o segredo cifrado ao tipo de canal (dado adicional autenticado).
func SecretContext(kind string) string { return "vigiahost/notification-channel/" + kind }

func (s *Service) openSecret(ch store.NotificationChannel) ([]byte, error) {
	if len(ch.Secret) == 0 {
		return nil, nil
	}
	if s.Box == nil {
		return nil, errors.New("cofre de segredos indisponível")
	}
	return s.Box.Open(ch.Secret, SecretContext(ch.Kind))
}

// SealSecret cifra o segredo do canal para gravar no banco.
func (s *Service) SealSecret(kind, secret string) ([]byte, error) {
	if secret == "" {
		return nil, nil
	}
	if s.Box == nil {
		return nil, errors.New("cofre de segredos indisponível")
	}
	return s.Box.Seal([]byte(secret), SecretContext(kind))
}

// SecretReadable indica se o segredo gravado abre com a chave atual (a interface avisa quando não abre).
func (s *Service) SecretReadable(ch store.NotificationChannel) bool {
	_, err := s.openSecret(ch)
	return err == nil
}

// SendTest envia agora uma mensagem de teste, registra o resultado no histórico e devolve o erro real do envio.
func (s *Service) SendTest(ctx context.Context, ch store.NotificationChannel, actor string) (store.OutboxEntry, error) {
	s.defaults()
	now := s.now()
	item := Item{Event: store.EventTest, Severity: string(report.SeverityInfo), Title: "Mensagem de teste",
		Detail: "Enviada por " + actor + " pelo painel. Se você recebeu, o canal está funcionando.", At: now}
	raw, _ := json.Marshal(item)
	id := ch.ID
	e := store.OutboxEntry{ChannelID: &id, ChannelName: ch.Name, ChannelKind: ch.Kind, Event: store.EventTest,
		Items: []json.RawMessage{raw}, ItemCount: 1, SeverityCounts: map[string]int{item.Severity: 1}, Attempts: 1,
		MaxAttempts: 1}
	m := Message{ID: "msg_test_" + randomHex(8), Event: store.EventTest, Count: 1, Items: []Item{item},
		SeverityCounts: e.SeverityCounts, Host: s.Hostname, Version: s.Version, CreatedAt: now}
	sctx, cancel := context.WithTimeout(ctx, s.Timeout)
	err := s.Deliver(sctx, ch, m)
	cancel()
	e.State = store.OutboxSent
	if err != nil {
		e.State, e.LastError = store.OutboxFailed, cleanError(err)
	}
	if rerr := s.DB.RecordNotification(ctx, &e); rerr != nil {
		s.Logger.Error("falha ao registrar o teste de notificação", "erro", rerr)
	}
	return e, err
}

// cleanError deixa a mensagem de erro pronta para guardar e mostrar: sem caracteres de controle e curta.
func cleanError(err error) string {
	msg := CleanText(err.Error(), 500)
	if msg == "" {
		msg = "falha sem descrição"
	}
	return msg
}

// truncateRunes corta o texto em n caracteres.
func truncateRunes(s string, n int) string {
	if n <= 0 {
		return s
	}
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return strings.TrimSpace(string(r[:n])) + "…"
}

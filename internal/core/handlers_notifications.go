package core

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"unicode"

	"github.com/guigallina27/vigiahost/internal/api"
	"github.com/guigallina27/vigiahost/internal/notify"
	"github.com/guigallina27/vigiahost/internal/store"
)

// Notificações (E1.12): canais, regras, botão de teste e caixa de saída. Só o administrador vê e altera; criar,
// alterar e remover canais e regras exige reautenticação (trocar o destino ou silenciar alertas é ação sensível).
// Segredos entram pela API e nunca saem: a resposta diz só se há um configurado.

func (s *Server) notifyReady(w http.ResponseWriter) bool {
	if s.Notify == nil {
		writeError(w, http.StatusServiceUnavailable, "notificações indisponíveis neste serviço", "unavailable")
		return false
	}
	return true
}

func (s *Server) toAPIChannel(r *http.Request, c store.NotificationChannel) api.NotificationChannel {
	out := api.NotificationChannel{Id: c.ID, Name: c.Name, Kind: api.NotificationChannelKind(c.Kind), Enabled: c.Enabled,
		IncludeDetails: c.IncludeDetails, SecretConfigured: len(c.Secret) > 0, SecretReadable: true,
		CreatedBy: c.CreatedBy, CreatedAt: c.CreatedAt, UpdatedAt: c.UpdatedAt}
	if out.SecretConfigured && s.Notify != nil {
		out.SecretReadable = s.Notify.SecretReadable(c)
	}
	switch c.Kind {
	case store.ChannelEmail:
		if cfg, err := notify.ParseEmailConfig(c.Config); err == nil {
			e := api.EmailSettings{Host: cfg.Host, Port: cfg.Port, Security: api.SmtpSecurity(cfg.Security), From: cfg.From,
				To: nonNil(cfg.To)}
			if cfg.Username != "" {
				e.Username = ptr(cfg.Username)
			}
			out.Email = &e
		}
	case store.ChannelWebhook:
		if cfg, err := notify.ParseWebhookConfig(c.Config); err == nil {
			out.Webhook = &api.WebhookSettings{Url: cfg.URL, AllowPrivateNetwork: cfg.AllowPrivateNetwork}
		}
	}
	if last, err := s.DB.ListOutbox(r.Context(), store.OutboxFilter{ChannelID: c.ID, Limit: 1}); err == nil && len(last) > 0 {
		st := api.OutboxState(last[0].State)
		out.LastState, out.LastAt = &st, ptr(last[0].UpdatedAt)
		if last[0].LastError != "" {
			out.LastError = ptr(last[0].LastError)
		}
	}
	return out
}

func toAPIOutbox(e store.OutboxEntry) api.OutboxEntry {
	m := notify.MessageFrom(e, "", "")
	out := api.OutboxEntry{Id: e.ID, ChannelId: e.ChannelID, ChannelName: e.ChannelName,
		ChannelKind: api.NotificationChannelKind(e.ChannelKind), Event: api.OutboxEvent(e.Event),
		Summary: notify.Summary(e.Event, m.Count, m.Items, e.SeverityCounts), ItemCount: m.Count,
		SeverityCounts: e.SeverityCounts, Items: []api.OutboxItem{}, State: api.OutboxState(e.State),
		Attempts: e.Attempts, MaxAttempts: e.MaxAttempts, NextAttemptAt: e.NextAttemptAt, LastError: e.LastError,
		CreatedAt: e.CreatedAt, UpdatedAt: e.UpdatedAt, SentAt: e.SentAt}
	if out.SeverityCounts == nil {
		out.SeverityCounts = map[string]int{}
	}
	if e.State != store.OutboxPending {
		out.NextAttemptAt = nil
	}
	for _, it := range m.Items {
		oi := api.OutboxItem{Severity: api.Severity(it.Severity), Title: notify.CleanText(it.Title, 300)}
		if it.FindingID > 0 {
			oi.FindingId = ptr(it.FindingID)
		}
		if it.RunID != "" {
			oi.RunId = ptr(it.RunID)
		}
		if !it.At.IsZero() {
			oi.At = ptr(it.At)
		}
		out.Items = append(out.Items, oi)
	}
	return out
}

// ListNotificationChannels lista os canais sem os segredos.
func (s *Server) ListNotificationChannels(w http.ResponseWriter, r *http.Request) {
	list, err := s.DB.ListNotificationChannels(r.Context())
	if err != nil {
		s.storeError(w, err)
		return
	}
	out := make([]api.NotificationChannel, 0, len(list))
	for _, c := range list {
		out = append(out, s.toAPIChannel(r, c))
	}
	writeJSON(w, http.StatusOK, out)
}

func validName(n string) bool {
	return n != "" && len([]rune(n)) <= 64 && strings.IndexFunc(n, unicode.IsControl) < 0
}

// channelFrom valida a entrada e monta o canal. existing é o canal em edição (nil ao criar). Devolve também o
// resumo do destino para a auditoria (sem segredo).
func (s *Server) channelFrom(in api.NotificationChannelInput, existing *store.NotificationChannel) (store.NotificationChannel, string, error) {
	c := store.NotificationChannel{Name: strings.TrimSpace(in.Name), Kind: string(in.Kind), Enabled: in.Enabled,
		IncludeDetails: in.IncludeDetails == nil || *in.IncludeDetails}
	if existing != nil {
		c.ID, c.CreatedBy, c.CreatedAt, c.Secret = existing.ID, existing.CreatedBy, existing.CreatedAt, existing.Secret
		if existing.Kind != c.Kind {
			return c, "", fmt.Errorf("%w: o tipo do canal não muda; crie outro canal", notify.ErrInvalid)
		}
	}
	if !validName(c.Name) {
		return c, "", fmt.Errorf("%w: informe um nome de até 64 caracteres", notify.ErrInvalid)
	}
	var secret *string
	if in.Secret != nil {
		secret = in.Secret
	}
	var cfgJSON []byte
	var dest string
	switch c.Kind {
	case store.ChannelEmail:
		if in.Email == nil || in.Webhook != nil {
			return c, "", fmt.Errorf("%w: canal de e-mail precisa só da configuração de e-mail", notify.ErrInvalid)
		}
		cfg := notify.EmailConfig{Host: in.Email.Host, Port: in.Email.Port, Security: string(in.Email.Security),
			From: in.Email.From, To: in.Email.To}
		if in.Email.Username != nil {
			cfg.Username = *in.Email.Username
		}
		cfg.Normalize()
		if cfg.Username == "" {
			// Sem usuário não há autenticação: a senha não serve para nada e não fica guardada.
			empty := ""
			secret = &empty
		}
		hasPassword := len(c.Secret) > 0
		if secret != nil {
			hasPassword = *secret != ""
		}
		if err := cfg.Validate(hasPassword); err != nil {
			return c, "", err
		}
		cfgJSON, _ = json.Marshal(cfg)
		dest = fmt.Sprintf("smtp %s:%d %s, %d destinatário(s)", cfg.Host, cfg.Port, cfg.Security, len(cfg.To))
	case store.ChannelWebhook:
		if in.Webhook == nil || in.Email != nil {
			return c, "", fmt.Errorf("%w: canal de webhook precisa só da configuração de webhook", notify.ErrInvalid)
		}
		cfg := notify.WebhookConfig{URL: in.Webhook.Url, AllowPrivateNetwork: in.Webhook.AllowPrivateNetwork}
		cfg.Normalize()
		if err := cfg.Validate(); err != nil {
			return c, "", err
		}
		switch {
		case secret != nil:
			if _, err := notify.WebhookKey(*secret); err != nil {
				return c, "", err
			}
		case len(c.Secret) == 0:
			return c, "", fmt.Errorf("%w: informe o segredo de assinatura do webhook", notify.ErrInvalid)
		}
		cfgJSON, _ = json.Marshal(cfg)
		dest = "webhook " + cfg.Destination()
		if cfg.AllowPrivateNetwork {
			dest += " (rede privada permitida)"
		}
	default:
		return c, "", fmt.Errorf("%w: tipo de canal inválido", notify.ErrInvalid)
	}
	c.Config = string(cfgJSON)
	if secret != nil {
		sealed, err := s.Notify.SealSecret(c.Kind, *secret)
		if err != nil {
			return c, "", err
		}
		c.Secret = sealed
		dest += ", segredo alterado"
	}
	if !c.IncludeDetails {
		dest += ", sem caminhos e hashes"
	}
	return c, dest, nil
}

func (s *Server) channelError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, notify.ErrInvalid):
		writeError(w, http.StatusBadRequest, strings.TrimPrefix(err.Error(), notify.ErrInvalid.Error()+": "), "bad_request")
	case errors.Is(err, store.ErrDuplicate):
		writeError(w, http.StatusConflict, "já existe um canal com esse nome", "duplicate")
	default:
		s.storeError(w, err)
	}
}

// CreateNotificationChannel cria o canal.
func (s *Server) CreateNotificationChannel(w http.ResponseWriter, r *http.Request) {
	if !s.notifyReady(w) {
		return
	}
	var in api.NotificationChannelInput
	if !decode(w, r, &in) {
		return
	}
	c, dest, err := s.channelFrom(in, nil)
	if err != nil {
		s.channelError(w, err)
		return
	}
	c.CreatedBy = principalFrom(r.Context()).Actor()
	if err := s.DB.CreateNotificationChannel(r.Context(), &c); err != nil {
		s.channelError(w, err)
		return
	}
	s.audit(r, "notification_channel_created", fmt.Sprint(c.ID), fmt.Sprintf("%s (%s): %s, ativo %v", c.Name, c.Kind, dest, c.Enabled))
	writeJSON(w, http.StatusCreated, s.toAPIChannel(r, c))
}

// UpdateNotificationChannel altera o canal; segredo ausente mantém o atual.
func (s *Server) UpdateNotificationChannel(w http.ResponseWriter, r *http.Request, id api.Id) {
	if !s.notifyReady(w) {
		return
	}
	var in api.NotificationChannelInput
	if !decode(w, r, &in) {
		return
	}
	existing, err := s.DB.GetNotificationChannel(r.Context(), id)
	if err != nil {
		s.storeError(w, err)
		return
	}
	c, dest, err := s.channelFrom(in, &existing)
	if err != nil {
		s.channelError(w, err)
		return
	}
	if err := s.DB.UpdateNotificationChannel(r.Context(), &c); err != nil {
		s.channelError(w, err)
		return
	}
	s.audit(r, "notification_channel_updated", fmt.Sprint(c.ID), fmt.Sprintf("%s (%s): %s, ativo %v", c.Name, c.Kind, dest, c.Enabled))
	writeJSON(w, http.StatusOK, s.toAPIChannel(r, c))
}

// DeleteNotificationChannel remove o canal e as regras dele.
func (s *Server) DeleteNotificationChannel(w http.ResponseWriter, r *http.Request, id api.Id) {
	c, err := s.DB.GetNotificationChannel(r.Context(), id)
	if err != nil {
		s.storeError(w, err)
		return
	}
	if err := s.DB.DeleteNotificationChannel(r.Context(), id); err != nil {
		s.storeError(w, err)
		return
	}
	s.audit(r, "notification_channel_deleted", fmt.Sprint(id), c.Name+" ("+c.Kind+")")
	w.WriteHeader(http.StatusNoContent)
}

// TestNotificationChannel envia a mensagem de teste e devolve o resultado real.
func (s *Server) TestNotificationChannel(w http.ResponseWriter, r *http.Request, id api.Id) {
	if !s.notifyReady(w) {
		return
	}
	c, err := s.DB.GetNotificationChannel(r.Context(), id)
	if err != nil {
		s.storeError(w, err)
		return
	}
	actor := principalFrom(r.Context()).Actor()
	entry, sendErr := s.Notify.SendTest(r.Context(), c, actor)
	out := api.NotificationTestResult{Ok: sendErr == nil, Entry: toAPIOutbox(entry)}
	detail := c.Name + ": enviado"
	if sendErr != nil {
		out.Error = ptr(entry.LastError)
		detail = c.Name + ": falhou: " + entry.LastError
	}
	s.audit(r, "notification_test", fmt.Sprint(id), detail)
	writeJSON(w, http.StatusOK, out)
}

func toAPIRule(rl store.NotificationRule) api.NotificationRule {
	return api.NotificationRule{Id: rl.ID, ChannelId: rl.ChannelID, Event: api.NotificationEvent(rl.Event),
		MinSeverity: api.Severity(rl.MinSeverity), DedupMinutes: rl.DedupMinutes, Enabled: rl.Enabled,
		CreatedAt: rl.CreatedAt, UpdatedAt: rl.UpdatedAt}
}

// ListNotificationRules lista as regras.
func (s *Server) ListNotificationRules(w http.ResponseWriter, r *http.Request) {
	list, err := s.DB.ListNotificationRules(r.Context())
	if err != nil {
		s.storeError(w, err)
		return
	}
	out := make([]api.NotificationRule, 0, len(list))
	for _, rl := range list {
		out = append(out, toAPIRule(rl))
	}
	writeJSON(w, http.StatusOK, out)
}

func ruleFrom(in api.NotificationRuleInput, rl *store.NotificationRule) string {
	rl.ChannelID, rl.Event = in.ChannelId, string(in.Event)
	if !slices.Contains(store.NotificationEvents, rl.Event) {
		return "evento de notificação inválido"
	}
	rl.MinSeverity = "high"
	if in.MinSeverity != nil {
		rl.MinSeverity = string(*in.MinSeverity)
	}
	if !notify.ValidSeverity(rl.MinSeverity) {
		return "severidade mínima inválida"
	}
	rl.DedupMinutes = notify.DefaultDedupMinutes(rl.Event)
	if in.DedupMinutes != nil {
		rl.DedupMinutes = *in.DedupMinutes
	}
	if rl.DedupMinutes < 0 || rl.DedupMinutes > 10080 {
		return "janela de deduplicação fora de 0..10080 minutos"
	}
	rl.Enabled = in.Enabled == nil || *in.Enabled
	return ""
}

func (s *Server) ruleError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, store.ErrNotFound):
		writeError(w, http.StatusBadRequest, "canal de notificação inexistente", "bad_request")
	case errors.Is(err, store.ErrDuplicate):
		writeError(w, http.StatusConflict, "este canal já tem uma regra para este evento; altere a existente", "duplicate")
	default:
		s.storeError(w, err)
	}
}

func ruleDetail(rl store.NotificationRule) string {
	return fmt.Sprintf("canal %d, evento %s, severidade mínima %s, janela %d min, ativa %v", rl.ChannelID, rl.Event,
		rl.MinSeverity, rl.DedupMinutes, rl.Enabled)
}

// CreateNotificationRule cria a regra.
func (s *Server) CreateNotificationRule(w http.ResponseWriter, r *http.Request) {
	var in api.NotificationRuleInput
	if !decode(w, r, &in) {
		return
	}
	var rl store.NotificationRule
	if msg := ruleFrom(in, &rl); msg != "" {
		writeError(w, http.StatusBadRequest, msg, "bad_request")
		return
	}
	if err := s.DB.CreateNotificationRule(r.Context(), &rl); err != nil {
		s.ruleError(w, err)
		return
	}
	s.audit(r, "notification_rule_created", fmt.Sprint(rl.ID), ruleDetail(rl))
	writeJSON(w, http.StatusCreated, toAPIRule(rl))
}

// UpdateNotificationRule altera a regra.
func (s *Server) UpdateNotificationRule(w http.ResponseWriter, r *http.Request, id api.Id) {
	var in api.NotificationRuleInput
	if !decode(w, r, &in) {
		return
	}
	rl, err := s.DB.GetNotificationRule(r.Context(), id)
	if err != nil {
		s.storeError(w, err)
		return
	}
	if msg := ruleFrom(in, &rl); msg != "" {
		writeError(w, http.StatusBadRequest, msg, "bad_request")
		return
	}
	if err := s.DB.UpdateNotificationRule(r.Context(), &rl); err != nil {
		s.ruleError(w, err)
		return
	}
	s.audit(r, "notification_rule_updated", fmt.Sprint(rl.ID), ruleDetail(rl))
	writeJSON(w, http.StatusOK, toAPIRule(rl))
}

// DeleteNotificationRule remove a regra.
func (s *Server) DeleteNotificationRule(w http.ResponseWriter, r *http.Request, id api.Id) {
	rl, err := s.DB.GetNotificationRule(r.Context(), id)
	if err != nil {
		s.storeError(w, err)
		return
	}
	if err := s.DB.DeleteNotificationRule(r.Context(), id); err != nil {
		s.storeError(w, err)
		return
	}
	s.audit(r, "notification_rule_deleted", fmt.Sprint(id), ruleDetail(rl))
	w.WriteHeader(http.StatusNoContent)
}

// ListNotificationOutbox lista a caixa de saída.
func (s *Server) ListNotificationOutbox(w http.ResponseWriter, r *http.Request, params api.ListNotificationOutboxParams) {
	f := store.OutboxFilter{Limit: 50}
	if params.State != nil {
		if !params.State.Valid() {
			writeError(w, http.StatusBadRequest, "estado inválido", "bad_request")
			return
		}
		f.State = string(*params.State)
	}
	if params.ChannelId != nil {
		f.ChannelID = *params.ChannelId
	}
	if params.Before != nil {
		f.BeforeID = *params.Before
	}
	if params.Limit != nil {
		f.Limit = *params.Limit
	}
	list, err := s.DB.ListOutbox(r.Context(), f)
	if err != nil {
		s.storeError(w, err)
		return
	}
	out := api.OutboxPage{Entries: make([]api.OutboxEntry, 0, len(list))}
	for _, e := range list {
		out.Entries = append(out.Entries, toAPIOutbox(e))
	}
	if len(list) == f.Limit && len(list) > 0 {
		out.NextBefore = ptr(list[len(list)-1].ID)
	}
	writeJSON(w, http.StatusOK, out)
}

// RetryNotification põe a mensagem para sair agora.
func (s *Server) RetryNotification(w http.ResponseWriter, r *http.Request, id api.Id) {
	e, err := s.DB.RetryNotification(r.Context(), id)
	if errors.Is(err, store.ErrConflict) {
		writeError(w, http.StatusConflict, "só mensagens pendentes ou com falha, de canal existente, podem ser reenviadas", "conflict")
		return
	}
	if err != nil {
		s.storeError(w, err)
		return
	}
	s.audit(r, "notification_retry", fmt.Sprint(id), e.ChannelName+": "+e.Event)
	if s.Notify != nil {
		s.Notify.Wake()
	}
	writeJSON(w, http.StatusOK, toAPIOutbox(e))
}

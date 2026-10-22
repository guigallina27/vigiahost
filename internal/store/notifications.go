package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"strings"
	"time"
)

// Eventos que as regras de notificação podem escolher (E1.12) e o evento das mensagens de teste.
const (
	EventFindingNew          = "finding_new"
	EventRunFailed           = "run_failed"
	EventRunPartial          = "run_partial"
	EventEngineSelfTest      = "engine_selftest_failed"
	EventExecutorUnavailable = "executor_unavailable"
	EventBackupFailed        = "backup_failed"
	EventTest                = "test"
)

// NotificationEvents lista os eventos aceitos nas regras, na ordem em que a interface os mostra.
var NotificationEvents = []string{EventFindingNew, EventRunFailed, EventRunPartial, EventEngineSelfTest,
	EventExecutorUnavailable, EventBackupFailed}

// Tipos de canal e estados da caixa de saída.
const (
	ChannelEmail   = "email"
	ChannelWebhook = "webhook"

	OutboxPending = "pending"
	OutboxSent    = "sent"
	OutboxFailed  = "failed"
)

// OutboxSampleItems limita os itens guardados numa mensagem agrupada; item_count continua contando todos.
const OutboxSampleItems = 25

// NotificationChannel é um destino de notificações. Config é JSON sem segredos; Secret é o segredo já cifrado.
type NotificationChannel struct {
	ID             int64
	Name           string
	Kind           string
	Enabled        bool
	Config         string
	Secret         []byte
	IncludeDetails bool
	CreatedBy      string
	CreatedAt      time.Time
	UpdatedAt      time.Time
}

const channelColumns = `id, name, kind, enabled, config, secret, include_details, created_by, created_at, updated_at`

func scanChannel(s scanner) (NotificationChannel, error) {
	var c NotificationChannel
	var enabled, details int
	var created, updated string
	err := s.Scan(&c.ID, &c.Name, &c.Kind, &enabled, &c.Config, &c.Secret, &details, &c.CreatedBy, &created, &updated)
	if errors.Is(err, sql.ErrNoRows) {
		return c, ErrNotFound
	}
	c.Enabled, c.IncludeDetails = enabled == 1, details == 1
	c.CreatedAt, c.UpdatedAt = parseTS(created), parseTS(updated)
	return c, err
}

// ListNotificationChannels lista os canais por nome.
func (d *DB) ListNotificationChannels(ctx context.Context) ([]NotificationChannel, error) {
	rows, err := d.QueryContext(ctx, `SELECT `+channelColumns+` FROM notification_channels ORDER BY name COLLATE NOCASE`)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var out []NotificationChannel
	for rows.Next() {
		c, err := scanChannel(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// GetNotificationChannel busca o canal.
func (d *DB) GetNotificationChannel(ctx context.Context, id int64) (NotificationChannel, error) {
	return scanChannel(d.QueryRowContext(ctx, `SELECT `+channelColumns+` FROM notification_channels WHERE id = ?`, id))
}

// CreateNotificationChannel grava o canal; nome repetido devolve ErrDuplicate.
func (d *DB) CreateNotificationChannel(ctx context.Context, c *NotificationChannel) error {
	now := d.now()
	c.CreatedAt, c.UpdatedAt = now, now
	err := d.QueryRowContext(ctx, `INSERT INTO notification_channels (name, kind, enabled, config, secret,
		include_details, created_by, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?) RETURNING id`,
		c.Name, c.Kind, boolInt(c.Enabled), c.Config, nullBlob(c.Secret), boolInt(c.IncludeDetails), c.CreatedBy,
		ts(now), ts(now)).Scan(&c.ID)
	if err != nil && strings.Contains(err.Error(), "UNIQUE") {
		return ErrDuplicate
	}
	return err
}

// UpdateNotificationChannel grava nome, estado, configuração, segredo e privacidade (o tipo não muda).
func (d *DB) UpdateNotificationChannel(ctx context.Context, c *NotificationChannel) error {
	c.UpdatedAt = d.now()
	res, err := d.ExecContext(ctx, `UPDATE notification_channels SET name = ?, enabled = ?, config = ?, secret = ?,
		include_details = ?, updated_at = ? WHERE id = ?`, c.Name, boolInt(c.Enabled), c.Config, nullBlob(c.Secret),
		boolInt(c.IncludeDetails), ts(c.UpdatedAt), c.ID)
	if err != nil {
		if strings.Contains(err.Error(), "UNIQUE") {
			return ErrDuplicate
		}
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

// DeleteNotificationChannel remove o canal com as regras dele. Mensagens pendentes viram falha ("canal removido");
// o histórico da caixa de saída fica, com o nome do canal guardado na própria mensagem.
func (d *DB) DeleteNotificationChannel(ctx context.Context, id int64) error {
	now := d.now()
	return d.tx(ctx, func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx, `UPDATE notification_outbox SET state = 'failed', next_attempt_at = NULL,
			last_error = 'canal removido antes do envio', updated_at = ? WHERE channel_id = ? AND state = 'pending'`,
			ts(now), id); err != nil {
			return err
		}
		res, err := tx.ExecContext(ctx, `DELETE FROM notification_channels WHERE id = ?`, id)
		if err != nil {
			return err
		}
		if n, _ := res.RowsAffected(); n == 0 {
			return ErrNotFound
		}
		return nil
	})
}

func nullBlob(b []byte) any {
	if len(b) == 0 {
		return nil
	}
	return b
}

// NotificationRule diz quais eventos um canal recebe.
type NotificationRule struct {
	ID           int64
	ChannelID    int64
	Event        string
	MinSeverity  string
	DedupMinutes int
	Enabled      bool
	CreatedAt    time.Time
	UpdatedAt    time.Time
}

const ruleColumns = `id, channel_id, event, min_severity, dedup_minutes, enabled, created_at, updated_at`

func scanRule(s scanner) (NotificationRule, error) {
	var r NotificationRule
	var enabled int
	var created, updated string
	err := s.Scan(&r.ID, &r.ChannelID, &r.Event, &r.MinSeverity, &r.DedupMinutes, &enabled, &created, &updated)
	if errors.Is(err, sql.ErrNoRows) {
		return r, ErrNotFound
	}
	r.Enabled = enabled == 1
	r.CreatedAt, r.UpdatedAt = parseTS(created), parseTS(updated)
	return r, err
}

// ListNotificationRules lista as regras por canal e evento.
func (d *DB) ListNotificationRules(ctx context.Context) ([]NotificationRule, error) {
	rows, err := d.QueryContext(ctx, `SELECT `+ruleColumns+` FROM notification_rules ORDER BY channel_id, event`)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var out []NotificationRule
	for rows.Next() {
		r, err := scanRule(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// GetNotificationRule busca a regra.
func (d *DB) GetNotificationRule(ctx context.Context, id int64) (NotificationRule, error) {
	return scanRule(d.QueryRowContext(ctx, `SELECT `+ruleColumns+` FROM notification_rules WHERE id = ?`, id))
}

// CreateNotificationRule grava a regra; canal inexistente devolve ErrNotFound e evento repetido no mesmo canal,
// ErrDuplicate.
func (d *DB) CreateNotificationRule(ctx context.Context, r *NotificationRule) error {
	if _, err := d.GetNotificationChannel(ctx, r.ChannelID); err != nil {
		return err
	}
	now := d.now()
	r.CreatedAt, r.UpdatedAt = now, now
	err := d.QueryRowContext(ctx, `INSERT INTO notification_rules (channel_id, event, min_severity, dedup_minutes,
		enabled, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?) RETURNING id`, r.ChannelID, r.Event,
		r.MinSeverity, r.DedupMinutes, boolInt(r.Enabled), ts(now), ts(now)).Scan(&r.ID)
	if err != nil && strings.Contains(err.Error(), "UNIQUE") {
		return ErrDuplicate
	}
	return err
}

// UpdateNotificationRule grava canal, evento, severidade mínima, janela e estado.
func (d *DB) UpdateNotificationRule(ctx context.Context, r *NotificationRule) error {
	if _, err := d.GetNotificationChannel(ctx, r.ChannelID); err != nil {
		return err
	}
	r.UpdatedAt = d.now()
	res, err := d.ExecContext(ctx, `UPDATE notification_rules SET channel_id = ?, event = ?, min_severity = ?,
		dedup_minutes = ?, enabled = ?, updated_at = ? WHERE id = ?`, r.ChannelID, r.Event, r.MinSeverity,
		r.DedupMinutes, boolInt(r.Enabled), ts(r.UpdatedAt), r.ID)
	if err != nil {
		if strings.Contains(err.Error(), "UNIQUE") {
			return ErrDuplicate
		}
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

// DeleteNotificationRule remove a regra.
func (d *DB) DeleteNotificationRule(ctx context.Context, id int64) error {
	res, err := d.ExecContext(ctx, `DELETE FROM notification_rules WHERE id = ?`, id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

// NotificationTarget é uma regra ativa de um canal ativo para um evento.
type NotificationTarget struct {
	Rule    NotificationRule
	Channel NotificationChannel
}

// NotificationTargets devolve as regras ativas do evento com o canal de cada uma (só canais ativos).
func (d *DB) NotificationTargets(ctx context.Context, event string) ([]NotificationTarget, error) {
	rows, err := d.QueryContext(ctx, `SELECT r.id, r.channel_id, r.event, r.min_severity, r.dedup_minutes, r.enabled,
		r.created_at, r.updated_at, c.id, c.name, c.kind, c.enabled, c.config, c.secret, c.include_details,
		c.created_by, c.created_at, c.updated_at
		FROM notification_rules r JOIN notification_channels c ON c.id = r.channel_id
		WHERE r.event = ? AND r.enabled = 1 AND c.enabled = 1 ORDER BY c.id`, event)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var out []NotificationTarget
	for rows.Next() {
		var t NotificationTarget
		var rEnabled, cEnabled, details int
		var rCreated, rUpdated, cCreated, cUpdated string
		if err := rows.Scan(&t.Rule.ID, &t.Rule.ChannelID, &t.Rule.Event, &t.Rule.MinSeverity, &t.Rule.DedupMinutes,
			&rEnabled, &rCreated, &rUpdated, &t.Channel.ID, &t.Channel.Name, &t.Channel.Kind, &cEnabled,
			&t.Channel.Config, &t.Channel.Secret, &details, &t.Channel.CreatedBy, &cCreated, &cUpdated); err != nil {
			return nil, err
		}
		t.Rule.Enabled, t.Channel.Enabled, t.Channel.IncludeDetails = rEnabled == 1, cEnabled == 1, details == 1
		t.Rule.CreatedAt, t.Rule.UpdatedAt = parseTS(rCreated), parseTS(rUpdated)
		t.Channel.CreatedAt, t.Channel.UpdatedAt = parseTS(cCreated), parseTS(cUpdated)
		out = append(out, t)
	}
	return out, rows.Err()
}

// OutboxEntry é uma mensagem da caixa de saída.
type OutboxEntry struct {
	ID             int64
	ChannelID      *int64
	ChannelName    string
	ChannelKind    string
	Event          string
	Items          []json.RawMessage
	ItemCount      int
	SeverityCounts map[string]int
	State          string
	Attempts       int
	MaxAttempts    int
	NextAttemptAt  *time.Time
	LastError      string
	CreatedAt      time.Time
	UpdatedAt      time.Time
	SentAt         *time.Time
}

const outboxColumns = `id, channel_id, channel_name, channel_kind, event, items, item_count, severity_counts, state,
	attempts, max_attempts, next_attempt_at, last_error, created_at, updated_at, sent_at`

func scanOutbox(s scanner) (OutboxEntry, error) {
	var e OutboxEntry
	var channel sql.NullInt64
	var items, counts, created, updated string
	var next, sent sql.NullString
	err := s.Scan(&e.ID, &channel, &e.ChannelName, &e.ChannelKind, &e.Event, &items, &e.ItemCount, &counts, &e.State,
		&e.Attempts, &e.MaxAttempts, &next, &e.LastError, &created, &updated, &sent)
	if errors.Is(err, sql.ErrNoRows) {
		return e, ErrNotFound
	}
	if err != nil {
		return e, err
	}
	if channel.Valid {
		id := channel.Int64
		e.ChannelID = &id
	}
	e.Items = fromJSON[[]json.RawMessage](items)
	e.SeverityCounts = fromJSON[map[string]int](counts)
	if e.SeverityCounts == nil {
		e.SeverityCounts = map[string]int{}
	}
	e.NextAttemptAt, e.SentAt = parseNullTS(next), parseNullTS(sent)
	e.CreatedAt, e.UpdatedAt = parseTS(created), parseTS(updated)
	return e, nil
}

// NotificationEnqueue é uma mensagem para um canal, já aprovada pela regra.
type NotificationEnqueue struct {
	ChannelID   int64
	ChannelName string
	ChannelKind string
	Event       string
	// DedupKey identifica o achado ou evento; com DedupWindow > 0, a mesma chave no mesmo canal não entra de novo
	// dentro da janela.
	DedupKey    string
	DedupWindow time.Duration
	// GroupWindow > 0 junta itens do mesmo evento e canal numa só mensagem enquanto ela não foi tentada; a primeira
	// tentativa acontece depois da janela.
	GroupWindow time.Duration
	Severity    string
	Item        json.RawMessage
	MaxAttempts int
}

// EnqueueResult conta o que aconteceu com cada item.
type EnqueueResult struct {
	Queued     int // mensagem nova
	Grouped    int // somado a uma mensagem pendente
	Suppressed int // dentro da janela de deduplicação
}

// EnqueueNotifications grava os itens na caixa de saída numa transação, aplicando deduplicação e agrupamento.
func (d *DB) EnqueueNotifications(ctx context.Context, list []NotificationEnqueue) (EnqueueResult, error) {
	var res EnqueueResult
	if len(list) == 0 {
		return res, nil
	}
	now := d.now()
	err := d.tx(ctx, func(tx *sql.Tx) error {
		for _, e := range list {
			if e.DedupKey != "" && e.DedupWindow > 0 {
				var last string
				err := tx.QueryRowContext(ctx, `SELECT last_at FROM notification_dedup WHERE channel_id = ? AND dedup_key = ?`,
					e.ChannelID, e.DedupKey).Scan(&last)
				if err != nil && !errors.Is(err, sql.ErrNoRows) {
					return err
				}
				if err == nil && parseTS(last).After(now.Add(-e.DedupWindow)) {
					res.Suppressed++
					continue
				}
				if _, err := tx.ExecContext(ctx, `INSERT INTO notification_dedup (channel_id, dedup_key, last_at)
					VALUES (?, ?, ?) ON CONFLICT (channel_id, dedup_key) DO UPDATE SET last_at = excluded.last_at`,
					e.ChannelID, e.DedupKey, ts(now)); err != nil {
					return err
				}
			}
			if e.GroupWindow > 0 {
				grouped, err := groupInto(ctx, tx, e, now)
				if err != nil {
					return err
				}
				if grouped {
					res.Grouped++
					continue
				}
			}
			next := now.Add(e.GroupWindow)
			maxAttempts := e.MaxAttempts
			if maxAttempts <= 0 {
				maxAttempts = 8
			}
			items := "[]"
			if len(e.Item) > 0 {
				items = "[" + string(e.Item) + "]"
			}
			if _, err := tx.ExecContext(ctx, `INSERT INTO notification_outbox (channel_id, channel_name, channel_kind,
				event, items, item_count, severity_counts, state, attempts, max_attempts, next_attempt_at, created_at,
				updated_at) VALUES (?, ?, ?, ?, ?, 1, ?, 'pending', 0, ?, ?, ?, ?)`, e.ChannelID, e.ChannelName,
				e.ChannelKind, e.Event, items, toJSON(map[string]int{e.Severity: 1}), maxAttempts, ts(next), ts(now),
				ts(now)); err != nil {
				return err
			}
			res.Queued++
		}
		return nil
	})
	return res, err
}

// groupInto soma o item à mensagem pendente do mesmo evento e canal que ainda não foi tentada. A condição
// attempts = 0 no UPDATE garante que nada entra numa mensagem que já saiu para envio.
func groupInto(ctx context.Context, tx *sql.Tx, e NotificationEnqueue, now time.Time) (bool, error) {
	var id int64
	var items, counts string
	var count int
	err := tx.QueryRowContext(ctx, `SELECT id, items, item_count, severity_counts FROM notification_outbox
		WHERE channel_id = ? AND event = ? AND state = 'pending' AND attempts = 0 ORDER BY id DESC LIMIT 1`,
		e.ChannelID, e.Event).Scan(&id, &items, &count, &counts)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	list := fromJSON[[]json.RawMessage](items)
	if len(list) < OutboxSampleItems && len(e.Item) > 0 {
		list = append(list, e.Item)
	}
	sev := fromJSON[map[string]int](counts)
	if sev == nil {
		sev = map[string]int{}
	}
	sev[e.Severity]++
	res, err := tx.ExecContext(ctx, `UPDATE notification_outbox SET items = ?, item_count = item_count + 1,
		severity_counts = ?, updated_at = ? WHERE id = ? AND attempts = 0 AND state = 'pending'`,
		toJSON(list), toJSON(sev), ts(now), id)
	if err != nil {
		return false, err
	}
	n, _ := res.RowsAffected()
	return n == 1, nil
}

// ClaimDueNotifications reserva as mensagens vencidas: conta a tentativa e empurra o próximo horário pela validade
// da reserva. Se o core cair no meio do envio, a mensagem volta sozinha depois da reserva.
func (d *DB) ClaimDueNotifications(ctx context.Context, lease time.Duration, limit int) ([]OutboxEntry, error) {
	if limit <= 0 {
		limit = 20
	}
	now := d.now()
	var out []OutboxEntry
	err := d.tx(ctx, func(tx *sql.Tx) error {
		rows, err := tx.QueryContext(ctx, `SELECT id FROM notification_outbox WHERE state = 'pending'
			AND next_attempt_at <= ? ORDER BY next_attempt_at, id LIMIT ?`, ts(now), limit)
		if err != nil {
			return err
		}
		var ids []int64
		for rows.Next() {
			var id int64
			if err := rows.Scan(&id); err != nil {
				_ = rows.Close()
				return err
			}
			ids = append(ids, id)
		}
		_ = rows.Close()
		if err := rows.Err(); err != nil {
			return err
		}
		for _, id := range ids {
			if _, err := tx.ExecContext(ctx, `UPDATE notification_outbox SET attempts = attempts + 1,
				next_attempt_at = ?, updated_at = ? WHERE id = ?`, ts(now.Add(lease)), ts(now), id); err != nil {
				return err
			}
			e, err := scanOutbox(tx.QueryRowContext(ctx, `SELECT `+outboxColumns+` FROM notification_outbox WHERE id = ?`, id))
			if err != nil {
				return err
			}
			out = append(out, e)
		}
		return nil
	})
	return out, err
}

// MarkNotificationSent registra o envio.
func (d *DB) MarkNotificationSent(ctx context.Context, id int64) error {
	now := d.now()
	_, err := d.ExecContext(ctx, `UPDATE notification_outbox SET state = 'sent', next_attempt_at = NULL, last_error = '',
		sent_at = ?, updated_at = ? WHERE id = ?`, ts(now), ts(now), id)
	return err
}

// MarkNotificationError registra a falha da tentativa: com retryAt, a mensagem volta a esperar; sem ele, a falha é
// definitiva.
func (d *DB) MarkNotificationError(ctx context.Context, id int64, msg string, retryAt *time.Time) error {
	now := d.now()
	state := OutboxFailed
	if retryAt != nil {
		state = OutboxPending
	}
	_, err := d.ExecContext(ctx, `UPDATE notification_outbox SET state = ?, next_attempt_at = ?, last_error = ?,
		updated_at = ? WHERE id = ?`, state, nullTS(retryAt), msg, ts(now), id)
	return err
}

// RecordNotification grava uma mensagem já tentada (o envio de teste é síncrono e fica no histórico).
func (d *DB) RecordNotification(ctx context.Context, e *OutboxEntry) error {
	now := d.now()
	e.CreatedAt, e.UpdatedAt = now, now
	if e.State == OutboxSent {
		e.SentAt = &now
	}
	if e.SeverityCounts == nil {
		e.SeverityCounts = map[string]int{}
	}
	if e.Items == nil {
		e.Items = []json.RawMessage{}
	}
	return d.QueryRowContext(ctx, `INSERT INTO notification_outbox (channel_id, channel_name, channel_kind, event,
		items, item_count, severity_counts, state, attempts, max_attempts, last_error, created_at, updated_at, sent_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) RETURNING id`, e.ChannelID, e.ChannelName, e.ChannelKind,
		e.Event, toJSON(e.Items), e.ItemCount, toJSON(e.SeverityCounts), e.State, e.Attempts, e.MaxAttempts,
		e.LastError, ts(now), ts(now), nullTS(e.SentAt)).Scan(&e.ID)
}

// GetOutboxEntry busca a mensagem.
func (d *DB) GetOutboxEntry(ctx context.Context, id int64) (OutboxEntry, error) {
	return scanOutbox(d.QueryRowContext(ctx, `SELECT `+outboxColumns+` FROM notification_outbox WHERE id = ?`, id))
}

// OutboxFilter seleciona mensagens da caixa de saída.
type OutboxFilter struct {
	State     string
	ChannelID int64
	BeforeID  int64
	Limit     int
}

// ListOutbox lista as mensagens da mais nova para a mais antiga.
func (d *DB) ListOutbox(ctx context.Context, f OutboxFilter) ([]OutboxEntry, error) {
	q := `SELECT ` + outboxColumns + ` FROM notification_outbox WHERE 1=1`
	var args []any
	if f.State != "" {
		q += ` AND state = ?`
		args = append(args, f.State)
	}
	if f.ChannelID > 0 {
		q += ` AND channel_id = ?`
		args = append(args, f.ChannelID)
	}
	if f.BeforeID > 0 {
		q += ` AND id < ?`
		args = append(args, f.BeforeID)
	}
	if f.Limit <= 0 || f.Limit > 500 {
		f.Limit = 50
	}
	q += ` ORDER BY id DESC LIMIT ?`
	args = append(args, f.Limit)
	rows, err := d.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var out []OutboxEntry
	for rows.Next() {
		e, err := scanOutbox(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// RetryNotification põe a mensagem para sair agora: falha definitiva volta com as tentativas zeradas; pendente só
// antecipa o horário. Mensagem enviada, de teste ou de canal removido devolve ErrConflict.
func (d *DB) RetryNotification(ctx context.Context, id int64) (OutboxEntry, error) {
	now := d.now()
	res, err := d.ExecContext(ctx, `UPDATE notification_outbox SET
		attempts = CASE WHEN state = 'failed' THEN 0 ELSE attempts END,
		state = 'pending', next_attempt_at = ?, updated_at = ?
		WHERE id = ? AND state IN ('pending', 'failed') AND channel_id IS NOT NULL AND event != 'test'`,
		ts(now), ts(now), id)
	if err != nil {
		return OutboxEntry{}, err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		if _, err := d.GetOutboxEntry(ctx, id); err != nil {
			return OutboxEntry{}, err
		}
		return OutboxEntry{}, ErrConflict
	}
	return d.GetOutboxEntry(ctx, id)
}

// PurgeNotifications apaga mensagens resolvidas (enviadas ou com falha definitiva) anteriores a outboxBefore e a
// memória de deduplicação anterior a dedupBefore.
func (d *DB) PurgeNotifications(ctx context.Context, outboxBefore, dedupBefore time.Time) (int64, error) {
	res, err := d.ExecContext(ctx, `DELETE FROM notification_outbox WHERE state != 'pending' AND updated_at < ?`,
		ts(outboxBefore))
	if err != nil {
		return 0, err
	}
	n, _ := res.RowsAffected()
	_, err = d.ExecContext(ctx, `DELETE FROM notification_dedup WHERE last_at < ?`, ts(dedupBefore))
	return n, err
}

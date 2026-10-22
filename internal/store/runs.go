package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/guigallina27/vigiahost/internal/report"
)

// Estados de uma execução na fila; os finais vêm de report.Status.
const (
	RunQueued   = "queued"
	RunReserved = "reserved"
	RunRunning  = "running"
)

// FinalStatuses são os estados em que a execução não muda mais.
var FinalStatuses = []string{
	string(report.StatusCompleted), string(report.StatusPartial), string(report.StatusFailed),
	string(report.StatusEngineError), string(report.StatusCanceled), string(report.StatusInterrupted),
}

// finalStatusList é FinalStatuses para o SQL (constante: não há entrada do usuário na consulta).
const finalStatusList = `('completed', 'partial', 'failed', 'engine_failure', 'canceled', 'interrupted')`

// IsFinal indica estado terminal.
func IsFinal(status string) bool {
	for _, s := range FinalStatuses {
		if s == status {
			return true
		}
	}
	return false
}

// Run é uma execução (e o job da fila que a representa).
type Run struct {
	ID             string
	Kind           report.Kind
	Status         string
	Origin         string
	RequestedBy    string
	ScheduleID     *int64
	ScheduledFor   *time.Time
	IdempotencyKey string
	Paths          []string
	Exclude        []string
	Incremental    bool
	Profile        report.Profile
	Priority       int
	Attempts       int
	LeaseUntil     *time.Time
	HeartbeatAt    *time.Time
	CreatedAt      time.Time
	StartedAt      *time.Time
	FinishedAt     *time.Time
	Phase          string
	Paused         bool
	FilesSeen      int64
	FilesEligible  int64
	FilesProcessed int64
	BytesEligible  int64
	BytesProcessed int64
	FindingsCount  int64
	FindingsOffset int64
	Summary        *report.Summary
	Error          string
	// Accounts são as contas (UID) que a execução cobre; Owners restringe raízes compartilhadas (/tmp...) aos
	// arquivos desses donos.
	Accounts []uint32
	Owners   map[string][]uint32
}

const runColumns = `id, kind, status, origin, requested_by, schedule_id, scheduled_for, COALESCE(idempotency_key, ''),
	paths, exclude, incremental, profile, priority, attempts, lease_until, heartbeat_at, created_at, started_at,
	finished_at, phase, paused, files_seen, files_eligible, files_processed, bytes_eligible, bytes_processed,
	findings_count, findings_offset, summary, error, accounts, owners`

type scanner interface{ Scan(...any) error }

func scanRun(s scanner) (Run, error) {
	var r Run
	var kind, paths, exclude, prof, accounts, owners string
	var schedID sql.NullInt64
	var schedFor, lease, hb, started, finished, summary sql.NullString
	var created string
	var incr, paused int
	err := s.Scan(&r.ID, &kind, &r.Status, &r.Origin, &r.RequestedBy, &schedID, &schedFor, &r.IdempotencyKey,
		&paths, &exclude, &incr, &prof, &r.Priority, &r.Attempts, &lease, &hb, &created, &started,
		&finished, &r.Phase, &paused, &r.FilesSeen, &r.FilesEligible, &r.FilesProcessed, &r.BytesEligible,
		&r.BytesProcessed, &r.FindingsCount, &r.FindingsOffset, &summary, &r.Error, &accounts, &owners)
	if errors.Is(err, sql.ErrNoRows) {
		return r, ErrNotFound
	}
	if err != nil {
		return r, err
	}
	r.Kind = report.Kind(kind)
	if schedID.Valid {
		v := schedID.Int64
		r.ScheduleID = &v
	}
	r.ScheduledFor, r.LeaseUntil, r.HeartbeatAt = parseNullTS(schedFor), parseNullTS(lease), parseNullTS(hb)
	r.StartedAt, r.FinishedAt = parseNullTS(started), parseNullTS(finished)
	r.CreatedAt = parseTS(created)
	r.Paths, r.Exclude = fromJSON[[]string](paths), fromJSON[[]string](exclude)
	r.Profile = fromJSON[report.Profile](prof)
	r.Accounts, r.Owners = fromJSON[[]uint32](accounts), fromJSON[map[string][]uint32](owners)
	r.Incremental, r.Paused = incr == 1, paused == 1
	if summary.Valid && summary.String != "" {
		s := fromJSON[report.Summary](summary.String)
		r.Summary = &s
	}
	return r, nil
}

// InsertRun enfileira uma execução. Chave de idempotência ou horário de agendamento repetidos devolvem ErrDuplicate.
func (d *DB) InsertRun(ctx context.Context, r *Run) error {
	if r.CreatedAt.IsZero() {
		r.CreatedAt = d.now()
	}
	if r.Status == "" {
		r.Status = RunQueued
	}
	var idem any
	if r.IdempotencyKey != "" {
		idem = r.IdempotencyKey
	}
	err := d.tx(ctx, func(tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx, `INSERT INTO runs (id, kind, status, origin, requested_by, schedule_id,
			scheduled_for, idempotency_key, paths, exclude, incremental, profile, priority, created_at, accounts, owners)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			r.ID, string(r.Kind), r.Status, r.Origin, r.RequestedBy, r.ScheduleID, nullTS(r.ScheduledFor), idem,
			toJSON(nonNil(r.Paths)), toJSON(nonNil(r.Exclude)), boolInt(r.Incremental), toJSON(r.Profile), r.Priority,
			ts(r.CreatedAt), accountsJSON(r.Accounts), ownersJSON(r.Owners))
		if err != nil {
			return err
		}
		return insertRunAccounts(ctx, tx, r.ID, r.Accounts)
	})
	if err != nil && strings.Contains(err.Error(), "UNIQUE") {
		return ErrDuplicate
	}
	return err
}

func accountsJSON(a []uint32) string {
	if a == nil {
		return "[]"
	}
	return toJSON(a)
}

func ownersJSON(o map[string][]uint32) string {
	if o == nil {
		return "{}"
	}
	return toJSON(o)
}

// insertRunAccounts indexa as contas da execução (para "última verificação" e o filtro por conta).
func insertRunAccounts(ctx context.Context, tx *sql.Tx, runID string, uids []uint32) error {
	for _, uid := range uids {
		if _, err := tx.ExecContext(ctx, `INSERT OR IGNORE INTO run_accounts (run_id, uid) VALUES (?, ?)`, runID, int64(uid)); err != nil {
			return err
		}
	}
	return nil
}

func nonNil(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

// GetRun devolve uma execução.
func (d *DB) GetRun(ctx context.Context, id string) (Run, error) {
	return scanRun(d.QueryRowContext(ctx, `SELECT `+runColumns+` FROM runs WHERE id = ?`, id))
}

// RunFilter seleciona execuções para a listagem (mais recentes primeiro, paginada por created_at).
type RunFilter struct {
	Statuses []string
	Kind     string
	Account  *uint32 // só execuções que cobriram esta conta
	Before   string  // cursor: created_at da última execução da página anterior
	Limit    int
}

// ListRuns lista execuções.
func (d *DB) ListRuns(ctx context.Context, f RunFilter) ([]Run, error) {
	q := `SELECT ` + runColumns + ` FROM runs WHERE 1=1`
	var args []any
	if len(f.Statuses) > 0 {
		q += ` AND status IN (` + placeholders(len(f.Statuses)) + `)`
		for _, s := range f.Statuses {
			args = append(args, s)
		}
	}
	if f.Kind != "" {
		q += ` AND kind = ?`
		args = append(args, f.Kind)
	}
	if f.Account != nil {
		q += ` AND id IN (SELECT run_id FROM run_accounts WHERE uid = ?)`
		args = append(args, int64(*f.Account))
	}
	if f.Before != "" {
		q += ` AND created_at < ?`
		args = append(args, f.Before)
	}
	if f.Limit <= 0 || f.Limit > 500 {
		f.Limit = 50
	}
	q += ` ORDER BY created_at DESC LIMIT ?`
	args = append(args, f.Limit)
	rows, err := d.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var out []Run
	for rows.Next() {
		r, err := scanRun(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

func placeholders(n int) string {
	return strings.TrimSuffix(strings.Repeat("?,", n), ",")
}

// ReserveNext reserva a próxima execução da fila (maior prioridade, mais antiga) com lease. Devolve ErrNotFound se
// a fila estiver vazia. Uma conexão só (ADR-003) torna o UPDATE ... RETURNING atômico.
func (d *DB) ReserveNext(ctx context.Context, kind report.Kind, lease time.Duration) (Run, error) {
	now := d.now()
	return scanRun(d.QueryRowContext(ctx, `UPDATE runs SET status = 'reserved', lease_until = ?, heartbeat_at = ?,
		attempts = attempts + 1
		WHERE id = (SELECT id FROM runs WHERE status = 'queued' AND kind = ? ORDER BY priority DESC, created_at LIMIT 1)
		RETURNING `+runColumns, ts(now.Add(lease)), ts(now), string(kind)))
}

// MarkRunning registra que o executor aceitou a execução.
func (d *DB) MarkRunning(ctx context.Context, id string, lease time.Duration) error {
	now := d.now()
	_, err := d.ExecContext(ctx, `UPDATE runs SET status = 'running', started_at = COALESCE(started_at, ?),
		lease_until = ?, heartbeat_at = ? WHERE id = ?`, ts(now), ts(now.Add(lease)), ts(now), id)
	return err
}

// Requeue devolve à fila uma execução reservada que não chegou a rodar (executor indisponível).
func (d *DB) Requeue(ctx context.Context, id, reason string) error {
	_, err := d.ExecContext(ctx, `UPDATE runs SET status = 'queued', lease_until = NULL, error = ?
		WHERE id = ? AND status = 'reserved'`, reason, id)
	return err
}

// UpdateProgress grava progresso e renova o lease (heartbeat).
func (d *DB) UpdateProgress(ctx context.Context, id string, p report.Progress, paused bool, lease time.Duration) error {
	now := d.now()
	_, err := d.ExecContext(ctx, `UPDATE runs SET phase = ?, paused = ?, files_seen = ?, files_eligible = ?,
		files_processed = ?, bytes_eligible = ?, bytes_processed = ?, heartbeat_at = ?, lease_until = ?
		WHERE id = ? AND status = 'running'`,
		string(p.Phase), boolInt(paused), p.FilesSeen, p.FilesEligible, p.FilesProcessed, p.BytesEligible,
		p.BytesProcessed, ts(now), ts(now.Add(lease)), id)
	return err
}

// FinishRun grava o estado final, o resumo e a cobertura por motor.
func (d *DB) FinishRun(ctx context.Context, id, status string, sum *report.Summary, errMsg string) error {
	if !IsFinal(status) {
		return fmt.Errorf("estado final inválido: %s", status)
	}
	now := d.now()
	return d.tx(ctx, func(tx *sql.Tx) error {
		var summary any
		if sum != nil {
			summary = toJSON(sum)
		}
		res, err := tx.ExecContext(ctx, `UPDATE runs SET status = ?, finished_at = ?, summary = COALESCE(?, summary),
			error = ?, lease_until = NULL, paused = 0, phase = 'done' WHERE id = ? AND status NOT IN `+finalStatusList,
			status, ts(now), summary, errMsg, id)
		if err != nil {
			return err
		}
		if n, _ := res.RowsAffected(); n == 0 {
			return ErrConflict
		}
		if sum == nil {
			return nil
		}
		if _, err := tx.ExecContext(ctx, `UPDATE runs SET files_seen = ?, files_eligible = ?, bytes_eligible = ?
			WHERE id = ?`, sum.FilesSeen, sum.FilesEligible, sum.BytesEligible, id); err != nil {
			return err
		}
		for _, e := range sum.Engines {
			if _, err := tx.ExecContext(ctx, `INSERT INTO run_engines (run_id, engine, version, rules_version, available,
				selftest_passed, selftest_detail, eligible, analyzed, from_cache, bytes_analyzed, seconds, skipped, errors, error)
				VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
				ON CONFLICT (run_id, engine) DO UPDATE SET version = excluded.version, rules_version = excluded.rules_version,
				available = excluded.available, selftest_passed = excluded.selftest_passed,
				selftest_detail = excluded.selftest_detail, eligible = excluded.eligible, analyzed = excluded.analyzed,
				from_cache = excluded.from_cache, bytes_analyzed = excluded.bytes_analyzed, seconds = excluded.seconds,
				skipped = excluded.skipped, errors = excluded.errors, error = excluded.error`,
				id, e.Engine, e.Version, e.RulesVersion, boolInt(e.Available), boolInt(e.SelfTest.Passed()), e.SelfTest.Detail,
				e.Eligible, e.Analyzed, e.FromCache, e.BytesAnalyzed, e.Seconds, toJSON(e.Skipped), toJSON(e.Errors), e.Error); err != nil {
				return err
			}
		}
		return nil
	})
}

func anySlice(s []string) []any {
	out := make([]any, len(s))
	for i, v := range s {
		out[i] = v
	}
	return out
}

// RunEngine é a cobertura de um motor numa execução.
type RunEngine struct {
	Engine         string
	Version        string
	RulesVersion   string
	Available      bool
	SelfTestPassed bool
	SelfTestDetail string
	Eligible       int64
	Analyzed       int64
	FromCache      int64
	BytesAnalyzed  int64
	Seconds        float64
	Skipped        map[string]int64
	Errors         map[string]int64
	Error          string
}

// RunEngines devolve a cobertura por motor de uma execução.
func (d *DB) RunEngines(ctx context.Context, runID string) ([]RunEngine, error) {
	rows, err := d.QueryContext(ctx, `SELECT engine, version, rules_version, available, selftest_passed, selftest_detail,
		eligible, analyzed, from_cache, bytes_analyzed, seconds, skipped, errors, error
		FROM run_engines WHERE run_id = ? ORDER BY engine`, runID)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var out []RunEngine
	for rows.Next() {
		var e RunEngine
		var avail, st int
		var skipped, errs string
		if err := rows.Scan(&e.Engine, &e.Version, &e.RulesVersion, &avail, &st, &e.SelfTestDetail, &e.Eligible,
			&e.Analyzed, &e.FromCache, &e.BytesAnalyzed, &e.Seconds, &skipped, &errs, &e.Error); err != nil {
			return nil, err
		}
		e.Available, e.SelfTestPassed = avail == 1, st == 1
		e.Skipped, e.Errors = fromJSON[map[string]int64](skipped), fromJSON[map[string]int64](errs)
		out = append(out, e)
	}
	return out, rows.Err()
}

// ActiveRuns devolve execuções reservadas ou rodando (para acompanhar e reconciliar).
func (d *DB) ActiveRuns(ctx context.Context) ([]Run, error) {
	return d.ListRuns(ctx, RunFilter{Statuses: []string{RunReserved, RunRunning}, Limit: 500})
}

// CountActive conta execuções reservadas ou rodando de um tipo.
func (d *DB) CountActive(ctx context.Context, kind report.Kind) (int, error) {
	var n int
	err := d.QueryRowContext(ctx, `SELECT COUNT(*) FROM runs WHERE status IN ('reserved', 'running') AND kind = ?`,
		string(kind)).Scan(&n)
	return n, err
}

// SetPaused registra pausa ou retomada pedida pelo operador.
func (d *DB) SetPaused(ctx context.Context, id string, paused bool) error {
	_, err := d.ExecContext(ctx, `UPDATE runs SET paused = ? WHERE id = ?`, boolInt(paused), id)
	return err
}

// CancelQueued cancela uma execução ainda na fila (sem passar pelo executor).
func (d *DB) CancelQueued(ctx context.Context, id string) (bool, error) {
	now := d.now()
	res, err := d.ExecContext(ctx, `UPDATE runs SET status = 'canceled', finished_at = ?, phase = 'done'
		WHERE id = ? AND status = 'queued'`, ts(now), id)
	if err != nil {
		return false, err
	}
	n, _ := res.RowsAffected()
	return n == 1, nil
}

// LastFinishedRun devolve a última execução terminada de um tipo (para a visão geral).
func (d *DB) LastFinishedRun(ctx context.Context, kind report.Kind) (Run, error) {
	return scanRun(d.QueryRowContext(ctx, `SELECT `+runColumns+` FROM runs WHERE kind = ? AND finished_at IS NOT NULL
		ORDER BY finished_at DESC LIMIT 1`, string(kind)))
}

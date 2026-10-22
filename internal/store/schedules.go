package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/robfig/cron/v3"

	"github.com/guigallina27/vigiahost/internal/report"
)

// Políticas para horários perdidos (core parado, servidor desligado).
const (
	MissedSkip    = "skip"     // pula e espera o próximo horário
	MissedRunOnce = "run_once" // roda uma vez só, por mais horários que tenham passado
)

// Schedule é um agendamento recorrente de execução.
type Schedule struct {
	ID           int64
	Name         string
	Kind         report.Kind
	Cron         string
	Timezone     string
	Paths        []string
	Exclude      []string
	Incremental  bool
	Profile      string
	MissedPolicy string
	Enabled      bool
	NextRunAt    *time.Time
	LastRunAt    *time.Time
	CreatedBy    string
	CreatedAt    time.Time
	UpdatedAt    time.Time
}

var cronParser = cron.NewParser(cron.Minute | cron.Hour | cron.Dom | cron.Month | cron.Dow | cron.Descriptor)

// ParseCron valida a expressão (5 campos ou @daily, @weekly...) no fuso indicado.
func ParseCron(expr, tz string) (cron.Schedule, *time.Location, error) {
	loc, err := time.LoadLocation(tz)
	if err != nil {
		return nil, nil, fmt.Errorf("fuso horário inválido: %s", tz)
	}
	s, err := cronParser.Parse(expr)
	if err != nil {
		return nil, nil, fmt.Errorf("expressão cron inválida: %w", err)
	}
	return s, loc, nil
}

// NextAfter calcula o próximo horário depois de t, no fuso do agendamento.
func (s Schedule) NextAfter(t time.Time) (time.Time, error) {
	c, loc, err := ParseCron(s.Cron, s.Timezone)
	if err != nil {
		return time.Time{}, err
	}
	n := c.Next(t.In(loc))
	if n.IsZero() {
		return n, errors.New("a expressão não gera horários futuros")
	}
	return n.UTC(), nil
}

const scheduleColumns = `id, name, kind, cron, timezone, paths, exclude, incremental, profile, missed_policy, enabled,
	next_run_at, last_run_at, created_by, created_at, updated_at`

func scanSchedule(s scanner) (Schedule, error) {
	var sc Schedule
	var kind, paths, exclude, created, updated string
	var incr, enabled int
	var next, last sql.NullString
	err := s.Scan(&sc.ID, &sc.Name, &kind, &sc.Cron, &sc.Timezone, &paths, &exclude, &incr, &sc.Profile,
		&sc.MissedPolicy, &enabled, &next, &last, &sc.CreatedBy, &created, &updated)
	if errors.Is(err, sql.ErrNoRows) {
		return sc, ErrNotFound
	}
	if err != nil {
		return sc, err
	}
	sc.Kind = report.Kind(kind)
	sc.Paths, sc.Exclude = fromJSON[[]string](paths), fromJSON[[]string](exclude)
	sc.Incremental, sc.Enabled = incr == 1, enabled == 1
	sc.NextRunAt, sc.LastRunAt = parseNullTS(next), parseNullTS(last)
	sc.CreatedAt, sc.UpdatedAt = parseTS(created), parseTS(updated)
	return sc, nil
}

// SaveSchedule cria (ID zero) ou atualiza o agendamento, recalculando o próximo horário.
func (d *DB) SaveSchedule(ctx context.Context, s *Schedule) error {
	now := d.now()
	if s.Timezone == "" {
		s.Timezone = "UTC"
	}
	if s.MissedPolicy == "" {
		s.MissedPolicy = MissedRunOnce
	}
	next, err := s.NextAfter(now)
	if err != nil {
		return err
	}
	if s.Enabled {
		s.NextRunAt = &next
	} else {
		s.NextRunAt = nil
	}
	s.UpdatedAt = now
	if s.ID == 0 {
		s.CreatedAt = now
		return d.QueryRowContext(ctx, `INSERT INTO schedules (name, kind, cron, timezone, paths, exclude, incremental,
			profile, missed_policy, enabled, next_run_at, created_by, created_at, updated_at)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) RETURNING id`,
			s.Name, string(s.Kind), s.Cron, s.Timezone, toJSON(nonNil(s.Paths)), toJSON(nonNil(s.Exclude)),
			boolInt(s.Incremental), s.Profile, s.MissedPolicy, boolInt(s.Enabled), nullTS(s.NextRunAt), s.CreatedBy,
			ts(now), ts(now)).Scan(&s.ID)
	}
	res, err := d.ExecContext(ctx, `UPDATE schedules SET name = ?, kind = ?, cron = ?, timezone = ?, paths = ?,
		exclude = ?, incremental = ?, profile = ?, missed_policy = ?, enabled = ?, next_run_at = ?, updated_at = ?
		WHERE id = ?`, s.Name, string(s.Kind), s.Cron, s.Timezone, toJSON(nonNil(s.Paths)), toJSON(nonNil(s.Exclude)),
		boolInt(s.Incremental), s.Profile, s.MissedPolicy, boolInt(s.Enabled), nullTS(s.NextRunAt), ts(now), s.ID)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

// GetSchedule devolve um agendamento.
func (d *DB) GetSchedule(ctx context.Context, id int64) (Schedule, error) {
	return scanSchedule(d.QueryRowContext(ctx, `SELECT `+scheduleColumns+` FROM schedules WHERE id = ?`, id))
}

// ListSchedules devolve todos os agendamentos.
func (d *DB) ListSchedules(ctx context.Context) ([]Schedule, error) {
	return d.querySchedules(ctx, `SELECT `+scheduleColumns+` FROM schedules ORDER BY name, id`)
}

// DueSchedules devolve os agendamentos ativos com horário vencido.
func (d *DB) DueSchedules(ctx context.Context, now time.Time) ([]Schedule, error) {
	return d.querySchedules(ctx, `SELECT `+scheduleColumns+` FROM schedules
		WHERE enabled = 1 AND next_run_at IS NOT NULL AND next_run_at <= ? ORDER BY next_run_at`, ts(now))
}

func (d *DB) querySchedules(ctx context.Context, q string, args ...any) ([]Schedule, error) {
	rows, err := d.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var out []Schedule
	for rows.Next() {
		s, err := scanSchedule(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	return out, rows.Err()
}

// DeleteSchedule remove o agendamento; as execuções que ele criou ficam (schedule_id vira nulo).
func (d *DB) DeleteSchedule(ctx context.Context, id int64) error {
	res, err := d.ExecContext(ctx, `DELETE FROM schedules WHERE id = ?`, id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

// FireSchedule enfileira a execução do horário vencido e avança o próximo horário, na mesma transação. O índice
// único (schedule_id, scheduled_for) impede execução duplicada se o core reiniciar no meio. Com a política "skip",
// horário vencido há mais de grace só avança, sem enfileirar.
func (d *DB) FireSchedule(ctx context.Context, s Schedule, run *Run, grace time.Duration) (fired bool, err error) {
	now := d.now()
	if s.NextRunAt == nil {
		return false, nil
	}
	slot := *s.NextRunAt
	next, err := s.NextAfter(now)
	if err != nil {
		return false, err
	}
	late := now.Sub(slot) > grace
	err = d.tx(ctx, func(tx *sql.Tx) error {
		if !late || s.MissedPolicy == MissedRunOnce {
			run.Origin, run.ScheduleID, run.ScheduledFor = "schedule", &s.ID, &slot
			if run.CreatedAt.IsZero() {
				run.CreatedAt = now
			}
			_, err := tx.ExecContext(ctx, `INSERT INTO runs (id, kind, status, origin, requested_by, schedule_id,
				scheduled_for, paths, exclude, incremental, profile, priority, created_at)
				VALUES (?, ?, 'queued', 'schedule', ?, ?, ?, ?, ?, ?, ?, ?, ?)
				ON CONFLICT (schedule_id, scheduled_for) WHERE schedule_id IS NOT NULL DO NOTHING`,
				run.ID, string(run.Kind), run.RequestedBy, s.ID, ts(slot), toJSON(nonNil(run.Paths)),
				toJSON(nonNil(run.Exclude)), boolInt(run.Incremental), toJSON(run.Profile), run.Priority, ts(run.CreatedAt))
			if err != nil {
				return err
			}
			fired = true
		}
		_, err := tx.ExecContext(ctx, `UPDATE schedules SET next_run_at = ?, last_run_at = CASE WHEN ? THEN ? ELSE last_run_at END
			WHERE id = ?`, ts(next), boolInt(fired), ts(slot), s.ID)
		return err
	})
	return fired, err
}

// ResourceProfile é um perfil de recursos personalizado guardado pelo operador (sobrepõe o pré-definido de mesmo
// nome; os limites ainda passam pelas travas do executor).
type ResourceProfile struct {
	Profile   report.Profile
	UpdatedBy string
	UpdatedAt time.Time
}

// ResourceProfiles devolve os perfis personalizados por nome.
func (d *DB) ResourceProfiles(ctx context.Context) (map[string]ResourceProfile, error) {
	rows, err := d.QueryContext(ctx, `SELECT name, profile, updated_by, updated_at FROM resource_profiles`)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	out := map[string]ResourceProfile{}
	for rows.Next() {
		var name, prof, by, at string
		if err := rows.Scan(&name, &prof, &by, &at); err != nil {
			return nil, err
		}
		out[name] = ResourceProfile{Profile: fromJSON[report.Profile](prof), UpdatedBy: by, UpdatedAt: parseTS(at)}
	}
	return out, rows.Err()
}

// SaveResourceProfile grava (ou substitui) um perfil personalizado.
func (d *DB) SaveResourceProfile(ctx context.Context, p report.Profile, by string) error {
	_, err := d.ExecContext(ctx, `INSERT INTO resource_profiles (name, profile, updated_by, updated_at) VALUES (?, ?, ?, ?)
		ON CONFLICT (name) DO UPDATE SET profile = excluded.profile, updated_by = excluded.updated_by,
		updated_at = excluded.updated_at`, p.Name, toJSON(p), by, ts(d.now()))
	return err
}

// DeleteResourceProfile volta o perfil ao pré-definido.
func (d *DB) DeleteResourceProfile(ctx context.Context, name string) error {
	_, err := d.ExecContext(ctx, `DELETE FROM resource_profiles WHERE name = ?`, name)
	return err
}

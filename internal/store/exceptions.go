package store

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"time"

	"github.com/guigallina27/vigiahost/internal/report"
)

// Escopos de exceção (escopo, seção 11).
const (
	ScopeHash       = "hash"
	ScopeHashRule   = "hash_rule"
	ScopeRulePrefix = "rule_prefix"
	ScopeRuleGlobal = "rule_global"
)

// Exception oculta achados que o operador revisou.
type Exception struct {
	ID         int64
	Scope      string
	SHA256     string
	Signature  string
	PathPrefix string
	Reason     string
	CreatedBy  string
	CreatedAt  time.Time
	ExpiresAt  *time.Time
	RevokedAt  *time.Time
	RevokedBy  string
}

// Active indica exceção válida no instante.
func (e Exception) Active(now time.Time) bool {
	return e.RevokedAt == nil && (e.ExpiresAt == nil || now.Before(*e.ExpiresAt))
}

// Matches confere se a exceção cobre o achado. Hash deixa de valer se o conteúdo mudar (o hash muda junto).
func (e Exception) Matches(f report.Finding) bool {
	switch e.Scope {
	case ScopeHash:
		return f.SHA256 != "" && f.SHA256 == e.SHA256
	case ScopeHashRule:
		return f.SHA256 != "" && f.SHA256 == e.SHA256 && f.Signature == e.Signature
	case ScopeRulePrefix:
		if f.Signature != e.Signature || f.Location == nil || e.PathPrefix == "" {
			return false
		}
		p, pre := f.Location.Path, strings.TrimSuffix(e.PathPrefix, "/")
		return p == pre || strings.HasPrefix(p, pre+"/")
	case ScopeRuleGlobal:
		return f.Signature == e.Signature
	}
	return false
}

func matchException(excs []Exception, f report.Finding) *Exception {
	for i := range excs {
		if excs[i].Matches(f) {
			return &excs[i]
		}
	}
	return nil
}

const exceptionColumns = `id, scope, sha256, signature, path_prefix, reason, created_by, created_at, expires_at,
	revoked_at, revoked_by`

func scanException(s scanner) (Exception, error) {
	var e Exception
	var created string
	var expires, revoked sql.NullString
	err := s.Scan(&e.ID, &e.Scope, &e.SHA256, &e.Signature, &e.PathPrefix, &e.Reason, &e.CreatedBy, &created,
		&expires, &revoked, &e.RevokedBy)
	if errors.Is(err, sql.ErrNoRows) {
		return e, ErrNotFound
	}
	e.CreatedAt, e.ExpiresAt, e.RevokedAt = parseTS(created), parseNullTS(expires), parseNullTS(revoked)
	return e, err
}

type querier interface {
	QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error)
}

func activeExceptions(ctx context.Context, q querier, now time.Time) ([]Exception, error) {
	rows, err := q.QueryContext(ctx, `SELECT `+exceptionColumns+` FROM exceptions
		WHERE revoked_at IS NULL AND (expires_at IS NULL OR expires_at > ?)`, ts(now))
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var out []Exception
	for rows.Next() {
		e, err := scanException(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// CreateException grava a exceção e aplica aos achados abertos que ela cobre.
func (d *DB) CreateException(ctx context.Context, e *Exception) error {
	now := d.now()
	e.CreatedAt = now
	return d.tx(ctx, func(tx *sql.Tx) error {
		if err := tx.QueryRowContext(ctx, `INSERT INTO exceptions (scope, sha256, signature, path_prefix, reason,
			created_by, created_at, expires_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?) RETURNING id`,
			e.Scope, e.SHA256, e.Signature, e.PathPrefix, e.Reason, e.CreatedBy, ts(now), nullTS(e.ExpiresAt)).Scan(&e.ID); err != nil {
			return err
		}
		rows, err := tx.QueryContext(ctx, `SELECT f.id, f.state, f.signature, COALESCE(f.sha256, ''), COALESCE(l.path, '')
			FROM findings f LEFT JOIN locations l ON l.id = f.location_id WHERE f.state IN ('new', 'in_review')`)
		if err != nil {
			return err
		}
		type hit struct {
			id    int64
			state string
		}
		var hits []hit
		for rows.Next() {
			var h hit
			var f report.Finding
			var path string
			if err := rows.Scan(&h.id, &h.state, &f.Signature, &f.SHA256, &path); err != nil {
				_ = rows.Close()
				return err
			}
			if path != "" {
				f.Location = &report.Location{Path: path}
			}
			if e.Matches(f) {
				hits = append(hits, h)
			}
		}
		_ = rows.Close()
		for _, h := range hits {
			if _, err := tx.ExecContext(ctx, `UPDATE findings SET state = 'excepted', exception_id = ?, state_changed = ?
				WHERE id = ?`, e.ID, ts(now), h.id); err != nil {
				return err
			}
			if err := addEvent(ctx, tx, h.id, now, e.CreatedBy, "state", h.state, StateExcepted, "coberto pela exceção: "+e.Reason); err != nil {
				return err
			}
		}
		return nil
	})
}

// ListExceptions devolve as exceções (revogadas incluídas quando all).
func (d *DB) ListExceptions(ctx context.Context, all bool) ([]Exception, error) {
	q := `SELECT ` + exceptionColumns + ` FROM exceptions`
	if !all {
		q += ` WHERE revoked_at IS NULL`
	}
	rows, err := d.QueryContext(ctx, q+` ORDER BY id DESC LIMIT 1000`)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var out []Exception
	for rows.Next() {
		e, err := scanException(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// RevokeException revoga; os achados cobertos voltam a "novo" na próxima detecção.
func (d *DB) RevokeException(ctx context.Context, id int64, by string) error {
	res, err := d.ExecContext(ctx, `UPDATE exceptions SET revoked_at = ?, revoked_by = ? WHERE id = ? AND revoked_at IS NULL`,
		ts(d.now()), by, id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

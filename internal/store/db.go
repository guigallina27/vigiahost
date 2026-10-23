package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"time"
)

// Erros comuns da camada de dados.
var (
	ErrNotFound  = errors.New("registro não encontrado")
	ErrDuplicate = errors.New("registro duplicado")
	ErrConflict  = errors.New("estado não permite a operação")
)

// DB envolve o banco com as consultas tipadas do produto. Um único escritor (ADR-003): as gravações passam pela
// conexão única aberta por Open.
type DB struct {
	*sql.DB
	// Now permite fixar o relógio nos testes.
	Now func() time.Time
}

// New envolve um *sql.DB já migrado.
func New(db *sql.DB) *DB { return &DB{DB: db, Now: func() time.Time { return time.Now().UTC() }} }

func (d *DB) now() time.Time { return d.Now().UTC() }

// ts formata datas sempre em UTC com nanossegundos (ordenação lexicográfica = cronológica).
func ts(t time.Time) string { return t.UTC().Format("2006-01-02T15:04:05.000000000Z") }

func parseTS(s string) time.Time {
	t, _ := time.Parse(time.RFC3339Nano, s)
	return t.UTC()
}

func nullTS(t *time.Time) any {
	if t == nil || t.IsZero() {
		return nil
	}
	return ts(*t)
}

func parseNullTS(ns sql.NullString) *time.Time {
	if !ns.Valid || ns.String == "" {
		return nil
	}
	t := parseTS(ns.String)
	return &t
}

func toJSON(v any) string {
	b, err := json.Marshal(v)
	if err != nil {
		return "null"
	}
	return string(b)
}

func fromJSON[T any](s string) T {
	var v T
	_ = json.Unmarshal([]byte(s), &v)
	return v
}

func boolInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

// tx executa fn numa transação; erro desfaz tudo.
func (d *DB) tx(ctx context.Context, fn func(*sql.Tx) error) error {
	t, err := d.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	if err := fn(t); err != nil {
		_ = t.Rollback()
		return err
	}
	return t.Commit()
}

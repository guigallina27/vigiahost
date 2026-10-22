package store

import (
	"context"
	"database/sql"
	"errors"
	"time"
)

// Snapshot é o instantâneo de uma inspeção de processos (JSON como o executor gravou).
type Snapshot struct {
	RunID       string
	TakenAt     time.Time
	Processes   []byte
	Persistence []byte
}

// SnapshotsKept é quantos instantâneos ficam guardados (os mais antigos saem a cada gravação).
const SnapshotsKept = 30

// SaveSnapshot grava o instantâneo de uma execução e descarta os antigos.
func (d *DB) SaveSnapshot(ctx context.Context, s Snapshot) error {
	return d.tx(ctx, func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx, `INSERT INTO inventory_snapshots (run_id, taken_at, processes, persistence)
			VALUES (?, ?, ?, ?) ON CONFLICT (run_id) DO UPDATE SET taken_at = excluded.taken_at,
			processes = excluded.processes, persistence = excluded.persistence`,
			s.RunID, ts(s.TakenAt), string(s.Processes), string(s.Persistence)); err != nil {
			return err
		}
		_, err := tx.ExecContext(ctx, `DELETE FROM inventory_snapshots WHERE run_id NOT IN
			(SELECT run_id FROM inventory_snapshots ORDER BY taken_at DESC LIMIT ?)`, SnapshotsKept)
		return err
	})
}

// GetSnapshot devolve o instantâneo de uma execução ou, com runID vazio, o mais recente.
func (d *DB) GetSnapshot(ctx context.Context, runID string) (Snapshot, error) {
	q := `SELECT run_id, taken_at, processes, persistence FROM inventory_snapshots `
	args := []any{}
	if runID == "" {
		q += `ORDER BY taken_at DESC LIMIT 1`
	} else {
		q += `WHERE run_id = ?`
		args = append(args, runID)
	}
	var s Snapshot
	var taken, procs, pers string
	err := d.QueryRowContext(ctx, q, args...).Scan(&s.RunID, &taken, &procs, &pers)
	if errors.Is(err, sql.ErrNoRows) {
		return s, ErrNotFound
	}
	if err != nil {
		return s, err
	}
	s.TakenAt, s.Processes, s.Persistence = parseTS(taken), []byte(procs), []byte(pers)
	return s, nil
}

package store

import (
	"context"
	"database/sql"
	"errors"
	"time"
)

// Nomes dos relatórios das verificações do sistema.
const (
	HostReportIntegrity = "integrity"
	HostReportUpdates   = "updates"
	HostReportHidden    = "hidden"
)

// HostReport é o relatório de uma verificação do sistema (JSON como o executor gravou).
type HostReport struct {
	RunID   string
	Name    string
	TakenAt time.Time
	Data    []byte
}

// HostReportsKept é quantos relatórios de cada nome ficam guardados.
const HostReportsKept = 30

// SaveHostReport grava o relatório de uma execução e descarta os mais antigos do mesmo nome.
func (d *DB) SaveHostReport(ctx context.Context, r HostReport) error {
	return d.tx(ctx, func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx, `INSERT INTO host_reports (run_id, name, taken_at, data) VALUES (?, ?, ?, ?)
			ON CONFLICT (run_id, name) DO UPDATE SET taken_at = excluded.taken_at, data = excluded.data`,
			r.RunID, r.Name, ts(r.TakenAt), string(r.Data)); err != nil {
			return err
		}
		_, err := tx.ExecContext(ctx, `DELETE FROM host_reports WHERE name = ? AND run_id NOT IN
			(SELECT run_id FROM host_reports WHERE name = ? ORDER BY taken_at DESC LIMIT ?)`, r.Name, r.Name, HostReportsKept)
		return err
	})
}

// GetHostReport devolve o relatório de uma execução ou, com runID vazio, o mais recente daquele nome.
func (d *DB) GetHostReport(ctx context.Context, name, runID string) (HostReport, error) {
	q := `SELECT run_id, name, taken_at, data FROM host_reports WHERE name = ? `
	args := []any{name}
	if runID == "" {
		q += `ORDER BY taken_at DESC LIMIT 1`
	} else {
		q += `AND run_id = ?`
		args = append(args, runID)
	}
	var r HostReport
	var taken, data string
	err := d.QueryRowContext(ctx, q, args...).Scan(&r.RunID, &r.Name, &taken, &data)
	if errors.Is(err, sql.ErrNoRows) {
		return r, ErrNotFound
	}
	if err != nil {
		return r, err
	}
	r.TakenAt, r.Data = parseTS(taken), []byte(data)
	return r, nil
}

// HostReportRuns lista as execuções com relatório daquele nome, da mais recente para a mais antiga.
func (d *DB) HostReportRuns(ctx context.Context, name string) ([]HostReport, error) {
	rows, err := d.QueryContext(ctx, `SELECT run_id, taken_at FROM host_reports WHERE name = ? ORDER BY taken_at DESC LIMIT ?`,
		name, HostReportsKept)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var out []HostReport
	for rows.Next() {
		r := HostReport{Name: name}
		var taken string
		if err := rows.Scan(&r.RunID, &taken); err != nil {
			return nil, err
		}
		r.TakenAt = parseTS(taken)
		out = append(out, r)
	}
	return out, rows.Err()
}

// ResolveMissing resolve os achados abertos de um motor que a execução completa não encontrou mais: a verificação do
// sistema refaz o quadro inteiro a cada vez (o pacote reinstalado, a correção aplicada, o repositório corrigido).
// Achados com exceção ou marcados como falso positivo não mudam.
func (d *DB) ResolveMissing(ctx context.Context, runID, engine string) (int, error) {
	now := d.now()
	n := 0
	err := d.tx(ctx, func(tx *sql.Tx) error {
		rows, err := tx.QueryContext(ctx, `SELECT id, state FROM findings WHERE engine = ? AND last_run != ?
			AND state IN ('new', 'in_review', 'confirmed')`, engine, runID)
		if err != nil {
			return err
		}
		type item struct {
			id    int64
			state string
		}
		var list []item
		for rows.Next() {
			var it item
			if err := rows.Scan(&it.id, &it.state); err != nil {
				_ = rows.Close()
				return err
			}
			list = append(list, it)
		}
		_ = rows.Close()
		if err := rows.Err(); err != nil {
			return err
		}
		for _, it := range list {
			if _, err := tx.ExecContext(ctx, `UPDATE findings SET state = ?, state_changed = ? WHERE id = ?`,
				StateResolved, ts(now), it.id); err != nil {
				return err
			}
			if err := addEvent(ctx, tx, it.id, now, "sistema", "state", it.state, StateResolved,
				"não aparece mais na verificação "+runID); err != nil {
				return err
			}
			n++
		}
		return nil
	})
	return n, err
}

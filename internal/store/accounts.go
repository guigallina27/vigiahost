package store

import (
	"context"
	"database/sql"
	"strconv"
	"strings"
)

// AccountScope identifica uma conta do servidor para atribuir achados: pelo UID dos arquivos e processos, pelo
// diretório pessoal (arquivos de outro dono dentro dele) e pelo nome (dono dos itens de persistência).
type AccountScope struct {
	UID  uint32
	Home string
	Name string
}

func likePrefix(dir string) string {
	return strings.NewReplacer(`\`, `\\`, "%", `\%`, "_", `\_`).Replace(strings.TrimSuffix(dir, "/")) + "/%"
}

// accountClause filtra achados atribuídos à conta (usado na listagem de achados com o alias f): arquivo de dono da
// conta ou dentro do diretório pessoal, processo do UID e item de persistência da conta ou no diretório pessoal.
func accountClause(a AccountScope) (string, []any) {
	uid := int64(a.UID)
	home := strings.TrimSuffix(a.Home, "/")
	locWhere, persWhere := `lo.uid = ?`, `json_extract(NULLIF(f.persistence, ''), '$.owner') IN (?, ?)`
	locArgs := []any{uid}
	persArgs := []any{a.Name, strconv.FormatInt(uid, 10)}
	if home != "" {
		locWhere += ` OR lo.path LIKE ? ESCAPE '\'`
		persWhere += ` OR json_extract(NULLIF(f.persistence, ''), '$.path') LIKE ? ESCAPE '\'`
		locArgs = append(locArgs, likePrefix(home))
		persArgs = append(persArgs, likePrefix(home))
	}
	q := `(f.id IN (SELECT fr.finding_id FROM finding_runs fr JOIN locations lo ON lo.id = fr.location_id WHERE ` +
		locWhere + `)
		OR (f.process != '' AND json_extract(NULLIF(f.process, ''), '$.uid') = ?)
		OR (f.persistence != '' AND (` + persWhere + `)))`
	args := append(append(locArgs, uid), persArgs...)
	return q, args
}

// OpenFindingRef é um achado aberto com o que serve para atribuí-lo a contas.
type OpenFindingRef struct {
	ID       int64
	Severity string
	UIDs     []uint32 // donos dos arquivos (todas as localizações) ou do processo
	Paths    []string // caminhos das localizações e do item de persistência
	Owners   []string // dono do item de persistência (nome ou UID)
}

// OpenFindingRefs devolve os achados abertos com donos e caminhos, para a agregação por conta feita em memória
// (uma passada no banco atende a lista inteira de contas).
func (d *DB) OpenFindingRefs(ctx context.Context) ([]OpenFindingRef, error) {
	byID := map[int64]*OpenFindingRef{}
	var order []int64
	get := func(id int64, sev string) *OpenFindingRef {
		r, ok := byID[id]
		if !ok {
			r = &OpenFindingRef{ID: id, Severity: sev}
			byID[id] = r
			order = append(order, id)
		}
		return r
	}
	open := `f.state IN (` + placeholders(len(OpenStates)) + `)`
	rows, err := d.QueryContext(ctx, `SELECT f.id, f.severity, lo.uid, lo.path FROM findings f
		JOIN finding_runs fr ON fr.finding_id = f.id JOIN locations lo ON lo.id = fr.location_id
		WHERE `+open+` GROUP BY f.id, lo.id`, anySlice(OpenStates)...)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var id, uid int64
		var sev, path string
		if err := rows.Scan(&id, &sev, &uid, &path); err != nil {
			_ = rows.Close()
			return nil, err
		}
		r := get(id, sev)
		r.UIDs = append(r.UIDs, uint32(uid)) //nolint:gosec // UID gravado a partir de uint32
		r.Paths = append(r.Paths, path)
	}
	if err := rows.Close(); err != nil {
		return nil, err
	}
	rows, err = d.QueryContext(ctx, `SELECT f.id, f.severity, json_extract(NULLIF(f.process, ''), '$.uid'),
		json_extract(NULLIF(f.persistence, ''), '$.owner'), json_extract(NULLIF(f.persistence, ''), '$.path') FROM findings f
		WHERE `+open+` AND (f.process != '' OR f.persistence != '')`, anySlice(OpenStates)...)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		var id int64
		var sev string
		var uid sql.NullInt64
		var owner, path sql.NullString
		if err := rows.Scan(&id, &sev, &uid, &owner, &path); err != nil {
			return nil, err
		}
		r := get(id, sev)
		if uid.Valid {
			r.UIDs = append(r.UIDs, uint32(uid.Int64)) //nolint:gosec // idem
		}
		if owner.Valid && owner.String != "" {
			r.Owners = append(r.Owners, owner.String)
		}
		if path.Valid && path.String != "" {
			r.Paths = append(r.Paths, path.String)
		}
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	out := make([]OpenFindingRef, 0, len(order))
	for _, id := range order {
		out = append(out, *byID[id])
	}
	return out, nil
}

// LatestRunsByAccount devolve, por UID, a execução mais recente que cobriu a conta.
func (d *DB) LatestRunsByAccount(ctx context.Context) (map[uint32]Run, error) {
	// Tabela derivada: as colunas da execução ficam sem prefixo e o uid de run_accounts não colide com nada.
	rows, err := d.QueryContext(ctx, `SELECT uid, `+runColumns+` FROM (SELECT ra.uid AS uid, r.* FROM run_accounts ra
		JOIN runs r ON r.id = ra.run_id
		WHERE r.created_at = (SELECT MAX(r2.created_at) FROM run_accounts ra2 JOIN runs r2 ON r2.id = ra2.run_id
			WHERE ra2.uid = ra.uid))`)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	out := map[uint32]Run{}
	for rows.Next() {
		var uid int64
		r, err := scanRun(prependScanner{rows, &uid})
		if err != nil {
			return nil, err
		}
		out[uint32(uid)] = r //nolint:gosec // idem
	}
	return out, rows.Err()
}

// prependScanner lê uma coluna extra antes das colunas da execução.
type prependScanner struct {
	rows  *sql.Rows
	first any
}

func (p prependScanner) Scan(dest ...any) error {
	return p.rows.Scan(append([]any{p.first}, dest...)...)
}

package store

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"strings"
	"time"

	"github.com/guigallina27/vigiahost/internal/report"
)

// Estados do ciclo de vida do achado (escopo, seção 10).
const (
	StateNew           = "new"
	StateInReview      = "in_review"
	StateConfirmed     = "confirmed"
	StateResolved      = "resolved"
	StateFalsePositive = "false_positive"
	StateExcepted      = "excepted"
)

// OpenStates contam como abertos.
var OpenStates = []string{StateNew, StateInReview, StateConfirmed}

// transitions lista as mudanças manuais permitidas.
var transitions = map[string][]string{
	StateNew:           {StateInReview, StateConfirmed, StateFalsePositive, StateResolved},
	StateInReview:      {StateNew, StateConfirmed, StateFalsePositive, StateResolved},
	StateConfirmed:     {StateInReview, StateResolved},
	StateResolved:      {StateNew},
	StateFalsePositive: {StateNew},
	StateExcepted:      {StateNew},
}

// CanTransition indica se a mudança manual é permitida.
func CanTransition(from, to string) bool {
	for _, t := range transitions[from] {
		if t == to {
			return true
		}
	}
	return false
}

// Fingerprint é a identidade estável do achado. Arquivos: motor + assinatura + objeto (cópias do mesmo objeto são
// um achado com várias localizações, ADR-008); indicadores de nome: pela localização; processos e persistência:
// pelo executável ou pelo item.
func Fingerprint(f report.Finding) (kind, fp string) {
	h := sha256.New()
	write := func(parts ...string) {
		for _, p := range parts {
			h.Write([]byte(p))
			h.Write([]byte{0})
		}
	}
	switch {
	case f.Process != nil:
		kind = "process"
		exe := f.Process.ExeSHA256
		if exe == "" {
			exe = f.Process.Exe
		}
		write(kind, f.Engine, f.Signature, exe)
	case f.Persistence != nil:
		kind = "persistence"
		write(kind, f.Engine, f.Signature, f.Persistence.Kind, f.Persistence.Path)
	default:
		kind = "file"
		if f.SHA256 != "" && f.Category != report.CategoryIndicator {
			write(kind, f.Engine, f.Signature, f.SHA256)
		} else if f.Location != nil {
			write(kind, f.Engine, f.Signature, f.Location.Path, f.Location.PathHex)
		} else {
			write(kind, f.Engine, f.Signature)
		}
	}
	return kind, hex.EncodeToString(h.Sum(nil))
}

// IngestResult conta o que a ingestão fez.
type IngestResult struct {
	New      int
	Seen     int
	Reopened int
	Excepted int
	// IDs dos achados novos ou reabertos, para notificar a interface.
	Changed []int64
}

// IngestFindings grava os achados lidos do findings.ndjson e avança o offset na mesma transação: um reinício no
// meio retoma do ponto certo, sem duplicar.
func (d *DB) IngestFindings(ctx context.Context, runID string, list []report.Finding, newOffset int64) (IngestResult, error) {
	var res IngestResult
	now := d.now()
	err := d.tx(ctx, func(tx *sql.Tx) error {
		excs, err := activeExceptions(ctx, tx, now)
		if err != nil {
			return err
		}
		for _, f := range list {
			if err := ingestOne(ctx, tx, runID, f, now, excs, &res); err != nil {
				return err
			}
		}
		_, err = tx.ExecContext(ctx, `UPDATE runs SET findings_offset = ?, findings_count = findings_count + ? WHERE id = ?`,
			newOffset, len(list), runID)
		return err
	})
	return res, err
}

func ingestOne(ctx context.Context, tx *sql.Tx, runID string, f report.Finding, now time.Time, excs []Exception, res *IngestResult) error {
	if !report.ValidSeverity(f.Severity) {
		f.Severity = report.SeverityMedium
	}
	if f.Category == "" {
		f.Category = report.CategorySuspicious
	}
	var sha any
	if len(f.SHA256) == 64 {
		size := int64(0)
		if f.Location != nil {
			size = f.Location.Size
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO objects (sha256, size, file_type, first_seen, last_seen)
			VALUES (?, ?, ?, ?, ?) ON CONFLICT (sha256) DO UPDATE SET last_seen = excluded.last_seen`,
			f.SHA256, size, f.FileType, ts(now), ts(now)); err != nil {
			return err
		}
		sha = f.SHA256
	}
	var locID int64
	if l := f.Location; l != nil {
		err := tx.QueryRowContext(ctx, `INSERT INTO locations (path, path_hex, sha256, dev, ino, size, mode, uid, gid,
			nlink, mtime, ctime, first_seen, last_seen) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
			ON CONFLICT (path, path_hex) DO UPDATE SET sha256 = excluded.sha256, dev = excluded.dev, ino = excluded.ino,
			size = excluded.size, mode = excluded.mode, uid = excluded.uid, gid = excluded.gid, nlink = excluded.nlink,
			mtime = excluded.mtime, ctime = excluded.ctime, last_seen = excluded.last_seen
			RETURNING id`, l.Path, l.PathHex, sha, int64(l.Dev), int64(l.Ino), l.Size, int64(l.Mode), int64(l.UID), //nolint:gosec // SQLite só tem inteiro com sinal
			int64(l.GID), int64(l.Nlink), ts(l.Mtime), ts(l.Ctime), ts(now), ts(now)).Scan(&locID) //nolint:gosec // idem
		if err != nil {
			return err
		}
	}
	kind, fp := Fingerprint(f)
	exc := matchException(excs, f)
	var excID any
	initial := StateNew
	if exc != nil {
		excID, initial = exc.ID, StateExcepted
	}
	var procJSON, persJSON string
	if f.Process != nil {
		procJSON = toJSON(f.Process)
	}
	if f.Persistence != nil {
		persJSON = toJSON(f.Persistence)
	}
	var loc any
	if locID != 0 {
		loc = locID
	}

	var id int64
	var state string
	err := tx.QueryRowContext(ctx, `SELECT id, state FROM findings WHERE fingerprint = ?`, fp).Scan(&id, &state)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		err = tx.QueryRowContext(ctx, `INSERT INTO findings (fingerprint, kind, engine, engine_version, rules_version,
			signature, source, license, author, reference, description, category, severity, sha256, location_id,
			file_type, state, exception_id, first_run, last_run, first_seen, last_seen, state_changed, evidence,
			process, persistence) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
			RETURNING id`,
			fp, kind, f.Engine, f.EngineVersion, f.RulesVersion, f.Signature, f.Source, f.License, f.Author, f.Reference,
			f.Description, string(f.Category), string(f.Severity), sha, loc, f.FileType, initial, excID, runID, runID,
			ts(now), ts(now), ts(now), toJSON(f.Evidence), procJSON, persJSON).Scan(&id)
		if err != nil {
			return err
		}
		if initial == StateExcepted {
			res.Excepted++
		} else {
			res.New++
			res.Changed = append(res.Changed, id)
		}
		if err := addEvent(ctx, tx, id, now, "sistema", "detected", "", initial, "detectado na execução "+runID); err != nil {
			return err
		}
	case err != nil:
		return err
	default:
		res.Seen++
		next := state
		note := ""
		switch {
		case state == StateResolved:
			// Detectado de novo depois de resolvido: reabre com histórico (escopo, seção 10).
			next, note = StateNew, "detectado de novo na execução "+runID+" depois de resolvido"
		case state == StateExcepted && exc == nil:
			next, note = StateNew, "exceção não vale mais (revogada ou vencida)"
		case exc != nil && (state == StateNew || state == StateInReview):
			next, note = StateExcepted, "coberto por exceção"
		}
		if _, err := tx.ExecContext(ctx, `UPDATE findings SET last_run = ?, last_seen = ?, times_seen = times_seen + 1,
			engine_version = ?, rules_version = ?, location_id = COALESCE(?, location_id), state = ?,
			exception_id = ?, state_changed = CASE WHEN state != ? THEN ? ELSE state_changed END,
			process = CASE WHEN ? != '' THEN ? ELSE process END
			WHERE id = ?`, runID, ts(now), f.EngineVersion, f.RulesVersion, loc, next, excID, next, ts(now),
			procJSON, procJSON, id); err != nil {
			return err
		}
		if next != state {
			if next == StateNew {
				res.Reopened++
				res.Changed = append(res.Changed, id)
			}
			if err := addEvent(ctx, tx, id, now, "sistema", "state", state, next, note); err != nil {
				return err
			}
		}
	}
	_, err = tx.ExecContext(ctx, `INSERT OR IGNORE INTO finding_runs (finding_id, run_id, location_id) VALUES (?, ?, ?)`,
		id, runID, locID)
	return err
}

func addEvent(ctx context.Context, tx *sql.Tx, findingID int64, at time.Time, actor, action, from, to, note string) error {
	_, err := tx.ExecContext(ctx, `INSERT INTO finding_events (finding_id, at, actor, action, from_state, to_state, note)
		VALUES (?, ?, ?, ?, ?, ?, ?)`, findingID, ts(at), actor, action, from, to, note)
	return err
}

// Finding é um achado com a localização mais recente.
type Finding struct {
	ID            int64
	Kind          string
	Engine        string
	EngineVersion string
	RulesVersion  string
	Signature     string
	Source        string
	License       string
	Author        string
	Reference     string
	Description   string
	Category      string
	Severity      string
	SHA256        string
	FileType      string
	State         string
	Assignee      string
	ExceptionID   *int64
	FirstRun      string
	LastRun       string
	FirstSeen     time.Time
	LastSeen      time.Time
	StateChanged  time.Time
	TimesSeen     int64
	Location      *report.Location
	Locations     int64 // quantas localizações o objeto tem
	Evidence      map[string]string
	Process       *report.ProcessEvidence
	Persistence   *report.PersistenceEntry
}

const findingColumns = `f.id, f.kind, f.engine, f.engine_version, f.rules_version, f.signature, f.source, f.license,
	f.author, f.reference, f.description, f.category, f.severity, COALESCE(f.sha256, ''), f.file_type, f.state,
	f.assignee, f.exception_id, f.first_run, f.last_run, f.first_seen, f.last_seen, f.state_changed, f.times_seen,
	f.evidence, f.process, f.persistence,
	l.path, l.path_hex, l.dev, l.ino, l.size, l.mode, l.uid, l.gid, l.nlink, l.mtime, l.ctime,
	(SELECT COUNT(*) FROM locations x WHERE f.sha256 IS NOT NULL AND x.sha256 = f.sha256)`

func scanFinding(s scanner) (Finding, error) {
	var f Finding
	var excID sql.NullInt64
	var first, last, changed, evidence, proc, pers string
	var path, pathHex, mtime, ctime sql.NullString
	var dev, ino, size, mode, uid, gid, nlink sql.NullInt64
	err := s.Scan(&f.ID, &f.Kind, &f.Engine, &f.EngineVersion, &f.RulesVersion, &f.Signature, &f.Source, &f.License,
		&f.Author, &f.Reference, &f.Description, &f.Category, &f.Severity, &f.SHA256, &f.FileType, &f.State,
		&f.Assignee, &excID, &f.FirstRun, &f.LastRun, &first, &last, &changed, &f.TimesSeen,
		&evidence, &proc, &pers, &path, &pathHex, &dev, &ino, &size, &mode, &uid, &gid, &nlink, &mtime, &ctime, &f.Locations)
	if errors.Is(err, sql.ErrNoRows) {
		return f, ErrNotFound
	}
	if err != nil {
		return f, err
	}
	if excID.Valid {
		v := excID.Int64
		f.ExceptionID = &v
	}
	f.FirstSeen, f.LastSeen, f.StateChanged = parseTS(first), parseTS(last), parseTS(changed)
	f.Evidence = fromJSON[map[string]string](evidence)
	if proc != "" {
		p := fromJSON[report.ProcessEvidence](proc)
		f.Process = &p
	}
	if pers != "" {
		p := fromJSON[report.PersistenceEntry](pers)
		f.Persistence = &p
	}
	if path.Valid {
		f.Location = &report.Location{
			Path: path.String, PathHex: pathHex.String, Dev: uint64(dev.Int64), Ino: uint64(ino.Int64), //nolint:gosec // gravado a partir de uint64
			Size: size.Int64, Mode: uint32(mode.Int64), UID: uint32(uid.Int64), GID: uint32(gid.Int64), //nolint:gosec // idem
			Nlink: uint64(nlink.Int64), Mtime: parseTS(mtime.String), Ctime: parseTS(ctime.String), //nolint:gosec // idem
		}
	}
	return f, nil
}

// FindingFilter seleciona achados.
type FindingFilter struct {
	States     []string
	Severities []string
	Categories []string
	Kinds      []string
	RunID      string
	Query      string // trecho do caminho, assinatura ou hash
	BeforeID   int64  // cursor
	Limit      int
}

// ListFindings lista achados do mais recente para o mais antigo (por id).
func (d *DB) ListFindings(ctx context.Context, f FindingFilter) ([]Finding, error) {
	q := `SELECT ` + findingColumns + ` FROM findings f LEFT JOIN locations l ON l.id = f.location_id WHERE 1=1`
	var args []any
	in := func(col string, vals []string) {
		if len(vals) == 0 {
			return
		}
		q += ` AND ` + col + ` IN (` + placeholders(len(vals)) + `)`
		args = append(args, anySlice(vals)...)
	}
	in("f.state", f.States)
	in("f.severity", f.Severities)
	in("f.category", f.Categories)
	in("f.kind", f.Kinds)
	if f.RunID != "" {
		q += ` AND f.id IN (SELECT finding_id FROM finding_runs WHERE run_id = ?)`
		args = append(args, f.RunID)
	}
	if s := strings.TrimSpace(f.Query); s != "" {
		like := "%" + strings.NewReplacer(`\`, `\\`, "%", `\%`, "_", `\_`).Replace(s) + "%"
		// O caminho pode ser de qualquer cópia do objeto, não só da localização mais recente.
		q += ` AND (l.path LIKE ? ESCAPE '\' OR f.signature LIKE ? ESCAPE '\' OR f.sha256 = ?
			OR f.sha256 IN (SELECT sha256 FROM locations WHERE sha256 IS NOT NULL AND path LIKE ? ESCAPE '\'))`
		args = append(args, like, like, strings.ToLower(s), like)
	}
	if f.BeforeID > 0 {
		q += ` AND f.id < ?`
		args = append(args, f.BeforeID)
	}
	if f.Limit <= 0 || f.Limit > 500 {
		f.Limit = 50
	}
	q += ` ORDER BY f.id DESC LIMIT ?`
	args = append(args, f.Limit)
	rows, err := d.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var out []Finding
	for rows.Next() {
		fd, err := scanFinding(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, fd)
	}
	return out, rows.Err()
}

// GetFinding devolve um achado.
func (d *DB) GetFinding(ctx context.Context, id int64) (Finding, error) {
	return scanFinding(d.QueryRowContext(ctx, `SELECT `+findingColumns+` FROM findings f
		LEFT JOIN locations l ON l.id = f.location_id WHERE f.id = ?`, id))
}

// FindingLocations devolve todas as localizações conhecidas do objeto do achado.
func (d *DB) FindingLocations(ctx context.Context, sha string) ([]report.Location, error) {
	rows, err := d.QueryContext(ctx, `SELECT path, path_hex, dev, ino, size, mode, uid, gid, nlink, mtime, ctime
		FROM locations WHERE sha256 = ? ORDER BY last_seen DESC LIMIT 500`, sha)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var out []report.Location
	for rows.Next() {
		var l report.Location
		var dev, ino, mode, uid, gid, nlink int64
		var mtime, ctime string
		if err := rows.Scan(&l.Path, &l.PathHex, &dev, &ino, &l.Size, &mode, &uid, &gid, &nlink, &mtime, &ctime); err != nil {
			return nil, err
		}
		l.Dev, l.Ino, l.Mode, l.UID, l.GID, l.Nlink = uint64(dev), uint64(ino), uint32(mode), uint32(uid), uint32(gid), uint64(nlink) //nolint:gosec // gravados a partir de sem sinal
		l.Mtime, l.Ctime = parseTS(mtime), parseTS(ctime)
		out = append(out, l)
	}
	return out, rows.Err()
}

// FindingEvent é uma entrada do histórico.
type FindingEvent struct {
	At     time.Time
	Actor  string
	Action string
	From   string
	To     string
	Note   string
}

// FindingEvents devolve o histórico do achado.
func (d *DB) FindingEvents(ctx context.Context, id int64) ([]FindingEvent, error) {
	rows, err := d.QueryContext(ctx, `SELECT at, actor, action, from_state, to_state, note FROM finding_events
		WHERE finding_id = ? ORDER BY at, id`, id)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var out []FindingEvent
	for rows.Next() {
		var e FindingEvent
		var at string
		if err := rows.Scan(&at, &e.Actor, &e.Action, &e.From, &e.To, &e.Note); err != nil {
			return nil, err
		}
		e.At = parseTS(at)
		out = append(out, e)
	}
	return out, rows.Err()
}

// TransitionFinding muda o estado manualmente, conferindo a transição e registrando quem e por quê.
func (d *DB) TransitionFinding(ctx context.Context, id int64, to, actor, note string) (Finding, error) {
	now := d.now()
	err := d.tx(ctx, func(tx *sql.Tx) error {
		var state string
		if err := tx.QueryRowContext(ctx, `SELECT state FROM findings WHERE id = ?`, id).Scan(&state); err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return ErrNotFound
			}
			return err
		}
		if !CanTransition(state, to) {
			return ErrConflict
		}
		assignee := ""
		if to == StateInReview {
			assignee = actor
		}
		if _, err := tx.ExecContext(ctx, `UPDATE findings SET state = ?, state_changed = ?,
			assignee = CASE WHEN ? != '' THEN ? ELSE assignee END,
			exception_id = CASE WHEN ? = 'new' THEN NULL ELSE exception_id END WHERE id = ?`,
			to, ts(now), assignee, assignee, to, id); err != nil {
			return err
		}
		return addEvent(ctx, tx, id, now, actor, "state", state, to, note)
	})
	if err != nil {
		return Finding{}, err
	}
	return d.GetFinding(ctx, id)
}

// SeverityCount conta achados abertos por severidade.
type SeverityCount struct {
	Severity string
	Count    int64
}

// OpenFindingsBySeverity conta os achados abertos (novo, em análise, confirmado), sem os de teste.
func (d *DB) OpenFindingsBySeverity(ctx context.Context) (map[string]int64, error) {
	rows, err := d.QueryContext(ctx, `SELECT severity, COUNT(*) FROM findings
		WHERE state IN ('new', 'in_review', 'confirmed') AND category != 'test' GROUP BY severity`)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	out := map[string]int64{}
	for rows.Next() {
		var s string
		var n int64
		if err := rows.Scan(&s, &n); err != nil {
			return nil, err
		}
		out[s] = n
	}
	return out, rows.Err()
}

// AllowedTransitions lista os estados para onde o achado pode ir manualmente.
func AllowedTransitions(from string) []string {
	return append([]string(nil), transitions[from]...)
}

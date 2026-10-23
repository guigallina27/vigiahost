package store

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"strings"
	"time"
)

// Perfis de acesso do painel (ADR-016).
const (
	RoleAdmin    = "admin"
	RoleOperator = "operator"
	RoleReader   = "reader"
	RoleAuditor  = "auditor"
)

// ValidRole confere o perfil.
func ValidRole(r string) bool {
	switch r {
	case RoleAdmin, RoleOperator, RoleReader, RoleAuditor:
		return true
	}
	return false
}

// User é um usuário do painel (não confundir com conta do servidor; glossário).
type User struct {
	ID                int64
	Username          string
	DisplayName       string
	Role              string
	PasswordHash      string
	TOTPSecret        string
	TOTPPending       string
	TOTPLastStep      int64
	Disabled          bool
	CreatedAt         time.Time
	UpdatedAt         time.Time
	PasswordChangedAt time.Time
	LastLoginAt       *time.Time
}

// MFAEnabled indica segundo fator configurado.
func (u User) MFAEnabled() bool { return u.TOTPSecret != "" }

const userColumns = `id, username, display_name, role, password_hash, totp_secret, totp_pending, totp_last_step,
	disabled, created_at, updated_at, password_changed_at, last_login_at`

func scanUser(s scanner) (User, error) {
	var u User
	var disabled int
	var created, updated, pwChanged string
	var last sql.NullString
	err := s.Scan(&u.ID, &u.Username, &u.DisplayName, &u.Role, &u.PasswordHash, &u.TOTPSecret, &u.TOTPPending,
		&u.TOTPLastStep, &disabled, &created, &updated, &pwChanged, &last)
	if errors.Is(err, sql.ErrNoRows) {
		return u, ErrNotFound
	}
	if err != nil {
		return u, err
	}
	u.Disabled = disabled == 1
	u.CreatedAt, u.UpdatedAt, u.PasswordChangedAt = parseTS(created), parseTS(updated), parseTS(pwChanged)
	u.LastLoginAt = parseNullTS(last)
	return u, nil
}

// CountUsers conta os usuários (zero = primeiro acesso pendente).
func (d *DB) CountUsers(ctx context.Context) (int, error) {
	var n int
	err := d.QueryRowContext(ctx, `SELECT COUNT(*) FROM users`).Scan(&n)
	return n, err
}

// CountActiveAdmins conta administradores habilitados (o último não pode ser removido nem rebaixado).
func (d *DB) CountActiveAdmins(ctx context.Context) (int, error) {
	var n int
	err := d.QueryRowContext(ctx, `SELECT COUNT(*) FROM users WHERE role = 'admin' AND disabled = 0`).Scan(&n)
	return n, err
}

// CreateUser grava o usuário; nome repetido devolve ErrDuplicate.
func (d *DB) CreateUser(ctx context.Context, u *User) error {
	now := d.now()
	u.CreatedAt, u.UpdatedAt, u.PasswordChangedAt = now, now, now
	err := d.QueryRowContext(ctx, `INSERT INTO users (username, display_name, role, password_hash, created_at,
		updated_at, password_changed_at) VALUES (?, ?, ?, ?, ?, ?, ?) RETURNING id`,
		u.Username, u.DisplayName, u.Role, u.PasswordHash, ts(now), ts(now), ts(now)).Scan(&u.ID)
	if err != nil && strings.Contains(err.Error(), "UNIQUE") {
		return ErrDuplicate
	}
	return err
}

// GetUser busca por id.
func (d *DB) GetUser(ctx context.Context, id int64) (User, error) {
	return scanUser(d.QueryRowContext(ctx, `SELECT `+userColumns+` FROM users WHERE id = ?`, id))
}

// GetUserByName busca pelo nome (sem diferenciar maiúsculas).
func (d *DB) GetUserByName(ctx context.Context, name string) (User, error) {
	return scanUser(d.QueryRowContext(ctx, `SELECT `+userColumns+` FROM users WHERE username = ?`, name))
}

// ListUsers devolve todos os usuários.
func (d *DB) ListUsers(ctx context.Context) ([]User, error) {
	rows, err := d.QueryContext(ctx, `SELECT `+userColumns+` FROM users ORDER BY username`)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var out []User
	for rows.Next() {
		u, err := scanUser(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, u)
	}
	return out, rows.Err()
}

// UpdateUser grava nome de exibição, perfil e bloqueio.
func (d *DB) UpdateUser(ctx context.Context, u User) error {
	res, err := d.ExecContext(ctx, `UPDATE users SET display_name = ?, role = ?, disabled = ?, updated_at = ? WHERE id = ?`,
		u.DisplayName, u.Role, boolInt(u.Disabled), ts(d.now()), u.ID)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

// DeleteUser remove o usuário (sessões, códigos e tokens vão junto).
func (d *DB) DeleteUser(ctx context.Context, id int64) error {
	res, err := d.ExecContext(ctx, `DELETE FROM users WHERE id = ?`, id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

// SetPassword troca a senha e encerra as sessões do usuário, exceto keepSession (hash), se informada.
func (d *DB) SetPassword(ctx context.Context, id int64, hash, keepSession string) error {
	now := d.now()
	return d.tx(ctx, func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx, `UPDATE users SET password_hash = ?, password_changed_at = ?, updated_at = ?
			WHERE id = ?`, hash, ts(now), ts(now), id); err != nil {
			return err
		}
		_, err := tx.ExecContext(ctx, `DELETE FROM sessions WHERE user_id = ? AND id_hash != ?`, id, keepSession)
		return err
	})
}

// SetTOTPPending guarda o segredo em configuração (ainda não confirmado por um código).
func (d *DB) SetTOTPPending(ctx context.Context, id int64, secret string) error {
	_, err := d.ExecContext(ctx, `UPDATE users SET totp_pending = ?, updated_at = ? WHERE id = ?`, secret, ts(d.now()), id)
	return err
}

// EnableTOTP ativa o segredo pendente, grava os códigos de recuperação (hashes) e encerra as outras sessões.
func (d *DB) EnableTOTP(ctx context.Context, id int64, step int64, codeHashes []string, keepSession string) error {
	now := d.now()
	return d.tx(ctx, func(tx *sql.Tx) error {
		res, err := tx.ExecContext(ctx, `UPDATE users SET totp_secret = totp_pending, totp_pending = '', totp_last_step = ?,
			updated_at = ? WHERE id = ? AND totp_pending != ''`, step, ts(now), id)
		if err != nil {
			return err
		}
		if n, _ := res.RowsAffected(); n == 0 {
			return ErrConflict
		}
		if _, err := tx.ExecContext(ctx, `DELETE FROM recovery_codes WHERE user_id = ?`, id); err != nil {
			return err
		}
		for _, h := range codeHashes {
			if _, err := tx.ExecContext(ctx, `INSERT INTO recovery_codes (user_id, code_hash) VALUES (?, ?)`, id, h); err != nil {
				return err
			}
		}
		_, err = tx.ExecContext(ctx, `DELETE FROM sessions WHERE user_id = ? AND id_hash != ?`, id, keepSession)
		return err
	})
}

// ResetMFA apaga o segundo fator e os códigos (o usuário configura de novo no próximo login) e encerra as sessões.
func (d *DB) ResetMFA(ctx context.Context, id int64) error {
	return d.tx(ctx, func(tx *sql.Tx) error {
		res, err := tx.ExecContext(ctx, `UPDATE users SET totp_secret = '', totp_pending = '', totp_last_step = 0,
			updated_at = ? WHERE id = ?`, ts(d.now()), id)
		if err != nil {
			return err
		}
		if n, _ := res.RowsAffected(); n == 0 {
			return ErrNotFound
		}
		if _, err := tx.ExecContext(ctx, `DELETE FROM recovery_codes WHERE user_id = ?`, id); err != nil {
			return err
		}
		_, err = tx.ExecContext(ctx, `DELETE FROM sessions WHERE user_id = ?`, id)
		return err
	})
}

// UseTOTPStep registra o passo aceito; falha (ErrConflict) se ele não for posterior ao último, o que impede reuso.
func (d *DB) UseTOTPStep(ctx context.Context, id, step int64) error {
	res, err := d.ExecContext(ctx, `UPDATE users SET totp_last_step = ? WHERE id = ? AND totp_last_step < ?`, step, id, step)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrConflict
	}
	return nil
}

// UseRecoveryCode consome um código de recuperação pelo hash.
func (d *DB) UseRecoveryCode(ctx context.Context, userID int64, codeHash string) error {
	res, err := d.ExecContext(ctx, `UPDATE recovery_codes SET used_at = ? WHERE user_id = ? AND code_hash = ? AND used_at IS NULL`,
		ts(d.now()), userID, codeHash)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

// RecoveryCodesLeft conta os códigos não usados.
func (d *DB) RecoveryCodesLeft(ctx context.Context, userID int64) (int, error) {
	var n int
	err := d.QueryRowContext(ctx, `SELECT COUNT(*) FROM recovery_codes WHERE user_id = ? AND used_at IS NULL`, userID).Scan(&n)
	return n, err
}

// TouchLogin registra o último login.
func (d *DB) TouchLogin(ctx context.Context, id int64) error {
	_, err := d.ExecContext(ctx, `UPDATE users SET last_login_at = ? WHERE id = ?`, ts(d.now()), id)
	return err
}

// Session é uma sessão do painel.
type Session struct {
	IDHash    string
	UserID    int64
	Stage     string
	CreatedAt time.Time
	LastSeen  time.Time
	ExpiresAt time.Time
	ReauthAt  *time.Time
	IP        string
	UserAgent string
}

// Etapas da sessão.
const (
	StagePassword = "password"
	StageMFASetup = "mfa_setup"
	StageFull     = "full"
)

// HashToken é o SHA-256 em hexadecimal usado para guardar identificadores e tokens.
func HashToken(tok string) string {
	h := sha256.Sum256([]byte(tok))
	return hex.EncodeToString(h[:])
}

// CreateSession grava a sessão.
func (d *DB) CreateSession(ctx context.Context, s Session) error {
	_, err := d.ExecContext(ctx, `INSERT INTO sessions (id_hash, user_id, stage, created_at, last_seen, expires_at,
		reauth_at, ip, user_agent) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`, s.IDHash, s.UserID, s.Stage, ts(s.CreatedAt),
		ts(s.LastSeen), ts(s.ExpiresAt), nullTS(s.ReauthAt), s.IP, s.UserAgent)
	return err
}

// GetSession busca a sessão pelo hash.
func (d *DB) GetSession(ctx context.Context, idHash string) (Session, error) {
	var s Session
	var created, last, exp string
	var reauth sql.NullString
	err := d.QueryRowContext(ctx, `SELECT id_hash, user_id, stage, created_at, last_seen, expires_at, reauth_at, ip,
		user_agent FROM sessions WHERE id_hash = ?`, idHash).Scan(&s.IDHash, &s.UserID, &s.Stage, &created, &last, &exp,
		&reauth, &s.IP, &s.UserAgent)
	if errors.Is(err, sql.ErrNoRows) {
		return s, ErrNotFound
	}
	s.CreatedAt, s.LastSeen, s.ExpiresAt, s.ReauthAt = parseTS(created), parseTS(last), parseTS(exp), parseNullTS(reauth)
	return s, err
}

// TouchSession renova a atividade.
func (d *DB) TouchSession(ctx context.Context, idHash string) error {
	_, err := d.ExecContext(ctx, `UPDATE sessions SET last_seen = ? WHERE id_hash = ?`, ts(d.now()), idHash)
	return err
}

// RotateSession troca o identificador (login, segundo fator, elevação), mudando a etapa e a reautenticação.
func (d *DB) RotateSession(ctx context.Context, oldHash string, s Session) error {
	return d.tx(ctx, func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx, `DELETE FROM sessions WHERE id_hash = ?`, oldHash); err != nil {
			return err
		}
		_, err := tx.ExecContext(ctx, `INSERT INTO sessions (id_hash, user_id, stage, created_at, last_seen, expires_at,
			reauth_at, ip, user_agent) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`, s.IDHash, s.UserID, s.Stage, ts(s.CreatedAt),
			ts(s.LastSeen), ts(s.ExpiresAt), nullTS(s.ReauthAt), s.IP, s.UserAgent)
		return err
	})
}

// DeleteSession encerra a sessão.
func (d *DB) DeleteSession(ctx context.Context, idHash string) error {
	_, err := d.ExecContext(ctx, `DELETE FROM sessions WHERE id_hash = ?`, idHash)
	return err
}

// DeleteUserSessions encerra todas as sessões do usuário.
func (d *DB) DeleteUserSessions(ctx context.Context, userID int64) error {
	_, err := d.ExecContext(ctx, `DELETE FROM sessions WHERE user_id = ?`, userID)
	return err
}

// PurgeExpiredSessions remove sessões vencidas ou ociosas além de idle.
func (d *DB) PurgeExpiredSessions(ctx context.Context, idle time.Duration) error {
	now := d.now()
	_, err := d.ExecContext(ctx, `DELETE FROM sessions WHERE expires_at <= ? OR last_seen <= ?`, ts(now), ts(now.Add(-idle)))
	return err
}

// CreateOneTimeToken grava um token de uso único (primeiro acesso ou recuperação). Um novo token do mesmo tipo e
// usuário invalida os anteriores.
func (d *DB) CreateOneTimeToken(ctx context.Context, tokenHash, kind string, userID *int64, ttl time.Duration) error {
	now := d.now()
	return d.tx(ctx, func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx, `DELETE FROM one_time_tokens WHERE kind = ? AND COALESCE(user_id, 0) = ?`,
			kind, derefInt(userID)); err != nil {
			return err
		}
		_, err := tx.ExecContext(ctx, `INSERT INTO one_time_tokens (token_hash, kind, user_id, created_at, expires_at)
			VALUES (?, ?, ?, ?, ?)`, tokenHash, kind, userID, ts(now), ts(now.Add(ttl)))
		return err
	})
}

func derefInt(p *int64) int64 {
	if p == nil {
		return 0
	}
	return *p
}

// ConsumeOneTimeToken marca o token como usado e devolve o usuário associado (nil no primeiro acesso).
func (d *DB) ConsumeOneTimeToken(ctx context.Context, tx *sql.Tx, tokenHash, kind string) (*int64, error) {
	now := d.now()
	var uid sql.NullInt64
	err := tx.QueryRowContext(ctx, `UPDATE one_time_tokens SET used_at = ? WHERE token_hash = ? AND kind = ?
		AND used_at IS NULL AND expires_at > ? RETURNING user_id`, ts(now), tokenHash, kind, ts(now)).Scan(&uid)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	if uid.Valid {
		v := uid.Int64
		return &v, nil
	}
	return nil, nil
}

// HasValidFirstAccessToken indica token de primeiro acesso ainda utilizável.
func (d *DB) HasValidFirstAccessToken(ctx context.Context) (bool, error) {
	var n int
	err := d.QueryRowContext(ctx, `SELECT COUNT(*) FROM one_time_tokens WHERE kind = 'first_access' AND used_at IS NULL
		AND expires_at > ?`, ts(d.now())).Scan(&n)
	return n > 0, err
}

// CreateFirstAdmin consome o token de primeiro acesso e cria o administrador, na mesma transação: dois pedidos
// simultâneos com o mesmo token não criam dois usuários.
func (d *DB) CreateFirstAdmin(ctx context.Context, tokenHash string, u *User) error {
	now := d.now()
	return d.tx(ctx, func(tx *sql.Tx) error {
		var n int
		if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM users`).Scan(&n); err != nil {
			return err
		}
		if n > 0 {
			return ErrConflict
		}
		if _, err := d.ConsumeOneTimeToken(ctx, tx, tokenHash, "first_access"); err != nil {
			return err
		}
		u.Role, u.CreatedAt, u.UpdatedAt, u.PasswordChangedAt = RoleAdmin, now, now, now
		return tx.QueryRowContext(ctx, `INSERT INTO users (username, display_name, role, password_hash, created_at,
			updated_at, password_changed_at) VALUES (?, ?, ?, ?, ?, ?, ?) RETURNING id`,
			u.Username, u.DisplayName, u.Role, u.PasswordHash, ts(now), ts(now), ts(now)).Scan(&u.ID)
	})
}

// ResetWithToken consome o token de recuperação, troca a senha, apaga o segundo fator e encerra as sessões.
func (d *DB) ResetWithToken(ctx context.Context, tokenHash, passwordHash string) (int64, error) {
	now := d.now()
	var uid int64
	err := d.tx(ctx, func(tx *sql.Tx) error {
		p, err := d.ConsumeOneTimeToken(ctx, tx, tokenHash, "reset")
		if err != nil {
			return err
		}
		if p == nil {
			return ErrNotFound
		}
		uid = *p
		if _, err := tx.ExecContext(ctx, `UPDATE users SET password_hash = ?, password_changed_at = ?, updated_at = ?,
			totp_secret = '', totp_pending = '', totp_last_step = 0, disabled = 0 WHERE id = ?`,
			passwordHash, ts(now), ts(now), uid); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `DELETE FROM recovery_codes WHERE user_id = ?`, uid); err != nil {
			return err
		}
		_, err = tx.ExecContext(ctx, `DELETE FROM sessions WHERE user_id = ?`, uid)
		return err
	})
	return uid, err
}

// Throttle é o estado de falhas de login de uma chave (usuário ou IP).
type Throttle struct {
	Failures    int
	LastFailure time.Time
	LockedUntil *time.Time
}

// GetThrottle lê o estado; chave sem registro devolve zero.
func (d *DB) GetThrottle(ctx context.Context, key string) (Throttle, error) {
	var t Throttle
	var last string
	var locked sql.NullString
	err := d.QueryRowContext(ctx, `SELECT failures, last_failure, locked_until FROM login_throttle WHERE key = ?`, key).
		Scan(&t.Failures, &last, &locked)
	if errors.Is(err, sql.ErrNoRows) {
		return t, nil
	}
	t.LastFailure, t.LockedUntil = parseTS(last), parseNullTS(locked)
	return t, err
}

// RecordFailure soma uma falha; a contagem recomeça depois de window sem falhas, e lockAt falhas bloqueiam por lockFor.
func (d *DB) RecordFailure(ctx context.Context, key string, window time.Duration, lockAt int, lockFor time.Duration) (Throttle, error) {
	now := d.now()
	t, err := d.GetThrottle(ctx, key)
	if err != nil {
		return t, err
	}
	if t.Failures > 0 && now.Sub(t.LastFailure) > window {
		t.Failures = 0
	}
	t.Failures++
	t.LastFailure = now
	if t.Failures >= lockAt {
		until := now.Add(lockFor)
		t.LockedUntil = &until
	}
	_, err = d.ExecContext(ctx, `INSERT INTO login_throttle (key, failures, last_failure, locked_until) VALUES (?, ?, ?, ?)
		ON CONFLICT (key) DO UPDATE SET failures = excluded.failures, last_failure = excluded.last_failure,
		locked_until = excluded.locked_until`, key, t.Failures, ts(now), nullTS(t.LockedUntil))
	return t, err
}

// ClearThrottle zera a chave (login bem-sucedido).
func (d *DB) ClearThrottle(ctx context.Context, key string) error {
	_, err := d.ExecContext(ctx, `DELETE FROM login_throttle WHERE key = ?`, key)
	return err
}

// APIToken é um token de automação (nunca serve para a interface).
type APIToken struct {
	ID        int64
	Name      string
	UserID    int64
	Username  string
	Role      string
	Prefix    string
	CreatedAt time.Time
	ExpiresAt time.Time
	LastUsed  *time.Time
	RevokedAt *time.Time
}

// CreateAPIToken grava o token pelo hash.
func (d *DB) CreateAPIToken(ctx context.Context, t *APIToken, tokenHash string) error {
	t.CreatedAt = d.now()
	return d.QueryRowContext(ctx, `INSERT INTO api_tokens (name, user_id, role, token_hash, prefix, created_at, expires_at)
		VALUES (?, ?, ?, ?, ?, ?, ?) RETURNING id`, t.Name, t.UserID, t.Role, tokenHash, t.Prefix, ts(t.CreatedAt),
		ts(t.ExpiresAt)).Scan(&t.ID)
}

//nolint:gosec // G101: lista de colunas, não é credencial
const apiTokenColumns = `t.id, t.name, t.user_id, u.username, t.role, t.prefix, t.created_at, t.expires_at, t.last_used, t.revoked_at`

func scanAPIToken(s scanner) (APIToken, error) {
	var t APIToken
	var created, exp string
	var used, revoked sql.NullString
	err := s.Scan(&t.ID, &t.Name, &t.UserID, &t.Username, &t.Role, &t.Prefix, &created, &exp, &used, &revoked)
	if errors.Is(err, sql.ErrNoRows) {
		return t, ErrNotFound
	}
	t.CreatedAt, t.ExpiresAt, t.LastUsed, t.RevokedAt = parseTS(created), parseTS(exp), parseNullTS(used), parseNullTS(revoked)
	return t, err
}

// LookupAPIToken devolve o token válido (não revogado, não vencido, usuário habilitado) e registra o uso.
func (d *DB) LookupAPIToken(ctx context.Context, tokenHash string) (APIToken, error) {
	now := d.now()
	t, err := scanAPIToken(d.QueryRowContext(ctx, `SELECT `+apiTokenColumns+` FROM api_tokens t JOIN users u ON u.id = t.user_id
		WHERE t.token_hash = ? AND t.revoked_at IS NULL AND t.expires_at > ? AND u.disabled = 0`, tokenHash, ts(now)))
	if err != nil {
		return t, err
	}
	_, _ = d.ExecContext(ctx, `UPDATE api_tokens SET last_used = ? WHERE id = ?`, ts(now), t.ID)
	return t, nil
}

// ListAPITokens devolve os tokens (todos, ou só os do usuário quando userID > 0).
func (d *DB) ListAPITokens(ctx context.Context, userID int64) ([]APIToken, error) {
	q := `SELECT ` + apiTokenColumns + ` FROM api_tokens t JOIN users u ON u.id = t.user_id`
	var args []any
	if userID > 0 {
		q += ` WHERE t.user_id = ?`
		args = append(args, userID)
	}
	rows, err := d.QueryContext(ctx, q+` ORDER BY t.id DESC`, args...)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var out []APIToken
	for rows.Next() {
		t, err := scanAPIToken(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

// RevokeAPIToken revoga o token.
func (d *DB) RevokeAPIToken(ctx context.Context, id int64) error {
	res, err := d.ExecContext(ctx, `UPDATE api_tokens SET revoked_at = ? WHERE id = ? AND revoked_at IS NULL`, ts(d.now()), id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

// AuditEntry é uma linha da auditoria.
type AuditEntry struct {
	ID       int64
	At       time.Time
	Actor    string
	Action   string
	Target   string
	Detail   string
	IP       string
	PrevHash string
	Hash     string
}

func auditHash(prev string, e AuditEntry) string {
	h := sha256.New()
	for _, p := range []string{prev, ts(e.At), e.Actor, e.Action, e.Target, e.Detail, e.IP} {
		h.Write([]byte(p))
		h.Write([]byte{0})
	}
	return hex.EncodeToString(h.Sum(nil))
}

// Audit grava uma entrada encadeada à anterior.
func (d *DB) Audit(ctx context.Context, actor, action, target, detail, ip string) error {
	return d.tx(ctx, func(tx *sql.Tx) error {
		var prev string
		err := tx.QueryRowContext(ctx, `SELECT hash FROM audit_log ORDER BY id DESC LIMIT 1`).Scan(&prev)
		if err != nil && !errors.Is(err, sql.ErrNoRows) {
			return err
		}
		e := AuditEntry{At: d.now(), Actor: actor, Action: action, Target: target, Detail: detail, IP: ip}
		_, err = tx.ExecContext(ctx, `INSERT INTO audit_log (at, actor, action, target, detail, ip, prev_hash, hash)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?)`, ts(e.At), actor, action, target, detail, ip, prev, auditHash(prev, e))
		return err
	})
}

// ListAudit devolve entradas da mais nova para a mais antiga.
func (d *DB) ListAudit(ctx context.Context, beforeID int64, limit int) ([]AuditEntry, error) {
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	q := `SELECT id, at, actor, action, target, detail, ip, prev_hash, hash FROM audit_log`
	var args []any
	if beforeID > 0 {
		q += ` WHERE id < ?`
		args = append(args, beforeID)
	}
	rows, err := d.QueryContext(ctx, q+` ORDER BY id DESC LIMIT ?`, append(args, limit)...)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var out []AuditEntry
	for rows.Next() {
		var e AuditEntry
		var at string
		if err := rows.Scan(&e.ID, &at, &e.Actor, &e.Action, &e.Target, &e.Detail, &e.IP, &e.PrevHash, &e.Hash); err != nil {
			return nil, err
		}
		e.At = parseTS(at)
		out = append(out, e)
	}
	return out, rows.Err()
}

// VerifyAudit percorre a cadeia inteira e devolve o id da primeira entrada adulterada (0 se íntegra).
func (d *DB) VerifyAudit(ctx context.Context) (int64, error) {
	rows, err := d.QueryContext(ctx, `SELECT id, at, actor, action, target, detail, ip, prev_hash, hash FROM audit_log ORDER BY id`)
	if err != nil {
		return 0, err
	}
	defer func() { _ = rows.Close() }()
	prev := ""
	for rows.Next() {
		var e AuditEntry
		var at string
		if err := rows.Scan(&e.ID, &at, &e.Actor, &e.Action, &e.Target, &e.Detail, &e.IP, &e.PrevHash, &e.Hash); err != nil {
			return 0, err
		}
		e.At = parseTS(at)
		if e.PrevHash != prev || auditHash(prev, e) != e.Hash {
			return e.ID, nil
		}
		prev = e.Hash
	}
	return 0, rows.Err()
}

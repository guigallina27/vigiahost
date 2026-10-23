-- Usuários do painel, sessões, segundo fator, tokens de uso único (primeiro acesso e recuperação), tokens de API,
-- controle de tentativas de login e auditoria encadeada por hash (ADR-016; escopo, seção 13).

-- +goose Up
CREATE TABLE users (
    id                  INTEGER PRIMARY KEY,
    username            TEXT NOT NULL UNIQUE COLLATE NOCASE,
    display_name        TEXT NOT NULL DEFAULT '',
    role                TEXT NOT NULL CHECK (role IN ('admin', 'operator', 'reader', 'auditor')),
    password_hash       TEXT NOT NULL,
    -- Segredo TOTP em base32; vazio enquanto o segundo fator não foi configurado.
    totp_secret         TEXT NOT NULL DEFAULT '',
    totp_pending        TEXT NOT NULL DEFAULT '',
    -- Último passo de 30 s aceito: o mesmo código não vale duas vezes.
    totp_last_step      INTEGER NOT NULL DEFAULT 0,
    disabled            INTEGER NOT NULL DEFAULT 0,
    created_at          TEXT NOT NULL,
    updated_at          TEXT NOT NULL,
    password_changed_at TEXT NOT NULL,
    last_login_at       TEXT
) STRICT;

CREATE TABLE recovery_codes (
    id        INTEGER PRIMARY KEY,
    user_id   INTEGER NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    code_hash TEXT NOT NULL,
    used_at   TEXT
) STRICT;

CREATE INDEX recovery_codes_user ON recovery_codes (user_id);

CREATE TABLE sessions (
    -- SHA-256 do identificador: o valor do cookie nunca fica no banco.
    id_hash     TEXT PRIMARY KEY,
    user_id     INTEGER NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    -- password: falta o segundo fator; mfa_setup: falta configurar o segundo fator; full: sessão completa.
    stage       TEXT NOT NULL CHECK (stage IN ('password', 'mfa_setup', 'full')),
    created_at  TEXT NOT NULL,
    last_seen   TEXT NOT NULL,
    expires_at  TEXT NOT NULL,
    reauth_at   TEXT,
    ip          TEXT NOT NULL DEFAULT '',
    user_agent  TEXT NOT NULL DEFAULT ''
) STRICT;

CREATE INDEX sessions_user ON sessions (user_id);

-- Tokens de uso único: primeiro acesso (sem usuário) e recuperação gerada pelo root (com usuário).
CREATE TABLE one_time_tokens (
    token_hash  TEXT PRIMARY KEY,
    kind        TEXT NOT NULL CHECK (kind IN ('first_access', 'reset')),
    user_id     INTEGER REFERENCES users (id) ON DELETE CASCADE,
    created_at  TEXT NOT NULL,
    expires_at  TEXT NOT NULL,
    used_at     TEXT
) STRICT;

CREATE TABLE api_tokens (
    id          INTEGER PRIMARY KEY,
    name        TEXT NOT NULL,
    user_id     INTEGER NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    role        TEXT NOT NULL CHECK (role IN ('admin', 'operator', 'reader', 'auditor')),
    token_hash  TEXT NOT NULL UNIQUE,
    prefix      TEXT NOT NULL,
    created_at  TEXT NOT NULL,
    expires_at  TEXT NOT NULL,
    last_used   TEXT,
    revoked_at  TEXT
) STRICT;

-- Falhas de login por usuário ("user:nome") e por IP ("ip:endereço").
CREATE TABLE login_throttle (
    key          TEXT PRIMARY KEY,
    failures     INTEGER NOT NULL DEFAULT 0,
    last_failure TEXT NOT NULL,
    locked_until TEXT
) STRICT;

-- Auditoria somente de inserção, encadeada: hash = SHA-256(hash anterior + campos). Evidencia adulteração ingênua.
CREATE TABLE audit_log (
    id         INTEGER PRIMARY KEY,
    at         TEXT NOT NULL,
    actor      TEXT NOT NULL,
    action     TEXT NOT NULL,
    target     TEXT NOT NULL DEFAULT '',
    detail     TEXT NOT NULL DEFAULT '',
    ip         TEXT NOT NULL DEFAULT '',
    prev_hash  TEXT NOT NULL,
    hash       TEXT NOT NULL
) STRICT;

-- +goose StatementBegin
CREATE TRIGGER audit_log_no_update BEFORE UPDATE ON audit_log
BEGIN
    SELECT RAISE(ABORT, 'auditoria é somente de inserção');
END;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE TRIGGER audit_log_no_delete BEFORE DELETE ON audit_log
BEGIN
    SELECT RAISE(ABORT, 'auditoria é somente de inserção');
END;
-- +goose StatementEnd

-- +goose Down
DROP TRIGGER audit_log_no_delete;
DROP TRIGGER audit_log_no_update;
DROP TABLE audit_log;
DROP TABLE login_throttle;
DROP TABLE api_tokens;
DROP TABLE one_time_tokens;
DROP TABLE sessions;
DROP TABLE recovery_codes;
DROP TABLE users;

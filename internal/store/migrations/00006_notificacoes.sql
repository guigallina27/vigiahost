-- Notificações (E1.12): canais (e-mail e webhook), regras de envio por evento, caixa de saída persistente com novas
-- tentativas e a memória da deduplicação. Segredos dos canais ficam cifrados (ADR-020); a chave não fica no banco.

-- +goose Up
CREATE TABLE notification_channels (
    id              INTEGER PRIMARY KEY,
    name            TEXT NOT NULL UNIQUE COLLATE NOCASE,
    kind            TEXT NOT NULL CHECK (kind IN ('email', 'webhook')),
    enabled         INTEGER NOT NULL DEFAULT 1,
    -- Configuração sem segredos (JSON): servidor SMTP, remetente e destinatários, ou endereço do webhook.
    config          TEXT NOT NULL DEFAULT '{}',
    -- Senha SMTP ou segredo do webhook cifrado com AES-256-GCM; NULL quando não há.
    secret          BLOB,
    -- Privacidade (escopo, seção 16): sem detalhes, a mensagem não leva caminhos nem hashes.
    include_details INTEGER NOT NULL DEFAULT 1,
    created_by      TEXT NOT NULL,
    created_at      TEXT NOT NULL,
    updated_at      TEXT NOT NULL
) STRICT;

CREATE TABLE notification_rules (
    id            INTEGER PRIMARY KEY,
    channel_id    INTEGER NOT NULL REFERENCES notification_channels (id) ON DELETE CASCADE,
    event         TEXT NOT NULL CHECK (event IN ('finding_new', 'run_failed', 'run_partial', 'engine_selftest_failed',
                                                 'executor_unavailable', 'backup_failed')),
    -- Só vale para achados: severidade mínima que notifica.
    min_severity  TEXT NOT NULL DEFAULT 'high' CHECK (min_severity IN ('critical', 'high', 'medium', 'low', 'info')),
    -- O mesmo achado ou evento não notifica de novo neste canal dentro da janela.
    dedup_minutes INTEGER NOT NULL DEFAULT 60 CHECK (dedup_minutes BETWEEN 0 AND 10080),
    enabled       INTEGER NOT NULL DEFAULT 1,
    created_at    TEXT NOT NULL,
    updated_at    TEXT NOT NULL,
    UNIQUE (channel_id, event)
) STRICT;

-- Caixa de saída: cada linha é uma mensagem para um canal. Achados que chegam juntos entram na mesma linha enquanto
-- ela não foi tentada (resumo em vez de uma mensagem por achado).
CREATE TABLE notification_outbox (
    id              INTEGER PRIMARY KEY,
    channel_id      INTEGER REFERENCES notification_channels (id) ON DELETE SET NULL,
    channel_name    TEXT NOT NULL,
    channel_kind    TEXT NOT NULL,
    event           TEXT NOT NULL,
    -- Itens da mensagem (JSON), limitados a uma amostra; item_count conta todos.
    items           TEXT NOT NULL DEFAULT '[]',
    item_count      INTEGER NOT NULL DEFAULT 0,
    severity_counts TEXT NOT NULL DEFAULT '{}',
    state           TEXT NOT NULL CHECK (state IN ('pending', 'sent', 'failed')),
    attempts        INTEGER NOT NULL DEFAULT 0,
    max_attempts    INTEGER NOT NULL DEFAULT 8,
    next_attempt_at TEXT,
    last_error      TEXT NOT NULL DEFAULT '',
    created_at      TEXT NOT NULL,
    updated_at      TEXT NOT NULL,
    sent_at         TEXT
) STRICT;

CREATE INDEX notification_outbox_due ON notification_outbox (state, next_attempt_at);
CREATE INDEX notification_outbox_group ON notification_outbox (channel_id, event, state, attempts);

-- Última notificação de cada chave por canal (achado, execução, motor...), para a janela de deduplicação.
CREATE TABLE notification_dedup (
    channel_id INTEGER NOT NULL REFERENCES notification_channels (id) ON DELETE CASCADE,
    dedup_key  TEXT NOT NULL,
    last_at    TEXT NOT NULL,
    PRIMARY KEY (channel_id, dedup_key)
) STRICT;

-- +goose Down
DROP TABLE notification_dedup;
DROP INDEX notification_outbox_group;
DROP INDEX notification_outbox_due;
DROP TABLE notification_outbox;
DROP TABLE notification_rules;
DROP TABLE notification_channels;

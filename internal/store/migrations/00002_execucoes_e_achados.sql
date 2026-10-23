-- Execuções (que também são os jobs da fila), cobertura por motor, objetos, localizações, achados com ciclo de vida,
-- exceções, agendamentos e perfis de recursos próprios (ADR-003 e ADR-008; escopo, seções 10 a 12).
-- Datas em texto RFC 3339 UTC; JSON em texto validado pelo core.

-- +goose Up
CREATE TABLE runs (
    id               TEXT PRIMARY KEY,
    kind             TEXT NOT NULL CHECK (kind IN ('files', 'processes')),
    -- Estado da fila e da execução: queued → reserved → running → completed/partial/failed/engine_failure/canceled/interrupted
    status           TEXT NOT NULL,
    origin           TEXT NOT NULL CHECK (origin IN ('manual', 'schedule', 'system')),
    requested_by     TEXT NOT NULL DEFAULT '',
    schedule_id      INTEGER REFERENCES schedules (id) ON DELETE SET NULL,
    scheduled_for    TEXT,
    idempotency_key  TEXT UNIQUE,
    paths            TEXT NOT NULL DEFAULT '[]',
    exclude          TEXT NOT NULL DEFAULT '[]',
    incremental      INTEGER NOT NULL DEFAULT 1,
    profile          TEXT NOT NULL DEFAULT '{}',
    priority         INTEGER NOT NULL DEFAULT 0,
    attempts         INTEGER NOT NULL DEFAULT 0,
    lease_until      TEXT,
    heartbeat_at     TEXT,
    created_at       TEXT NOT NULL,
    started_at       TEXT,
    finished_at      TEXT,
    phase            TEXT NOT NULL DEFAULT '',
    paused           INTEGER NOT NULL DEFAULT 0,
    files_seen       INTEGER NOT NULL DEFAULT 0,
    files_eligible   INTEGER NOT NULL DEFAULT 0,
    files_processed  INTEGER NOT NULL DEFAULT 0,
    bytes_eligible   INTEGER NOT NULL DEFAULT 0,
    bytes_processed  INTEGER NOT NULL DEFAULT 0,
    findings_count   INTEGER NOT NULL DEFAULT 0,
    -- Posição já lida do findings.ndjson: a ingestão retoma daqui depois de um reinício, sem duplicar.
    findings_offset  INTEGER NOT NULL DEFAULT 0,
    summary          TEXT,
    error            TEXT NOT NULL DEFAULT ''
) STRICT;

CREATE INDEX runs_status ON runs (status, priority DESC, created_at);
CREATE INDEX runs_created ON runs (created_at DESC);
CREATE UNIQUE INDEX runs_schedule_slot ON runs (schedule_id, scheduled_for) WHERE schedule_id IS NOT NULL;

CREATE TABLE run_engines (
    run_id          TEXT NOT NULL REFERENCES runs (id) ON DELETE CASCADE,
    engine          TEXT NOT NULL,
    version         TEXT NOT NULL DEFAULT '',
    rules_version   TEXT NOT NULL DEFAULT '',
    available       INTEGER NOT NULL DEFAULT 0,
    selftest_passed INTEGER NOT NULL DEFAULT 0,
    selftest_detail TEXT NOT NULL DEFAULT '',
    eligible        INTEGER NOT NULL DEFAULT 0,
    analyzed        INTEGER NOT NULL DEFAULT 0,
    from_cache      INTEGER NOT NULL DEFAULT 0,
    bytes_analyzed  INTEGER NOT NULL DEFAULT 0,
    seconds         REAL NOT NULL DEFAULT 0,
    skipped         TEXT NOT NULL DEFAULT '{}',
    errors          TEXT NOT NULL DEFAULT '{}',
    error           TEXT NOT NULL DEFAULT '',
    PRIMARY KEY (run_id, engine)
) STRICT;

CREATE TABLE objects (
    sha256      TEXT PRIMARY KEY,
    size        INTEGER NOT NULL,
    file_type   TEXT NOT NULL DEFAULT '',
    first_seen  TEXT NOT NULL,
    last_seen   TEXT NOT NULL
) STRICT;

CREATE TABLE locations (
    id          INTEGER PRIMARY KEY,
    -- Caminho exato: em hexadecimal quando não é UTF-8 válido; path é a versão para exibição.
    path        TEXT NOT NULL,
    path_hex    TEXT NOT NULL DEFAULT '',
    sha256      TEXT REFERENCES objects (sha256),
    dev         INTEGER NOT NULL DEFAULT 0,
    ino         INTEGER NOT NULL DEFAULT 0,
    size        INTEGER NOT NULL DEFAULT 0,
    mode        INTEGER NOT NULL DEFAULT 0,
    uid         INTEGER NOT NULL DEFAULT 0,
    gid         INTEGER NOT NULL DEFAULT 0,
    nlink       INTEGER NOT NULL DEFAULT 0,
    mtime       TEXT NOT NULL DEFAULT '',
    ctime       TEXT NOT NULL DEFAULT '',
    first_seen  TEXT NOT NULL,
    last_seen   TEXT NOT NULL,
    UNIQUE (path, path_hex)
) STRICT;

CREATE INDEX locations_sha ON locations (sha256);

CREATE TABLE findings (
    id              INTEGER PRIMARY KEY,
    -- Identidade estável do achado: motor + assinatura + objeto (ou localização/processo/persistência).
    fingerprint     TEXT NOT NULL UNIQUE,
    kind            TEXT NOT NULL CHECK (kind IN ('file', 'process', 'persistence')),
    engine          TEXT NOT NULL,
    engine_version  TEXT NOT NULL DEFAULT '',
    rules_version   TEXT NOT NULL DEFAULT '',
    signature       TEXT NOT NULL,
    source          TEXT NOT NULL DEFAULT '',
    license         TEXT NOT NULL DEFAULT '',
    author          TEXT NOT NULL DEFAULT '',
    reference       TEXT NOT NULL DEFAULT '',
    description     TEXT NOT NULL DEFAULT '',
    category        TEXT NOT NULL,
    severity        TEXT NOT NULL CHECK (severity IN ('critical', 'high', 'medium', 'low', 'info')),
    sha256          TEXT REFERENCES objects (sha256),
    location_id     INTEGER REFERENCES locations (id),
    file_type       TEXT NOT NULL DEFAULT '',
    state           TEXT NOT NULL DEFAULT 'new'
                    CHECK (state IN ('new', 'in_review', 'confirmed', 'resolved', 'false_positive', 'excepted')),
    assignee        TEXT NOT NULL DEFAULT '',
    exception_id    INTEGER REFERENCES exceptions (id) ON DELETE SET NULL,
    first_run       TEXT NOT NULL,
    last_run        TEXT NOT NULL,
    first_seen      TEXT NOT NULL,
    last_seen       TEXT NOT NULL,
    state_changed   TEXT NOT NULL,
    times_seen      INTEGER NOT NULL DEFAULT 1,
    evidence        TEXT NOT NULL DEFAULT '{}',
    process         TEXT NOT NULL DEFAULT '',
    persistence     TEXT NOT NULL DEFAULT ''
) STRICT;

CREATE INDEX findings_state ON findings (state, severity);
CREATE INDEX findings_last_seen ON findings (last_seen DESC);
CREATE INDEX findings_sha ON findings (sha256);

CREATE TABLE finding_runs (
    finding_id  INTEGER NOT NULL REFERENCES findings (id) ON DELETE CASCADE,
    run_id      TEXT NOT NULL REFERENCES runs (id) ON DELETE CASCADE,
    location_id INTEGER NOT NULL DEFAULT 0, -- 0: achado sem localização (processo, persistência)
    PRIMARY KEY (finding_id, run_id, location_id)
) STRICT;

CREATE INDEX finding_runs_run ON finding_runs (run_id);

-- Histórico do ciclo de vida: cada mudança de estado, reabertura e nota.
CREATE TABLE finding_events (
    id          INTEGER PRIMARY KEY,
    finding_id  INTEGER NOT NULL REFERENCES findings (id) ON DELETE CASCADE,
    at          TEXT NOT NULL,
    actor       TEXT NOT NULL,
    action      TEXT NOT NULL,
    from_state  TEXT NOT NULL DEFAULT '',
    to_state    TEXT NOT NULL DEFAULT '',
    note        TEXT NOT NULL DEFAULT ''
) STRICT;

CREATE INDEX finding_events_finding ON finding_events (finding_id, at);

CREATE TABLE exceptions (
    id          INTEGER PRIMARY KEY,
    scope       TEXT NOT NULL CHECK (scope IN ('hash', 'hash_rule', 'rule_prefix', 'rule_global')),
    sha256      TEXT NOT NULL DEFAULT '',
    signature   TEXT NOT NULL DEFAULT '',
    path_prefix TEXT NOT NULL DEFAULT '',
    reason      TEXT NOT NULL,
    created_by  TEXT NOT NULL,
    created_at  TEXT NOT NULL,
    expires_at  TEXT,
    revoked_at  TEXT,
    revoked_by  TEXT NOT NULL DEFAULT ''
) STRICT;

CREATE TABLE schedules (
    id            INTEGER PRIMARY KEY,
    name          TEXT NOT NULL,
    kind          TEXT NOT NULL CHECK (kind IN ('files', 'processes')),
    cron          TEXT NOT NULL,
    timezone      TEXT NOT NULL DEFAULT 'UTC',
    paths         TEXT NOT NULL DEFAULT '[]',
    exclude       TEXT NOT NULL DEFAULT '[]',
    incremental   INTEGER NOT NULL DEFAULT 1,
    profile       TEXT NOT NULL DEFAULT 'padrao',
    missed_policy TEXT NOT NULL DEFAULT 'run_once' CHECK (missed_policy IN ('skip', 'run_once')),
    enabled       INTEGER NOT NULL DEFAULT 1,
    next_run_at   TEXT,
    last_run_at   TEXT,
    created_by    TEXT NOT NULL DEFAULT '',
    created_at    TEXT NOT NULL,
    updated_at    TEXT NOT NULL
) STRICT;

CREATE TABLE resource_profiles (
    name        TEXT PRIMARY KEY,
    profile     TEXT NOT NULL,
    updated_by  TEXT NOT NULL DEFAULT '',
    updated_at  TEXT NOT NULL
) STRICT;

-- +goose Down
DROP TABLE resource_profiles;
DROP TABLE schedules;
DROP TABLE exceptions;
DROP TABLE finding_events;
DROP TABLE finding_runs;
DROP TABLE findings;
DROP TABLE locations;
DROP TABLE objects;
DROP TABLE run_engines;
DROP TABLE runs;

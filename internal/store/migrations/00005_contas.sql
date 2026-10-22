-- Contas do servidor como unidade de escopo (E1.9): quais contas cada execução cobriu, o filtro por dono nas raízes
-- compartilhadas (/tmp, /var/tmp, /dev/shm) e a seleção de contas dos agendamentos.

-- +goose Up
ALTER TABLE runs ADD COLUMN accounts TEXT NOT NULL DEFAULT '[]';
ALTER TABLE runs ADD COLUMN owners TEXT NOT NULL DEFAULT '{}';
CREATE TABLE run_accounts (
    run_id  TEXT NOT NULL REFERENCES runs (id) ON DELETE CASCADE,
    uid     INTEGER NOT NULL,
    PRIMARY KEY (run_id, uid)
) STRICT;
CREATE INDEX run_accounts_uid ON run_accounts (uid, run_id);
ALTER TABLE schedules ADD COLUMN accounts TEXT NOT NULL DEFAULT '{}';
CREATE INDEX locations_uid ON locations (uid);

-- +goose Down
DROP INDEX locations_uid;
ALTER TABLE schedules DROP COLUMN accounts;
DROP TABLE run_accounts;
ALTER TABLE runs DROP COLUMN owners;
ALTER TABLE runs DROP COLUMN accounts;

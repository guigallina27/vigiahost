-- Instantâneos da inspeção de processos: lista de processos (segredos já mascarados pelo executor) e inventário de
-- persistência. Guardados para as telas "Processos" e "Persistência"; os achados ficam em findings.

-- +goose Up
CREATE TABLE inventory_snapshots (
    run_id      TEXT PRIMARY KEY REFERENCES runs (id) ON DELETE CASCADE,
    taken_at    TEXT NOT NULL,
    processes   TEXT NOT NULL,
    persistence TEXT NOT NULL
);
CREATE INDEX inventory_snapshots_taken ON inventory_snapshots (taken_at DESC);

-- +goose Down
DROP TABLE inventory_snapshots;

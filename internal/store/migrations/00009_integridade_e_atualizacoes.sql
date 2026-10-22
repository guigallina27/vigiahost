-- Verificação contra os pacotes (E2.2) e correções pendentes, reinícios e processos e portas ocultos (E2.4).
--
-- 1. Tipos de execução e de achado deixam de ser listas fechadas no CHECK: o core valida o tipo (report.ValidKind) e
--    o banco só garante o formato (letras minúsculas, até 32). Trocar o CHECK pela reconstrução das tabelas apagaria
--    colunas acrescentadas por outras migrações; a SQLite documenta a edição direta do esquema para afrouxar CHECK
--    (o conteúdo gravado não muda), e "writable_schema = RESET" recarrega o esquema na própria conexão (ADR-021).
-- 2. Achados do sistema (sem arquivo, processo ou item de persistência) têm um assunto estável: "security-updates",
--    "repo:epel", "tcp/31337".
-- 3. Relatórios das verificações do sistema (integrity.json, updates.json, hidden.json) guardados por execução para
--    as telas "Integridade", "Atualizações" e "Processos".

-- +goose Up
PRAGMA writable_schema = ON;
UPDATE sqlite_schema
SET sql = replace(sql, 'CHECK (kind IN (''files'', ''processes''))',
                  'CHECK (kind <> '''' AND kind NOT GLOB ''*[^a-z]*'' AND length(kind) <= 32)')
WHERE type = 'table' AND name IN ('runs', 'schedules');
UPDATE sqlite_schema
SET sql = replace(sql, 'CHECK (kind IN (''file'', ''process'', ''persistence''))',
                  'CHECK (kind <> '''' AND kind NOT GLOB ''*[^a-z]*'' AND length(kind) <= 32)')
WHERE type = 'table' AND name = 'findings';
PRAGMA writable_schema = RESET;

ALTER TABLE findings ADD COLUMN subject TEXT NOT NULL DEFAULT '';

CREATE TABLE host_reports (
    run_id    TEXT NOT NULL REFERENCES runs (id) ON DELETE CASCADE,
    -- integrity, updates ou hidden
    name      TEXT NOT NULL,
    taken_at  TEXT NOT NULL,
    data      TEXT NOT NULL,
    PRIMARY KEY (run_id, name)
) STRICT;
CREATE INDEX host_reports_name ON host_reports (name, taken_at DESC);

-- +goose Down
DROP TABLE host_reports;
ALTER TABLE findings DROP COLUMN subject;
PRAGMA writable_schema = ON;
UPDATE sqlite_schema
SET sql = replace(sql, 'CHECK (kind <> '''' AND kind NOT GLOB ''*[^a-z]*'' AND length(kind) <= 32)',
                  'CHECK (kind IN (''files'', ''processes''))')
WHERE type = 'table' AND name IN ('runs', 'schedules');
UPDATE sqlite_schema
SET sql = replace(sql, 'CHECK (kind <> '''' AND kind NOT GLOB ''*[^a-z]*'' AND length(kind) <= 32)',
                  'CHECK (kind IN (''file'', ''process'', ''persistence''))')
WHERE type = 'table' AND name = 'findings';
PRAGMA writable_schema = RESET;

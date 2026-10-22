-- Recursos avançados (E1.13): estado da limitação por pressão (PSI) durante a execução e histórico dos ajustes de
-- limites feitos em tempo real. As métricas de desempenho de cada execução ficam no resumo (coluna summary).

-- +goose Up
-- JSON do estado da limitação em andamento ({"state":"reduced","workers":1,...}); vazio sem limitação.
ALTER TABLE runs ADD COLUMN throttle TEXT NOT NULL DEFAULT '';
-- Lista JSON dos ajustes: quando, quem, limites antes e depois.
ALTER TABLE runs ADD COLUMN adjustments TEXT NOT NULL DEFAULT '[]';
-- Comparativo entre execuções do mesmo tipo (últimas N terminadas).
CREATE INDEX runs_kind_finished ON runs (kind, finished_at DESC) WHERE finished_at IS NOT NULL;

-- +goose Down
DROP INDEX runs_kind_finished;
ALTER TABLE runs DROP COLUMN adjustments;
ALTER TABLE runs DROP COLUMN throttle;

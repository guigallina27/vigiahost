-- +goose Up
CREATE TABLE settings (
    key        TEXT PRIMARY KEY,
    value      TEXT NOT NULL,
    updated_at TEXT NOT NULL
) STRICT;

-- +goose Down
DROP TABLE settings;

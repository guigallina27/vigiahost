// Package store abre o banco SQLite local e aplica as migrações embarcadas.
//
// Política de migração (escopo, seção 15): expandir e depois contrair. Uma release só adiciona;
// remoções vêm na seguinte. Assim a versão anterior do binário continua funcionando sobre o
// esquema novo, e o retorno de versão não exige restaurar backup.
package store

import (
	"context"
	"database/sql"
	"embed"
	"fmt"
	"io/fs"
	"strings"

	"github.com/pressly/goose/v3"
	_ "modernc.org/sqlite"
)

//go:embed migrations/*.sql
var migrations embed.FS

// Open abre o banco com WAL, espera em caso de bloqueio e um único escritor.
func Open(ctx context.Context, path string) (*sql.DB, error) {
	if path == "" || strings.ContainsAny(path, "?#") {
		return nil, fmt.Errorf("caminho de banco inválido: %q", path)
	}
	dsn := "file:" + path +
		"?_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)&_pragma=foreign_keys(1)&_pragma=synchronous(NORMAL)"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	if err := db.PingContext(ctx); err != nil {
		db.Close()
		return nil, err
	}
	return db, nil
}

type MigrationResult struct {
	From int64
	To   int64
	// NewerSchema indica banco migrado por uma versão mais nova do produto (retorno de versão).
	NewerSchema bool
}

// Migrate aplica as migrações pendentes. Se o banco já estiver à frente deste binário, não altera nada.
func Migrate(ctx context.Context, db *sql.DB) (MigrationResult, error) {
	sub, err := fs.Sub(migrations, "migrations")
	if err != nil {
		return MigrationResult{}, err
	}
	provider, err := goose.NewProvider(goose.DialectSQLite3, db, sub)
	if err != nil {
		return MigrationResult{}, err
	}
	current, err := provider.GetDBVersion(ctx)
	if err != nil {
		return MigrationResult{}, fmt.Errorf("versão do esquema: %w", err)
	}
	sources := provider.ListSources()
	latest := sources[len(sources)-1].Version
	if current > latest {
		return MigrationResult{From: current, To: current, NewerSchema: true}, nil
	}
	if _, err := provider.Up(ctx); err != nil {
		return MigrationResult{}, fmt.Errorf("migração: %w", err)
	}
	after, err := provider.GetDBVersion(ctx)
	if err != nil {
		return MigrationResult{}, err
	}
	return MigrationResult{From: current, To: after}, nil
}

// LatestSchema é a versão mais nova do esquema embarcada neste binário.
func LatestSchema() int64 {
	ents, err := fs.ReadDir(migrations, "migrations")
	if err != nil {
		return 0
	}
	var latest int64
	for _, e := range ents {
		var v int64
		if _, err := fmt.Sscanf(e.Name(), "%d_", &v); err == nil && v > latest {
			latest = v
		}
	}
	return latest
}

// SchemaVersion lê a versão aplicada ao banco (0 em banco novo).
func SchemaVersion(ctx context.Context, db *sql.DB) (int64, error) {
	var exists int
	if err := db.QueryRowContext(ctx, `SELECT count(*) FROM sqlite_master WHERE type = 'table' AND name = 'goose_db_version'`).Scan(&exists); err != nil || exists == 0 {
		return 0, err
	}
	var v sql.NullInt64
	err := db.QueryRowContext(ctx, `SELECT MAX(version_id) FROM goose_db_version WHERE is_applied`).Scan(&v)
	return v.Int64, err
}

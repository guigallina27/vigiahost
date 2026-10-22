package store

import (
	"context"
	"path/filepath"
	"testing"
)

func TestMigrateCriaEsquemaEEhIdempotente(t *testing.T) {
	ctx := context.Background()
	db, err := Open(ctx, filepath.Join(t.TempDir(), "teste.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	res, err := Migrate(ctx, db)
	if err != nil {
		t.Fatal(err)
	}
	if res.From != 0 || res.To < 1 || res.NewerSchema {
		t.Fatalf("resultado inesperado na primeira migração: %+v", res)
	}
	if _, err := db.ExecContext(ctx, `INSERT INTO settings(key, value, updated_at) VALUES ('k', 'v', 'agora')`); err != nil {
		t.Fatalf("tabela settings indisponível: %v", err)
	}

	again, err := Migrate(ctx, db)
	if err != nil {
		t.Fatal(err)
	}
	if again.From != res.To || again.To != res.To {
		t.Fatalf("segunda migração deveria ser nula: %+v", again)
	}

	var mode string
	if err := db.QueryRowContext(ctx, `PRAGMA journal_mode`).Scan(&mode); err != nil || mode != "wal" {
		t.Errorf("journal_mode = %q (%v), esperado wal", mode, err)
	}
}

func TestMigrateComEsquemaMaisNovo(t *testing.T) {
	ctx := context.Background()
	db, err := Open(ctx, filepath.Join(t.TempDir(), "teste.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := Migrate(ctx, db); err != nil {
		t.Fatal(err)
	}
	// Simula um banco migrado por uma versão futura do produto (retorno de versão do pacote).
	if _, err := db.ExecContext(ctx, `INSERT INTO goose_db_version(version_id, is_applied) VALUES (9999, 1)`); err != nil {
		t.Fatal(err)
	}
	res, err := Migrate(ctx, db)
	if err != nil {
		t.Fatalf("binário antigo deveria aceitar esquema mais novo: %v", err)
	}
	if !res.NewerSchema || res.From != 9999 {
		t.Fatalf("esquema mais novo não detectado: %+v", res)
	}
}

func TestOpenRecusaCaminhoComParametros(t *testing.T) {
	if _, err := Open(context.Background(), "/tmp/x.db?mode=memory"); err == nil {
		t.Fatal("caminho com parâmetros deveria ser recusado")
	}
}

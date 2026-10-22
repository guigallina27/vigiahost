package backup

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/guigallina27/vigiahost/internal/store"
)

func openDB(t *testing.T, path string) *store.DB {
	t.Helper()
	raw, err := store.Open(context.Background(), path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = raw.Close() })
	if _, err := store.Migrate(context.Background(), raw); err != nil {
		t.Fatal(err)
	}
	return store.New(raw)
}

func TestCopiaConsistenteRetencaoERestauracao(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "vigiahost.db")
	db := openDB(t, dbPath)
	if err := db.Audit(ctx, "ana", "teste", "antes", "", "127.0.0.1"); err != nil {
		t.Fatal(err)
	}
	if v, err := store.SchemaVersion(ctx, db.DB); err != nil || v != store.LatestSchema() {
		t.Fatalf("versão do esquema: %d (%v), esperado %d", v, err, store.LatestSchema())
	}
	backups := filepath.Join(dir, "backups")
	base := time.Date(2026, 10, 22, 3, 0, 0, 0, time.UTC)
	var first Info
	for i := range 4 {
		info, err := Create(ctx, db.DB, backups, "automatic", base.Add(time.Duration(i)*24*time.Hour))
		if err != nil {
			t.Fatal(err)
		}
		if i == 0 {
			first = info
		}
		if info.SchemaVersion != store.LatestSchema() || len(info.SHA256) != 64 || info.Size == 0 {
			t.Fatalf("manifesto incompleto: %+v", info)
		}
	}
	if _, err := Create(ctx, db.DB, backups, "manual", base); err == nil {
		t.Fatal("dois backups no mesmo segundo deveriam ser recusados")
	}
	if n, err := Prune(backups, 2); err != nil || n != 2 {
		t.Fatalf("retenção: removeu %d (%v)", n, err)
	}
	list, _ := List(backups)
	if len(list) != 2 || list[0].CreatedAt.Before(list[1].CreatedAt) {
		t.Fatalf("lista após a retenção: %+v", list)
	}
	if _, _, err := Find(backups, first.Name); err == nil {
		t.Fatal("a cópia mais antiga deveria ter saído")
	}
	if _, _, err := Find(backups, "../vigiahost.db"); err == nil {
		t.Fatal("nome com caminho aceito")
	}

	// Restauração: dado gravado depois da cópia some; o banco anterior vira cópia "pre-restore".
	if err := db.Audit(ctx, "ana", "teste", "depois", "", "127.0.0.1"); err != nil {
		t.Fatal(err)
	}
	_, src, err := Find(backups, list[0].Name)
	if err != nil {
		t.Fatal(err)
	}
	_ = db.Close()
	if _, err := Restore(ctx, src, dbPath, backups, 1, base.Add(10*24*time.Hour)); err == nil {
		t.Fatal("restaurar esquema mais novo que o binário deveria ser recusado")
	}
	if _, err := Restore(ctx, src, dbPath, backups, 99, base.Add(10*24*time.Hour)); err != nil {
		t.Fatal(err)
	}
	db2 := openDB(t, dbPath)
	entries, err := db2.ListAudit(ctx, 0, 100)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if e.Target == "depois" {
			t.Fatal("o banco restaurado não deveria ter o dado posterior à cópia")
		}
	}
	list, _ = List(backups)
	if list[0].Origin != "pre-restore" {
		t.Fatalf("faltou a cópia do banco anterior: %+v", list[0])
	}
	if _, err := os.Stat(src); err != nil {
		t.Fatal("a cópia restaurada continua guardada")
	}
}

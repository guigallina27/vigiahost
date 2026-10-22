package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/guigallina27/vigiahost/internal/backup"
	"github.com/guigallina27/vigiahost/internal/setup"
	"github.com/guigallina27/vigiahost/internal/store"
)

const backupUsage = `uso: vigiahost backup <create|list|restore NOME> [-db arquivo]

  create         faz uma cópia consistente do banco agora (o serviço pode continuar no ar)
  list           lista as cópias guardadas
  restore NOME   troca o banco pela cópia NOME (o serviço vigiahost-core precisa estar parado)
`

// runBackup trata "vigiahost backup create|list|restore" (root).
func runBackup(args []string) int {
	if len(args) < 1 {
		fmt.Fprint(os.Stderr, backupUsage)
		return 2
	}
	sub := args[0]
	fs := flag.NewFlagSet("backup "+sub, flag.ContinueOnError)
	dbPath := fs.String("db", defaultDB(), "arquivo do banco SQLite")
	if err := fs.Parse(args[1:]); err != nil {
		return 2
	}
	dir := filepath.Join(filepath.Dir(*dbPath), "backups")
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
	defer cancel()
	var err error
	switch sub {
	case "list":
		err = backupList(dir)
	case "create":
		err = backupCreate(ctx, *dbPath, dir)
	case "restore":
		if fs.NArg() != 1 {
			fmt.Fprint(os.Stderr, backupUsage)
			return 2
		}
		err = backupRestore(ctx, *dbPath, dir, fs.Arg(0))
	default:
		fmt.Fprint(os.Stderr, backupUsage)
		return 2
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "erro:", err)
		return 1
	}
	return 0
}

func backupList(dir string) error {
	list, err := backup.List(dir)
	if err != nil {
		return err
	}
	if len(list) == 0 {
		fmt.Printf("nenhuma cópia em %s\n", dir)
		return nil
	}
	tw := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	_, _ = fmt.Fprintln(tw, "NOME\tDATA (UTC)\tTAMANHO\tESQUEMA\tORIGEM")
	for _, i := range list {
		_, _ = fmt.Fprintf(tw, "%s\t%s\t%d KiB\t%d\t%s\n", i.Name, i.CreatedAt.Format("02/01/2006 15:04:05"),
			(i.Size+1023)/1024, i.SchemaVersion, i.Origin)
	}
	_ = tw.Flush()
	fmt.Printf("\nDiretório: %s (o serviço guarda as %d cópias automáticas diárias mais recentes)\n", dir, backup.KeepAutomatic)
	return nil
}

func backupCreate(ctx context.Context, dbPath, dir string) error {
	if os.Geteuid() != 0 {
		return fmt.Errorf("execute como root (o comando lê o banco do serviço)")
	}
	if _, err := os.Stat(dbPath); err != nil { //nolint:gosec // G703: caminho do banco dado pelo root no terminal
		return fmt.Errorf("banco %s: %w", dbPath, err)
	}
	raw, err := store.Open(ctx, dbPath)
	if err != nil {
		return err
	}
	info, err := backup.Create(ctx, raw, dir, "cli", time.Now())
	_ = raw.Close()
	owner := filepath.Dir(dbPath)
	copyOwner(owner, dbPath+"-wal", dbPath+"-shm", dir)
	if err != nil {
		return err
	}
	base := filepath.Join(dir, strings.TrimSuffix(info.Name, ".db"))
	copyOwner(owner, base+".db", base+".json")
	fmt.Printf("cópia criada: %s\n  sha256 %s\n  esquema %d, %d KiB\n", filepath.Join(dir, info.Name), info.SHA256,
		info.SchemaVersion, (info.Size+1023)/1024)
	return nil
}

func backupRestore(ctx context.Context, dbPath, dir, name string) error {
	if os.Geteuid() != 0 {
		return fmt.Errorf("execute como root")
	}
	// Trocar o banco com o serviço no ar corromperia o estado em memória; o comando nunca para o serviço sozinho.
	if st, _ := setup.Host().Systemctl(ctx, "is-active", "vigiahost-core.service"); st == "active" || st == "activating" || st == "reloading" {
		return fmt.Errorf("o vigiahost-core está em execução; pare-o com \"systemctl stop vigiahost-core\", rode o restore de novo " +
			"e depois inicie com \"systemctl start vigiahost-core\" (as verificações em andamento serão interrompidas)")
	}
	_, src, err := backup.Find(dir, name)
	if err != nil {
		return fmt.Errorf("cópia %q: %w (veja \"vigiahost backup list\")", name, err)
	}
	info, err := backup.Restore(ctx, src, dbPath, dir, store.LatestSchema(), time.Now())
	if err != nil {
		return err
	}
	owner := filepath.Dir(dbPath)
	copyOwner(owner, dbPath)
	if list, err := backup.List(dir); err == nil {
		for _, i := range list {
			base := filepath.Join(dir, strings.TrimSuffix(i.Name, ".db"))
			copyOwner(owner, base+".db", base+".json")
		}
	}
	fmt.Printf("banco restaurado a partir de %s (esquema %d).\n"+
		"O banco anterior foi guardado como cópia \"pre-restore\" em %s.\n"+
		"Inicie o serviço: systemctl start vigiahost-core\n", info.Name, info.SchemaVersion, dir)
	return nil
}

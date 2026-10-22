package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/guigallina27/vigiahost/internal/auth"
	"github.com/guigallina27/vigiahost/internal/store"
)

// openAdminDB abre o banco para os comandos do root no terminal. Depois de gravar, devolve os arquivos do SQLite
// (-wal, -shm) ao dono do banco, para o serviço continuar conseguindo escrever.
func openAdminDB(ctx context.Context, path string) (*store.DB, func(), error) {
	if os.Geteuid() != 0 {
		return nil, nil, errors.New("execute como root (o comando lê o banco do serviço)")
	}
	if _, err := os.Stat(path); err != nil {
		return nil, nil, fmt.Errorf("banco %s: %w (o serviço já foi iniciado alguma vez?)", path, err)
	}
	raw, err := store.Open(ctx, path)
	if err != nil {
		return nil, nil, err
	}
	if _, err := store.Migrate(ctx, raw); err != nil {
		_ = raw.Close()
		return nil, nil, err
	}
	closeFn := func() {
		_ = raw.Close()
		copyOwner(path, path+"-wal", path+"-shm")
	}
	return store.New(raw), closeFn, nil
}

func adminService(db *store.DB) *auth.Service {
	return &auth.Service{DB: db, Logger: slog.New(slog.NewTextHandler(io.Discard, nil))}
}

// runFirstAccess mostra (ou gera de novo) o token de primeiro acesso.
func runFirstAccess(args []string) int {
	fs := flag.NewFlagSet("first-access", flag.ContinueOnError)
	dbPath := fs.String("db", defaultDB(), "arquivo do banco SQLite")
	renew := fs.Bool("renew", false, "gera um token novo (o anterior deixa de valer)")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	file := filepath.Join(filepath.Dir(*dbPath), firstAccessFileName)
	if !*renew {
		if data, err := os.ReadFile(file); err == nil { //nolint:gosec // arquivo do diretório de estado
			printFirstAccess(strings.TrimSpace(string(data)))
			return 0
		}
	}
	db, done, err := openAdminDB(ctx, *dbPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "erro:", err)
		return 1
	}
	defer done()
	tok, err := adminService(db).NewFirstAccessToken(ctx)
	if err != nil {
		fmt.Fprintln(os.Stderr, "erro:", err)
		return 1
	}
	if err := os.WriteFile(file, []byte(tok+"\n"), 0o600); err == nil {
		copyOwner(*dbPath, file)
	}
	printFirstAccess(tok)
	return 0
}

func printFirstAccess(tok string) {
	fmt.Printf(`Token de primeiro acesso (uso único, vale 24 horas):

    %s

Abra o painel (por padrão em http://127.0.0.1:8743, pelo túnel SSH:
    ssh -L 8743:127.0.0.1:8743 root@servidor
), informe o token e crie o administrador. O segundo fator (aplicativo autenticador) é configurado em seguida.
`, tok)
}

// runUser trata "vigiahost user reset <usuário>".
func runUser(args []string) int {
	if len(args) < 1 || args[0] != "reset" {
		fmt.Fprintln(os.Stderr, "uso: vigiahost user reset [-db arquivo] <usuário>")
		return 2
	}
	fs := flag.NewFlagSet("user reset", flag.ContinueOnError)
	dbPath := fs.String("db", defaultDB(), "arquivo do banco SQLite")
	if err := fs.Parse(args[1:]); err != nil {
		return 2
	}
	if fs.NArg() != 1 {
		fmt.Fprintln(os.Stderr, "informe o nome do usuário")
		return 2
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	db, done, err := openAdminDB(ctx, *dbPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "erro:", err)
		return 1
	}
	defer done()
	tok, err := adminService(db).NewResetToken(ctx, fs.Arg(0))
	if errors.Is(err, store.ErrNotFound) {
		fmt.Fprintf(os.Stderr, "usuário %q não existe\n", fs.Arg(0))
		return 1
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "erro:", err)
		return 1
	}
	fmt.Printf(`Token de recuperação para %s (uso único, vale 15 minutos):

    %s

Na tela de login do painel, use "Recuperar acesso" com este token para definir uma senha nova. O segundo fator
é apagado e configurado de novo no próximo login. A emissão ficou registrada na auditoria.
`, fs.Arg(0), tok)
	return 0
}

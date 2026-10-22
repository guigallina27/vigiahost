package main

import (
	"context"
	"flag"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/guigallina27/vigiahost/internal/engines/yarax"
	"github.com/guigallina27/vigiahost/internal/rules"
	"github.com/guigallina27/vigiahost/internal/scan"
)

// runRules é o processo da unidade transitória da compilação pedida pelo administrador: confere e compila cada
// fonte, monta o conjunto, testa o controle positivo no conjunto compilado e grava o resultado em
// STATE/rules/status.json (lido pela operação rules.status).
func runRules(args []string) int {
	fs := flag.NewFlagSet("rules", flag.ContinueOnError)
	state := fs.String("state", defaultStateDir, "diretório de estado do executor")
	userRules := fs.String("user-rules", rules.UserDir, "diretório das fontes locais de regras YARA")
	disabledList := fs.String("disabled", "", "fontes desativadas, separadas por vírgula")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	logger := slog.New(slog.NewJSONHandler(os.Stderr, nil))
	var disabled []string
	if *disabledList != "" {
		disabled = strings.Split(*disabledList, ",")
	}
	if err := rules.ValidDisabled(disabled); err != nil {
		logger.Error("lista de fontes desativadas inválida", "erro", err)
		return 2
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	ctx, cancel := context.WithTimeout(ctx, 14*time.Minute)
	defer cancel()

	dir := filepath.Join(*state, "rules")
	fail := func(msg string) int {
		st := rules.CompileStatus{At: time.Now().UTC(), Trigger: "manual", Error: msg, Disabled: disabled}
		if err := rules.WriteStatus(dir, st); err != nil {
			logger.Error("status da compilação não gravado", "erro", err)
		}
		logger.Error("compilação de regras falhou", "erro", msg)
		return 1
	}
	yr := scan.YRBinary()
	if yr == "" {
		return fail("YARA-X (yr) não encontrado")
	}
	v, err := yarax.Version(ctx, yr)
	if err != nil {
		return fail(err.Error())
	}
	_, compiled, st, err := rules.Prepare(ctx, yr, v, dir, rules.PrepareOptions{UserDir: *userRules, Disabled: disabled, Trigger: "manual"})
	if err != nil {
		logger.Error("compilação de regras falhou", "erro", err)
		return 1
	}
	ok, detail := scan.RulesSelfTest(ctx, yr, compiled)
	st.SelfTest, st.Detail = &ok, detail
	if err := rules.WriteStatus(dir, st); err != nil {
		logger.Error("status da compilação não gravado", "erro", err)
		return 1
	}
	logger.Info("regras compiladas", "conjunto", st.SetVersion, "autoteste", ok, "fontes", len(st.Sources))
	if !ok {
		return 1
	}
	return 0
}

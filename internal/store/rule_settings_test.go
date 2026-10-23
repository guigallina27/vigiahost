package store

import (
	"context"
	"slices"
	"testing"
)

func TestConfiguracaoDeRegrasELMD(t *testing.T) {
	ctx := context.Background()
	db, _ := openTest(t)
	if on, err := db.LMDEnabled(ctx); err != nil || on {
		t.Fatalf("LMD deveria começar desligado: %v %v", on, err)
	}
	if list, err := db.DisabledRuleSources(ctx); err != nil || len(list) != 0 {
		t.Fatalf("nenhuma fonte desativada por padrão: %v %v", list, err)
	}
	if err := db.SetLMDEnabled(ctx, true); err != nil {
		t.Fatal(err)
	}
	if on, _ := db.LMDEnabled(ctx); !on {
		t.Fatal("LMD não ficou ligado")
	}
	if err := db.SetLMDEnabled(ctx, false); err != nil {
		t.Fatal(err)
	}
	if on, _ := db.LMDEnabled(ctx); on {
		t.Fatal("LMD não ficou desligado")
	}
	if err := db.SetDisabledRuleSources(ctx, []string{"zeta", "alfa", "zeta", ""}); err != nil {
		t.Fatal(err)
	}
	if list, _ := db.DisabledRuleSources(ctx); !slices.Equal(list, []string{"alfa", "zeta"}) {
		t.Fatalf("lista gravada: %v", list)
	}
	if err := db.SetDisabledRuleSources(ctx, nil); err != nil {
		t.Fatal(err)
	}
	if list, _ := db.DisabledRuleSources(ctx); len(list) != 0 {
		t.Fatalf("lista deveria esvaziar: %v", list)
	}
}

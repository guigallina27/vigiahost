package yarax

import (
	"encoding/json"
	"testing"
)

func TestParseMeta(t *testing.T) {
	var raw []json.RawMessage
	if err := json.Unmarshal([]byte(`[["author","VigiaHost"],["score",80],["ativo",true],["ruim"],[1,2]]`), &raw); err != nil {
		t.Fatal(err)
	}
	m := parseMeta(raw)
	if m["author"] != "VigiaHost" || m["score"] != "80" || m["ativo"] != "true" || len(m) != 3 {
		t.Fatalf("meta: %v", m)
	}
}

func TestFdIndex(t *testing.T) {
	cases := map[string]struct {
		i  int
		ok bool
	}{
		"/dev/fd/3":     {0, true},
		"/dev/fd/12":    {9, true},
		"/dev/fd/13":    {0, false}, // fora do lote de 10
		"/dev/fd/2":     {0, false},
		"/var/www/x":    {0, false},
		"/dev/fd/3x":    {0, false},
		"/dev/fd/../3":  {0, false},
		"/dev/fd/-1":    {0, false},
		"x/dev/fd/3":    {0, false},
		"/dev/fd/00003": {0, true},
	}
	for p, want := range cases {
		i, ok := fdIndex(p, 10)
		if ok != want.ok || (ok && i != want.i) {
			t.Errorf("fdIndex(%q) = %d, %v; esperado %d, %v", p, i, ok, want.i, want.ok)
		}
	}
}

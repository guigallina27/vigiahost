package executor

import (
	"strings"
	"testing"

	"github.com/guigallina27/vigiahost/internal/report"
)

func TestValidacaoDoPedidoCaminhosEFiltroDeDono(t *testing.T) {
	ok := func(paths []string, owners map[string][]uint32) error {
		req := report.Request{RunID: "20261022-120000-abcdef12", Kind: report.KindFiles, Paths: paths, Owners: owners}
		return ValidateRequest(&req, nil)
	}
	// Verificação por conta: diretório da conta mais as áreas temporárias, estas só com os arquivos do UID.
	tmp := t.TempDir()
	if err := ok([]string{tmp, "/tmp", "/dev/shm"}, map[string][]uint32{"/tmp": {1001}, "/dev/shm": {1001}}); err != nil {
		t.Fatalf("pedido por conta recusado: %v", err)
	}
	for name, c := range map[string]struct {
		paths  []string
		owners map[string][]uint32
		want   string
	}{
		"/dev fora do shm":         {[]string{"/dev"}, nil, "não é varrida"},
		"/dev/shm/../pts":          {[]string{"/dev/pts"}, nil, "não é varrida"},
		"/proc":                    {[]string{"/proc/1"}, nil, "não é varrida"},
		"dono de raiz inexistente": {[]string{tmp}, map[string][]uint32{"/tmp": {1}}, "não é raiz"},
		"dono sem contas":          {[]string{"/tmp"}, map[string][]uint32{"/tmp": {}}, "0 contas"},
	} {
		if err := ok(c.paths, c.owners); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

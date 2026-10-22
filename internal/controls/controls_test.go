package controls

import (
	"bytes"
	"strings"
	"testing"
)

// Os testes conferem o conteúdo em memória; nenhum arquivo EICAR é gravado em disco.

func TestEICAR(t *testing.T) {
	b := EICAR()
	if len(b) != 68 {
		t.Fatalf("EICAR com %d bytes, esperado 68", len(b))
	}
	if !bytes.HasPrefix(b, []byte("X5O!")) {
		t.Fatal("EICAR deve começar no primeiro byte")
	}
}

func TestRegraReconheceOMarcador(t *testing.T) {
	if !strings.Contains(YARARule, "rule "+YARARuleName) {
		t.Fatalf("regra embarcada não declara %s", YARARuleName)
	}
	if !strings.Contains(YARARule, `"`+Marker+`"`) {
		t.Fatal("regra embarcada não procura o marcador atual")
	}
	if !bytes.Contains(MarkerFile(), []byte(Marker)) {
		t.Fatal("arquivo de controle positivo sem o marcador")
	}
	if bytes.Contains(NegativeFile(), []byte(Marker)) || bytes.Contains(NegativeFile(), []byte("EICAR")) {
		t.Fatal("controle negativo não pode conter marcador nem EICAR")
	}
}

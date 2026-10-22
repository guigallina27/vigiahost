package accounts

import (
	"os"
	"testing"
)

func TestLoginDefsEFaixaDeContas(t *testing.T) {
	lo, hi := LoginDefs([]byte("# comentário\nUID_MIN\t\t 500\nUID_MAX 59999\nGID_MIN 500\nUID_MIN lixo\n"))
	if lo != 500 || hi != 59999 {
		t.Fatalf("faixa = %d..%d", lo, hi)
	}
	if lo, hi := LoginDefs(nil); lo != DefaultUIDMin || hi != DefaultUIDMax {
		t.Fatalf("padrão = %d..%d", lo, hi)
	}
}

func TestParseSeparaContasDeSistemaERepetidas(t *testing.T) {
	passwd := "root:x:0:0:root:/root:/bin/bash\n" +
		"nginx:x:998:996::/var/lib/nginx:/sbin/nologin\n" +
		"ana:x:1001:1001:Ana:/home/ana:/bin/bash\n" +
		"bia:x:1002:1002::/home/bia:/sbin/nologin\n" +
		"ana:x:5001:5001:LDAP:/home/ana-ldap:/bin/bash\n" + // repetida: vale a primeira
		"nobody:x:65534:65534::/:/sbin/nologin\n" +
		"quebrada:x:abc:1::/home/q:/bin/sh\n" +
		"+@grupo::::::\n"
	got := Parse([]byte(passwd), 1000, 60000)
	want := map[string]bool{"root": true, "nginx": true, "ana": false, "bia": false, "nobody": true}
	if len(got) != len(want) {
		t.Fatalf("contas = %+v", got)
	}
	for _, a := range got {
		if sys, ok := want[a.Name]; !ok || sys != a.System {
			t.Errorf("%s: system=%v", a.Name, a.System)
		}
		if a.Name == "ana" && (a.UID != 1001 || a.Home != "/home/ana") {
			t.Errorf("ana repetida trocou de dados: %+v", a)
		}
	}
}

func TestDiretorioPessoalValido(t *testing.T) {
	dir := t.TempDir()
	if !validHome(dir) {
		t.Fatal("diretório existente recusado")
	}
	f := dir + "/arquivo"
	_ = os.WriteFile(f, nil, 0o600)
	for _, h := range []string{"", "/", "relativo", f, dir + "/nao-existe"} {
		if validHome(h) {
			t.Errorf("%q aceito como diretório pessoal", h)
		}
	}
}

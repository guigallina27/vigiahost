// Package accounts descobre as contas do servidor (escopo, seção 9.1; E1.9): "conta" é o usuário do sistema ou da
// hospedagem dono de arquivos e processos, diferente dos usuários do painel. Sem painel de hospedagem, a fonte é o
// getent passwd (inclui LDAP e SSSD), com as contas humanas separadas pelo UID_MIN/UID_MAX de /etc/login.defs.
package accounts

import (
	"bufio"
	"bytes"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// Account é uma conta do servidor.
type Account struct {
	UID   uint32 `json:"uid"`
	GID   uint32 `json:"gid"`
	Name  string `json:"name"`
	Home  string `json:"home"`
	Shell string `json:"shell"`
	// System marca contas fora da faixa de contas humanas/de hospedagem (root, serviços, nobody).
	System bool `json:"system"`
	// HomeOK diz se o diretório pessoal existe e é um diretório (sem ele não há o que verificar).
	HomeOK bool `json:"home_ok"`
}

// Faixa padrão de contas humanas quando /etc/login.defs não informa.
const (
	DefaultUIDMin = 1000
	DefaultUIDMax = 60000
)

// LoginDefs lê UID_MIN e UID_MAX de /etc/login.defs.
func LoginDefs(data []byte) (uidMin, uidMax uint32) {
	uidMin, uidMax = DefaultUIDMin, DefaultUIDMax
	for l := range strings.SplitSeq(string(data), "\n") {
		f := strings.Fields(l)
		if len(f) != 2 {
			continue
		}
		n, err := strconv.ParseUint(f[1], 10, 32)
		if err != nil || n == 0 {
			continue
		}
		switch f[0] {
		case "UID_MIN":
			uidMin = uint32(n)
		case "UID_MAX":
			uidMax = uint32(n)
		}
	}
	return uidMin, uidMax
}

// Parse lê linhas no formato do passwd. Nomes repetidos (arquivo local e diretório remoto) ficam com a primeira
// ocorrência, como faz o NSS.
func Parse(passwd []byte, uidMin, uidMax uint32) []Account {
	var out []Account
	seen := map[string]bool{}
	sc := bufio.NewScanner(bytes.NewReader(passwd))
	sc.Buffer(make([]byte, 64*1024), 1024*1024)
	for sc.Scan() {
		f := strings.Split(sc.Text(), ":")
		if len(f) < 7 || f[0] == "" || seen[f[0]] || strings.HasPrefix(f[0], "+") || strings.HasPrefix(f[0], "-") {
			continue
		}
		uid, err1 := strconv.ParseUint(f[2], 10, 32)
		gid, err2 := strconv.ParseUint(f[3], 10, 32)
		if err1 != nil || err2 != nil {
			continue
		}
		seen[f[0]] = true
		a := Account{UID: uint32(uid), GID: uint32(gid), Name: f[0], Home: f[5], Shell: f[6]}
		a.System = a.UID < uidMin || a.UID > uidMax
		out = append(out, a)
	}
	return out
}

// Discover lista as contas pelo getent passwd (com o /etc/passwd como reserva) e confere os diretórios pessoais.
// Roda no executor: o core não enxerga /home (ProtectHome).
func Discover(ctx context.Context) (accts []Account, uidMin, uidMax uint32, err error) {
	defs, _ := os.ReadFile("/etc/login.defs")
	uidMin, uidMax = LoginDefs(defs)
	cctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	data, gerr := exec.CommandContext(cctx, "getent", "passwd").Output()
	if gerr != nil || len(data) == 0 {
		// Sem getent (contêiner mínimo) ou com o NSS fora do ar: só as contas locais.
		if data, err = os.ReadFile("/etc/passwd"); err != nil {
			return nil, uidMin, uidMax, err
		}
	}
	accts = Parse(data, uidMin, uidMax)
	for i := range accts {
		accts[i].HomeOK = validHome(accts[i].Home)
	}
	return accts, uidMin, uidMax, nil
}

func validHome(h string) bool {
	if h == "" || h == "/" || !filepath.IsAbs(h) {
		return false
	}
	st, err := os.Stat(h)
	return err == nil && st.IsDir()
}

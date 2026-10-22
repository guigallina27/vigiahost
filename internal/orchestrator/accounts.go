package orchestrator

import (
	"context"
	"slices"
	"strings"
	"time"

	"github.com/guigallina27/vigiahost/internal/accounts"
	"github.com/guigallina27/vigiahost/internal/ipc"
	"github.com/guigallina27/vigiahost/internal/store"
)

// SharedTempRoots são as áreas temporárias compartilhadas onde a verificação por conta pega só os arquivos do UID
// da conta (escopo, seção 9.1).
var SharedTempRoots = []string{"/tmp", "/var/tmp", "/dev/shm"}

// accountsTTL é por quanto tempo a lista de contas do executor é reaproveitada.
const accountsTTL = time.Minute

// Accounts devolve as contas do servidor informadas pelo executor (o core não enxerga /home).
func (s *Service) Accounts(ctx context.Context) (ipc.AccountList, error) {
	s.mu.Lock()
	if s.accts != nil && time.Since(s.acctsAt) < accountsTTL {
		l := *s.accts
		s.mu.Unlock()
		return l, nil
	}
	s.mu.Unlock()
	var l ipc.AccountList
	if err := s.Exec.Call(ctx, ipc.OpAccounts, nil, &l); err != nil {
		return l, err
	}
	s.mu.Lock()
	s.accts, s.acctsAt = &l, time.Now()
	s.mu.Unlock()
	return l, nil
}

// accountScope monta caminhos e filtros de dono para as contas escolhidas. "Todas" pega as contas humanas/de
// hospedagem com diretório pessoal; contas escolhidas pelo UID valem mesmo fora da faixa (ex.: um serviço com site).
func (s *Service) accountScope(ctx context.Context, sel store.AccountSelection) (uids []uint32, paths []string,
	owners map[string][]uint32, err error) {
	list, err := s.Accounts(ctx)
	if err != nil {
		return nil, nil, nil, err
	}
	byUID := map[uint32]accounts.Account{}
	for _, a := range list.Accounts {
		if _, dup := byUID[a.UID]; !dup {
			byUID[a.UID] = a
		}
	}
	var chosen []accounts.Account
	if sel.All {
		for _, a := range list.Accounts {
			if !a.System && a.HomeOK {
				chosen = append(chosen, a)
			}
		}
	} else {
		for _, uid := range sel.UIDs {
			a, ok := byUID[uid]
			if !ok {
				return nil, nil, nil, invalid("conta com UID %d não existe no servidor", uid)
			}
			if a.UID == 0 {
				return nil, nil, nil, invalid("root não é uma conta verificável por conta; use caminhos")
			}
			if !a.HomeOK {
				return nil, nil, nil, invalid("a conta %s não tem diretório pessoal válido (%s)", a.Name, a.Home)
			}
			chosen = append(chosen, a)
		}
	}
	if len(chosen) == 0 {
		return nil, nil, nil, invalid("nenhuma conta com diretório pessoal para verificar")
	}
	seen := map[string]bool{}
	for _, a := range chosen {
		if !slices.Contains(uids, a.UID) {
			uids = append(uids, a.UID)
		}
		if !seen[a.Home] {
			seen[a.Home] = true
			paths = append(paths, a.Home)
		}
	}
	slices.Sort(uids)
	paths = nestedOut(paths)
	owners = map[string][]uint32{}
	for _, t := range SharedTempRoots {
		// Diretório pessoal dentro de /tmp (raro) já cobre a área inteira; não repete a raiz.
		if seen[t] {
			continue
		}
		paths = append(paths, t)
		owners[t] = uids
	}
	return uids, paths, owners, nil
}

// nestedOut tira diretórios que já estão dentro de outro da lista (contas com diretório pessoal aninhado).
func nestedOut(paths []string) []string {
	slices.Sort(paths)
	var out []string
	for _, p := range paths {
		if n := len(out); n > 0 && (p == out[n-1] || strings.HasPrefix(p, out[n-1]+"/")) {
			continue
		}
		out = append(out, p)
	}
	return out
}

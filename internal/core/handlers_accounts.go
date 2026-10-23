package core

import (
	"context"
	"encoding/json"
	"errors"
	"math"
	"net/http"
	"path"
	"strconv"
	"time"

	"github.com/guigallina27/vigiahost/internal/accounts"
	"github.com/guigallina27/vigiahost/internal/api"
	"github.com/guigallina27/vigiahost/internal/ipc"
	"github.com/guigallina27/vigiahost/internal/store"
)

// accountView junta, por conta, o que já está no banco: achados abertos, última execução e o último inventário de
// processos e persistência (escopo, seção 9.1: atribuição sem nova leitura do disco).
type accountView struct {
	list     ipc.AccountList
	findings map[uint32]*api.SeverityCounts
	latest   map[uint32]store.Run
	procs    map[uint32]int
	pers     map[uint32]int
	invAt    *time.Time
}

func (s *Server) buildAccountView(ctx context.Context) (*accountView, error) {
	list, err := s.Orch.Accounts(ctx)
	if err != nil {
		return nil, err
	}
	v := &accountView{list: list, findings: map[uint32]*api.SeverityCounts{}}
	byName := map[string]uint32{}
	byHome := map[string]uint32{}
	known := map[uint32]bool{}
	for _, a := range list.Accounts {
		known[a.UID] = true
		byName[a.Name] = a.UID
		byName[strconv.FormatUint(uint64(a.UID), 10)] = a.UID
		// Diretório pessoal só identifica a conta quando não é compartilhado nem a raiz.
		if a.HomeOK && a.Home != "/" {
			if _, dup := byHome[a.Home]; !dup {
				byHome[a.Home] = a.UID
			}
		}
	}
	ownerOfPath := func(p string) (uint32, bool) {
		for dir := path.Dir(p); dir != "/" && dir != "."; dir = path.Dir(dir) {
			if uid, ok := byHome[dir]; ok {
				return uid, true
			}
		}
		return 0, false
	}

	refs, err := s.DB.OpenFindingRefs(ctx)
	if err != nil {
		return nil, err
	}
	for _, r := range refs {
		hit := map[uint32]bool{}
		for _, uid := range r.UIDs {
			if known[uid] {
				hit[uid] = true
			}
		}
		for _, o := range r.Owners {
			if uid, ok := byName[o]; ok {
				hit[uid] = true
			}
		}
		for _, p := range r.Paths {
			if uid, ok := ownerOfPath(p); ok {
				hit[uid] = true
			}
		}
		for uid := range hit {
			c := v.findings[uid]
			if c == nil {
				c = &api.SeverityCounts{}
				v.findings[uid] = c
			}
			addSeverity(c, r.Severity)
		}
	}

	if v.latest, err = s.DB.LatestRunsByAccount(ctx); err != nil {
		return nil, err
	}

	snap, err := s.DB.GetSnapshot(ctx, "")
	switch {
	case errors.Is(err, store.ErrNotFound):
	case err != nil:
		return nil, err
	default:
		v.invAt = &snap.TakenAt
		v.procs, v.pers = map[uint32]int{}, map[uint32]int{}
		var procs []struct {
			UID uint32 `json:"uid"`
		}
		_ = json.Unmarshal(snap.Processes, &procs)
		for _, p := range procs {
			v.procs[p.UID]++
		}
		var pers struct {
			Items []struct {
				Path   string `json:"path"`
				Owner  string `json:"owner"`
				Change string `json:"change"`
			} `json:"items"`
		}
		_ = json.Unmarshal(snap.Persistence, &pers)
		for _, it := range pers.Items {
			if it.Change == "removed" {
				continue
			}
			if uid, ok := byName[it.Owner]; ok {
				v.pers[uid]++
			} else if uid, ok := ownerOfPath(it.Path); ok {
				v.pers[uid]++
			}
		}
	}
	return v, nil
}

func addSeverity(c *api.SeverityCounts, sev string) {
	switch sev {
	case "critical":
		c.Critical++
	case "high":
		c.High++
	case "medium":
		c.Medium++
	case "low":
		c.Low++
	default:
		c.Info++
	}
	c.Total++
}

func (v *accountView) account(a accounts.Account) api.Account {
	out := api.Account{Uid: int64(a.UID), Name: a.Name, Home: a.Home, Shell: a.Shell, System: a.System, HomeOk: a.HomeOK,
		Processes: -1, PersistenceItems: -1}
	if c := v.findings[a.UID]; c != nil {
		out.OpenFindings = *c
	}
	if r, ok := v.latest[a.UID]; ok {
		out.LastRun = &api.AccountRun{Id: r.ID, Status: api.RunStatus(r.Status), CreatedAt: r.CreatedAt,
			FinishedAt: optTime(r.FinishedAt), FilesProcessed: r.FilesProcessed, FilesEligible: r.FilesEligible}
	}
	if v.procs != nil {
		out.Processes, out.PersistenceItems = v.procs[a.UID], v.pers[a.UID]
	}
	return out
}

// ListAccounts lista as contas do servidor com o resumo de risco de cada uma.
func (s *Server) ListAccounts(w http.ResponseWriter, r *http.Request, params api.ListAccountsParams) {
	v, err := s.buildAccountView(r.Context())
	if err != nil {
		s.storeError(w, err)
		return
	}
	withSystem := params.System != nil && *params.System
	out := api.AccountList{UidMin: int64(v.list.UIDMin), UidMax: int64(v.list.UIDMax), InventoryAt: v.invAt,
		Accounts: []api.Account{}}
	for _, a := range v.list.Accounts {
		if a.System && !withSystem {
			continue
		}
		out.Accounts = append(out.Accounts, v.account(a))
	}
	writeJSON(w, http.StatusOK, out)
}

// GetAccount devolve uma conta.
func (s *Server) GetAccount(w http.ResponseWriter, r *http.Request, uid int64) {
	v, err := s.buildAccountView(r.Context())
	if err != nil {
		s.storeError(w, err)
		return
	}
	for _, a := range v.list.Accounts {
		if int64(a.UID) == uid {
			writeJSON(w, http.StatusOK, v.account(a))
			return
		}
	}
	writeError(w, http.StatusNotFound, "conta não encontrada", "not_found")
}

// accountScope monta o filtro de achados de uma conta. Sem o executor, filtra só pelo UID.
func (s *Server) accountScope(ctx context.Context, uid int64) (store.AccountScope, error) {
	if uid < 0 || uid > math.MaxUint32 {
		return store.AccountScope{}, errors.New("UID fora da faixa")
	}
	sc := store.AccountScope{UID: uint32(uid), Name: strconv.FormatInt(uid, 10)}
	if list, err := s.Orch.Accounts(ctx); err == nil {
		for _, a := range list.Accounts {
			if a.UID == sc.UID {
				sc.Name = a.Name
				if a.HomeOK && a.Home != "/" {
					sc.Home = a.Home
				}
				break
			}
		}
	}
	return sc, nil
}

// selectionFrom converte a seleção de contas do contrato.
func selectionFrom(in *api.AccountSelection) (store.AccountSelection, error) {
	var sel store.AccountSelection
	if in == nil {
		return sel, nil
	}
	if in.All != nil {
		sel.All = *in.All
	}
	if in.Uids != nil {
		for _, u := range *in.Uids {
			if u < 0 || u > math.MaxUint32 {
				return sel, errors.New("UID fora da faixa")
			}
			sel.UIDs = append(sel.UIDs, uint32(u))
		}
	}
	return sel, nil
}

func toAPISelection(sel store.AccountSelection) *api.AccountSelection {
	if sel.Empty() {
		return nil
	}
	out := &api.AccountSelection{}
	if sel.All {
		out.All = ptr(true)
	}
	if len(sel.UIDs) > 0 {
		uids := make([]int64, 0, len(sel.UIDs))
		for _, u := range sel.UIDs {
			uids = append(uids, int64(u))
		}
		out.Uids = &uids
	}
	return out
}

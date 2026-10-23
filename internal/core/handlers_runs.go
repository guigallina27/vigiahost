package core

import (
	"fmt"
	"math"
	"net/http"
	"strings"

	"github.com/guigallina27/vigiahost/internal/api"
	"github.com/guigallina27/vigiahost/internal/orchestrator"
	"github.com/guigallina27/vigiahost/internal/report"
	"github.com/guigallina27/vigiahost/internal/store"
)

func limitOf(l *api.Limit) int {
	if l == nil {
		return 50
	}
	return int(*l)
}

// ListRuns lista execuções com cursor por data de criação.
func (s *Server) ListRuns(w http.ResponseWriter, r *http.Request, params api.ListRunsParams) {
	f := store.RunFilter{Limit: limitOf(params.Limit)}
	if params.Status != nil {
		for _, st := range *params.Status {
			f.Statuses = append(f.Statuses, string(st))
		}
	}
	if params.Kind != nil {
		f.Kind = string(*params.Kind)
	}
	if params.Before != nil {
		f.Before = *params.Before
	}
	if params.Account != nil {
		if *params.Account < 0 || *params.Account > math.MaxUint32 {
			writeError(w, http.StatusBadRequest, "UID fora da faixa", "bad_request")
			return
		}
		f.Account = ptr(uint32(*params.Account))
	}
	runs, err := s.DB.ListRuns(r.Context(), f)
	if err != nil {
		s.storeError(w, err)
		return
	}
	page := api.RunPage{Runs: toAPIRuns(runs)}
	if len(runs) == f.Limit && len(runs) > 0 {
		page.NextBefore = ptr(runs[len(runs)-1].CreatedAt.UTC().Format("2006-01-02T15:04:05.000000000Z"))
	}
	writeJSON(w, http.StatusOK, page)
}

// CreateRun enfileira uma execução.
func (s *Server) CreateRun(w http.ResponseWriter, r *http.Request, params api.CreateRunParams) {
	var in api.RunCreate
	if !decode(w, r, &in) {
		return
	}
	p := principalFrom(r.Context())
	req := orchestrator.RunRequest{Kind: report.Kind(in.Kind), Incremental: true, RequestedBy: p.Actor()}
	if in.Paths != nil {
		req.Paths = *in.Paths
	}
	if in.Exclude != nil {
		req.Exclude = *in.Exclude
	}
	if in.Incremental != nil {
		req.Incremental = *in.Incremental
	}
	if in.Profile != nil {
		req.Profile = *in.Profile
	}
	if in.Priority != nil {
		req.Priority = *in.Priority
	}
	sel, err := selectionFrom(in.Accounts)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error(), "bad_request")
		return
	}
	req.Accounts = sel
	if k := params.IdempotencyKey; k != nil && strings.TrimSpace(*k) != "" {
		// A chave vale por usuário: dois operadores com a mesma chave não se confundem.
		req.IdempotencyKey = fmt.Sprintf("%d:%s", p.UserID, strings.TrimSpace(*k))
	}
	run, err := s.Orch.Enqueue(r.Context(), req)
	if err != nil {
		s.storeError(w, err)
		return
	}
	detail := fmt.Sprintf("tipo %s, perfil %s, caminhos %s", run.Kind, run.Profile.Name, strings.Join(run.Paths, ", "))
	if len(run.Accounts) > 0 {
		detail = fmt.Sprintf("tipo %s, perfil %s, %d conta(s): %v", run.Kind, run.Profile.Name, len(run.Accounts), run.Accounts)
	}
	s.audit(r, "run_created", run.ID, detail)
	writeJSON(w, http.StatusCreated, toAPIRun(run))
}

// GetRun devolve a execução com a cobertura por motor.
func (s *Server) GetRun(w http.ResponseWriter, r *http.Request, runID api.RunId) {
	run, err := s.DB.GetRun(r.Context(), runID)
	if err != nil {
		s.storeError(w, err)
		return
	}
	eng, err := s.DB.RunEngines(r.Context(), runID)
	if err != nil {
		s.storeError(w, err)
		return
	}
	out := api.RunDetail{Run: toAPIRun(run), Engines: make([]api.EngineCoverage, 0, len(eng))}
	for _, e := range eng {
		out.Engines = append(out.Engines, toAPIEngine(e))
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) runAction(w http.ResponseWriter, r *http.Request, id, action string, fn func() (store.Run, error)) {
	run, err := fn()
	if err != nil {
		s.storeError(w, err)
		return
	}
	s.audit(r, action, id, "")
	writeJSON(w, http.StatusOK, toAPIRun(run))
}

// CancelRun cancela a execução.
func (s *Server) CancelRun(w http.ResponseWriter, r *http.Request, runID api.RunId) {
	s.runAction(w, r, runID, "run_canceled", func() (store.Run, error) { return s.Orch.Cancel(r.Context(), runID) })
}

// PauseRun pausa a execução.
func (s *Server) PauseRun(w http.ResponseWriter, r *http.Request, runID api.RunId) {
	s.runAction(w, r, runID, "run_paused", func() (store.Run, error) { return s.Orch.SetPaused(r.Context(), runID, true) })
}

// ResumeRun retoma a execução.
func (s *Server) ResumeRun(w http.ResponseWriter, r *http.Request, runID api.RunId) {
	s.runAction(w, r, runID, "run_resumed", func() (store.Run, error) { return s.Orch.SetPaused(r.Context(), runID, false) })
}

// SetRunLimits troca o perfil da execução em andamento.
func (s *Server) SetRunLimits(w http.ResponseWriter, r *http.Request, runID api.RunId) {
	var in api.RunLimitsRequest
	if !decode(w, r, &in) {
		return
	}
	run, err := s.Orch.SetLimits(r.Context(), runID, in.Profile, principalFrom(r.Context()).Actor())
	if err != nil {
		s.storeError(w, err)
		return
	}
	s.audit(r, "run_limits_changed", runID, "perfil "+in.Profile)
	writeJSON(w, http.StatusOK, toAPIRun(run))
}

// ListFindings lista achados com filtros e cursor.
func (s *Server) ListFindings(w http.ResponseWriter, r *http.Request, params api.ListFindingsParams) {
	f := store.FindingFilter{Limit: limitOf(params.Limit)}
	if params.State != nil {
		for _, v := range *params.State {
			f.States = append(f.States, string(v))
		}
	}
	if params.Severity != nil {
		for _, v := range *params.Severity {
			f.Severities = append(f.Severities, string(v))
		}
	}
	if params.Kind != nil {
		for _, v := range *params.Kind {
			f.Kinds = append(f.Kinds, string(v))
		}
	}
	if params.Category != nil {
		f.Categories = *params.Category
	}
	if params.Run != nil {
		f.RunID = *params.Run
	}
	if params.Q != nil {
		f.Query = *params.Q
	}
	if params.Account != nil {
		sc, err := s.accountScope(r.Context(), *params.Account)
		if err != nil {
			writeError(w, http.StatusBadRequest, err.Error(), "bad_request")
			return
		}
		f.Account = &sc
	}
	if params.Before != nil {
		f.BeforeID = *params.Before
	}
	list, err := s.DB.ListFindings(r.Context(), f)
	if err != nil {
		s.storeError(w, err)
		return
	}
	page := api.FindingPage{Findings: toAPIFindings(list)}
	if len(list) == f.Limit && len(list) > 0 {
		page.NextBefore = ptr(list[len(list)-1].ID)
	}
	writeJSON(w, http.StatusOK, page)
}

func (s *Server) findingDetail(w http.ResponseWriter, r *http.Request, id int64, code int) {
	f, err := s.DB.GetFinding(r.Context(), id)
	if err != nil {
		s.storeError(w, err)
		return
	}
	out := api.FindingDetail{Finding: toAPIFinding(f), Locations: []api.Location{}, Events: []api.FindingEvent{},
		AllowedTransitions: []api.FindingState{}}
	if f.SHA256 != "" {
		locs, err := s.DB.FindingLocations(r.Context(), f.SHA256)
		if err != nil {
			s.storeError(w, err)
			return
		}
		for _, l := range locs {
			out.Locations = append(out.Locations, toAPILocation(l))
		}
	} else if f.Location != nil {
		out.Locations = append(out.Locations, toAPILocation(*f.Location))
	}
	evs, err := s.DB.FindingEvents(r.Context(), id)
	if err != nil {
		s.storeError(w, err)
		return
	}
	for _, e := range evs {
		out.Events = append(out.Events, api.FindingEvent{At: e.At, Actor: e.Actor, Action: e.Action, From: e.From,
			To: e.To, Note: e.Note})
	}
	if p := principalFrom(r.Context()); p != nil && allowed(accessOperate, p.Role) {
		for _, t := range store.AllowedTransitions(f.State) {
			out.AllowedTransitions = append(out.AllowedTransitions, api.FindingState(t))
		}
	}
	writeJSON(w, code, out)
}

// GetFinding devolve o achado com localizações e histórico.
func (s *Server) GetFinding(w http.ResponseWriter, r *http.Request, findingID api.FindingId) {
	s.findingDetail(w, r, findingID, http.StatusOK)
}

// TransitionFinding muda o estado do achado.
func (s *Server) TransitionFinding(w http.ResponseWriter, r *http.Request, findingID api.FindingId) {
	var in api.FindingTransition
	if !decode(w, r, &in) {
		return
	}
	if !in.To.Valid() {
		writeError(w, http.StatusBadRequest, "estado inválido", "bad_request")
		return
	}
	if in.To == api.Excepted {
		writeError(w, http.StatusBadRequest, "para cobrir por exceção, crie a exceção (com motivo e validade)", "bad_request")
		return
	}
	note := ""
	if in.Note != nil {
		note = strings.TrimSpace(*in.Note)
	}
	p := principalFrom(r.Context())
	if _, err := s.DB.TransitionFinding(r.Context(), findingID, string(in.To), p.Actor(), note); err != nil {
		s.storeError(w, err)
		return
	}
	s.audit(r, "finding_transition", fmt.Sprint(findingID), string(in.To)+" "+note)
	if s.Hub != nil {
		s.Hub.Publish(orchestrator.Event{Type: "finding", ID: fmt.Sprint(findingID)})
	}
	s.findingDetail(w, r, findingID, http.StatusOK)
}

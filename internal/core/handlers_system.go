package core

import (
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/guigallina27/vigiahost/internal/api"
	"github.com/guigallina27/vigiahost/internal/inspect"
	"github.com/guigallina27/vigiahost/internal/integrity"
	"github.com/guigallina27/vigiahost/internal/report"
	"github.com/guigallina27/vigiahost/internal/store"
	"github.com/guigallina27/vigiahost/internal/updates"
)

// reportRun é uma execução com relatório guardado (para escolher a verificação anterior na tela).
type reportRun struct {
	RunID   string    `json:"run_id"`
	TakenAt time.Time `json:"taken_at"`
}

// hostReport lê o relatório guardado de uma verificação do sistema e a lista das execuções com relatório.
func (s *Server) hostReport(w http.ResponseWriter, r *http.Request, name string, runID *api.SnapshotRun, empty string) (store.HostReport, []reportRun, bool) {
	id := ""
	if runID != nil {
		id = *runID
	}
	rep, err := s.DB.GetHostReport(r.Context(), name, id)
	if err != nil {
		if id == "" && errors.Is(err, store.ErrNotFound) {
			writeError(w, http.StatusNotFound, empty, "not_found")
			return rep, nil, false
		}
		s.storeError(w, err)
		return rep, nil, false
	}
	list, err := s.DB.HostReportRuns(r.Context(), name)
	if err != nil {
		s.storeError(w, err)
		return rep, nil, false
	}
	runs := make([]reportRun, 0, len(list))
	for _, l := range list {
		runs = append(runs, reportRun{l.RunID, l.TakenAt})
	}
	return rep, runs, true
}

func nonNilSlice[T any](v []T) []T {
	if v == nil {
		return []T{}
	}
	return v
}

// GetIntegrity devolve a verificação contra os pacotes (E2.2).
func (s *Server) GetIntegrity(w http.ResponseWriter, r *http.Request, params api.GetIntegrityParams) {
	hr, runs, ok := s.hostReport(w, r, store.HostReportIntegrity, params.RunId, "nenhuma verificação de integridade concluída ainda")
	if !ok {
		return
	}
	var rep integrity.Report
	if err := json.Unmarshal(hr.Data, &rep); err != nil {
		s.Logger.Error("relatório de integridade ilegível", "execucao", hr.RunID, "erro", err)
		writeError(w, http.StatusInternalServerError, "relatório de integridade ilegível", "internal")
		return
	}
	rep.Tools, rep.Files = nonNilSlice(rep.Tools), nonNilSlice(rep.Files)
	for i := range rep.Files {
		rep.Files[i].Changes = nonNilSlice(rep.Files[i].Changes)
	}
	if rep.Ignored == nil {
		rep.Ignored = map[string]int{}
	}
	if rep.BySeverity == nil {
		rep.BySeverity = map[report.Severity]int{}
	}
	if sig := rep.Signatures; sig != nil {
		sig.Repos = nonNilSlice(sig.Repos)
	}
	writeJSON(w, http.StatusOK, struct {
		RunID   string      `json:"run_id"`
		TakenAt time.Time   `json:"taken_at"`
		Runs    []reportRun `json:"runs"`
		integrity.Report
	}{hr.RunID, hr.TakenAt, runs, rep})
}

// GetUpdates devolve correções pendentes, reinício e serviços a reiniciar (E2.4).
func (s *Server) GetUpdates(w http.ResponseWriter, r *http.Request, params api.GetUpdatesParams) {
	hr, runs, ok := s.hostReport(w, r, store.HostReportUpdates, params.RunId, "nenhuma verificação de atualizações concluída ainda")
	if !ok {
		return
	}
	var rep updates.Report
	if err := json.Unmarshal(hr.Data, &rep); err != nil {
		s.Logger.Error("relatório de atualizações ilegível", "execucao", hr.RunID, "erro", err)
		writeError(w, http.StatusInternalServerError, "relatório de atualizações ilegível", "internal")
		return
	}
	rep.Security, rep.Other = nonNilSlice(rep.Security), nonNilSlice(rep.Other)
	rep.Services, rep.Processes = nonNilSlice(rep.Services), nonNilSlice(rep.Processes)
	for i := range rep.Processes {
		rep.Processes[i].Files = nonNilSlice(rep.Processes[i].Files)
	}
	if rep.BySeverity == nil {
		rep.BySeverity = map[string]int{}
	}
	if rep.Tools == nil {
		rep.Tools = map[string]bool{}
	}
	writeJSON(w, http.StatusOK, struct {
		RunID   string      `json:"run_id"`
		TakenAt time.Time   `json:"taken_at"`
		Runs    []reportRun `json:"runs"`
		updates.Report
	}{hr.RunID, hr.TakenAt, runs, rep})
}

// hiddenReport devolve o relatório de processos e portas ocultos da inspeção, quando houver.
func (s *Server) hiddenReport(r *http.Request, runID string) *inspect.HiddenReport {
	hr, err := s.DB.GetHostReport(r.Context(), store.HostReportHidden, runID)
	if err != nil {
		return nil
	}
	var rep inspect.HiddenReport
	if json.Unmarshal(hr.Data, &rep) != nil {
		return nil
	}
	rep.Processes.Found = nonNilSlice(rep.Processes.Found)
	rep.Ports.Found = nonNilSlice(rep.Ports.Found)
	for i := range rep.Processes.Found {
		rep.Processes.Found[i].Checks = nonNilSlice(rep.Processes.Found[i].Checks)
	}
	return &rep
}

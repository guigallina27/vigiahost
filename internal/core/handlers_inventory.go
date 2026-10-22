package core

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/guigallina27/vigiahost/internal/api"
	"github.com/guigallina27/vigiahost/internal/store"
)

func (s *Server) snapshot(w http.ResponseWriter, r *http.Request, runID *api.SnapshotRun) (store.Snapshot, bool) {
	id := ""
	if runID != nil {
		id = *runID
	}
	snap, err := s.DB.GetSnapshot(r.Context(), id)
	if err != nil {
		if id == "" && errors.Is(err, store.ErrNotFound) {
			writeError(w, http.StatusNotFound, "nenhuma inspeção de processos concluída ainda", "not_found")
			return snap, false
		}
		s.storeError(w, err)
		return snap, false
	}
	return snap, true
}

// rawList devolve a lista JSON gravada pelo executor ("[]" quando vazia).
func rawList(b []byte) json.RawMessage {
	if t := bytes.TrimSpace(b); len(t) == 0 || bytes.Equal(t, []byte("null")) {
		return json.RawMessage("[]")
	}
	return b
}

// GetProcessInventory devolve os processos da inspeção (JSON gravado pelo executor, já com segredos mascarados).
func (s *Server) GetProcessInventory(w http.ResponseWriter, r *http.Request, params api.GetProcessInventoryParams) {
	snap, ok := s.snapshot(w, r, params.RunId)
	if !ok {
		return
	}
	writeJSON(w, http.StatusOK, struct {
		RunID     string          `json:"run_id"`
		TakenAt   time.Time       `json:"taken_at"`
		Processes json.RawMessage `json:"processes"`
	}{snap.RunID, snap.TakenAt, rawList(snap.Processes)})
}

// GetPersistenceInventory devolve o inventário de persistência e o que saiu desde a inspeção anterior.
func (s *Server) GetPersistenceInventory(w http.ResponseWriter, r *http.Request, params api.GetPersistenceInventoryParams) {
	snap, ok := s.snapshot(w, r, params.RunId)
	if !ok {
		return
	}
	var rep struct {
		Baseline bool            `json:"baseline"`
		Items    json.RawMessage `json:"items"`
		Removed  json.RawMessage `json:"removed"`
	}
	if err := json.Unmarshal(snap.Persistence, &rep); err != nil {
		s.Logger.Error("inventário de persistência ilegível", "execucao", snap.RunID, "erro", err)
		writeError(w, http.StatusInternalServerError, "inventário de persistência ilegível", "internal")
		return
	}
	writeJSON(w, http.StatusOK, struct {
		RunID    string          `json:"run_id"`
		TakenAt  time.Time       `json:"taken_at"`
		Baseline bool            `json:"baseline"`
		Items    json.RawMessage `json:"items"`
		Removed  json.RawMessage `json:"removed"`
	}{snap.RunID, snap.TakenAt, rep.Baseline, rawList(rep.Items), rawList(rep.Removed)})
}

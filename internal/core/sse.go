package core

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

// StreamEvents envia eventos ao vivo (SSE). Cada evento traz só tipo e identificador; a interface busca o estado
// pela API. Sem histórico: ao reconectar, a interface recarrega o que estiver na tela.
func (s *Server) StreamEvents(w http.ResponseWriter, r *http.Request) {
	if s.Hub == nil {
		writeError(w, http.StatusServiceUnavailable, "eventos indisponíveis", "unavailable")
		return
	}
	rc := http.NewResponseController(w)
	// A conexão do SSE é longa: tira o prazo de escrita do servidor só desta resposta.
	_ = rc.SetWriteDeadline(time.Time{})
	h := w.Header()
	h.Set("Content-Type", "text/event-stream")
	h.Set("Cache-Control", "no-store")
	h.Set("X-Accel-Buffering", "no")
	w.WriteHeader(http.StatusOK)

	events, cancel := s.Hub.Subscribe()
	defer cancel()
	_, _ = fmt.Fprint(w, "retry: 5000\n: conectado\n\n")
	_ = rc.Flush()

	p := principalFrom(r.Context())
	heartbeat := time.NewTicker(25 * time.Second)
	defer heartbeat.Stop()
	var seq int64
	for {
		select {
		case <-r.Context().Done():
			return
		case ev, ok := <-events:
			if !ok {
				return
			}
			seq++
			data, _ := json.Marshal(ev)
			if _, err := fmt.Fprintf(w, "id: %d\nevent: %s\ndata: %s\n\n", seq, ev.Type, data); err != nil {
				return
			}
			_ = rc.Flush()
		case <-heartbeat.C:
			// Sessão expirada ou encerrada (logout em outra aba, usuário bloqueado) fecha o fluxo.
			if p != nil && !p.APIToken {
				if _, err := s.identify(r); err != nil {
					return
				}
			}
			if _, err := fmt.Fprint(w, ": ping\n\n"); err != nil {
				return
			}
			_ = rc.Flush()
		}
	}
}

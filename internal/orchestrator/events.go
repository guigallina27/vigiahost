package orchestrator

import (
	"encoding/json"
	"sync"
)

// Event é uma notificação para a interface (SSE): mudança de execução, achado novo, saúde.
type Event struct {
	Type string          `json:"type"` // run, finding, schedule
	ID   string          `json:"id,omitempty"`
	Data json.RawMessage `json:"data,omitempty"`
}

// Hub distribui eventos aos assinantes sem bloquear quem publica: assinante lento perde eventos e a interface
// recarrega pelo estado da API.
type Hub struct {
	mu   sync.Mutex
	subs map[chan Event]struct{}
}

// NewHub cria o distribuidor.
func NewHub() *Hub { return &Hub{subs: map[chan Event]struct{}{}} }

// Subscribe devolve o canal de eventos e a função para cancelar a assinatura.
func (h *Hub) Subscribe() (<-chan Event, func()) {
	ch := make(chan Event, 64)
	h.mu.Lock()
	h.subs[ch] = struct{}{}
	h.mu.Unlock()
	return ch, func() {
		h.mu.Lock()
		if _, ok := h.subs[ch]; ok {
			delete(h.subs, ch)
			close(ch)
		}
		h.mu.Unlock()
	}
}

// Publish envia o evento a todos os assinantes.
func (h *Hub) Publish(ev Event) {
	h.mu.Lock()
	defer h.mu.Unlock()
	for ch := range h.subs {
		select {
		case ch <- ev:
		default:
		}
	}
}

// Subscribers conta os assinantes (diagnóstico e testes).
func (h *Hub) Subscribers() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return len(h.subs)
}

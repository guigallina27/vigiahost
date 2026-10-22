// Package core implementa o serviço web sem privilégios: API, interface e orquestração.
// Tudo que exige root passa pelo executor (pacote ipc).
package core

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"time"

	"github.com/guigallina27/vigiahost/internal/ipc"
	"github.com/guigallina27/vigiahost/internal/sysinfo"
)

// ExecutorStatus resume a conexão com o executor para a API e o diagnóstico.
type ExecutorStatus struct {
	Connected bool                  `json:"connected"`
	Version   string                `json:"version,omitempty"`
	Protocol  string                `json:"protocol,omitempty"`
	Error     string                `json:"error,omitempty"`
	System    *sysinfo.Capabilities `json:"system,omitempty"`
}

// ExecutorProbe consulta o executor; é uma função para os testes poderem simular as respostas.
type ExecutorProbe func(ctx context.Context) ExecutorStatus

// ProbeExecutor conecta ao socket, faz o handshake e pede as capacidades do sistema.
func ProbeExecutor(socketPath string, local ipc.Hello) ExecutorProbe {
	return func(ctx context.Context) ExecutorStatus {
		c, err := ipc.Dial(ctx, socketPath, local)
		if err != nil {
			return ExecutorStatus{Error: err.Error()}
		}
		defer c.Close()
		st := ExecutorStatus{Connected: true, Version: c.Remote.Version, Protocol: c.Remote.Protocol()}
		var caps sysinfo.Capabilities
		if err := c.Call(ctx, ipc.OpCapabilities, nil, &caps); err != nil {
			st.Error = err.Error()
		} else {
			st.System = &caps
		}
		return st
	}
}

type Server struct {
	Logger  *slog.Logger
	Version string
	Probe   ExecutorProbe
}

type healthResponse struct {
	Status   string         `json:"status"`
	Version  string         `json:"version"`
	Executor ExecutorStatus `json:"executor"`
}

// Handler monta as rotas com os cabeçalhos de segurança e a proteção contra requisições de outra origem.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/v1/health", s.health)
	return securityHeaders(http.NewCrossOriginProtection().Handler(mux))
}

func (s *Server) health(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
	defer cancel()
	resp := healthResponse{Status: "ok", Version: s.Version, Executor: s.Probe(ctx)}
	code := http.StatusOK
	if !resp.Executor.Connected {
		resp.Status = "degraded"
		code = http.StatusServiceUnavailable
	}
	writeJSON(w, code, resp)
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Content-Security-Policy", "default-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'; object-src 'none'")
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Cross-Origin-Opener-Policy", "same-origin")
		h.Set("Cache-Control", "no-store")
		next.ServeHTTP(w, r)
	})
}

// NewHTTPServer aplica limites de tempo e de cabeçalho para não deixar conexões lentas presas.
func NewHTTPServer(addr string, h http.Handler, logger *slog.Logger) *http.Server {
	return &http.Server{
		Addr:              addr,
		Handler:           h,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       120 * time.Second,
		MaxHeaderBytes:    64 << 10,
		ErrorLog:          slog.NewLogLogger(logger.Handler(), slog.LevelWarn),
	}
}

// Package core implementa o serviço web sem privilégios: API, interface e orquestração.
// Tudo que exige root passa pelo executor (pacote ipc).
package core

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/guigallina27/vigiahost/internal/api"
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

// Server implementa api.ServerInterface, gerada de api/openapi.yaml.
type Server struct {
	Logger  *slog.Logger
	Version string
	Probe   ExecutorProbe
	// UI serve a interface embarcada; nil deixa só a API.
	UI http.Handler
}

var _ api.ServerInterface = (*Server)(nil)

// Handler monta as rotas com os cabeçalhos de segurança e a proteção contra requisições de outra origem.
// A interface fica em "GET /" para que métodos errados nas rotas da API continuem recebendo 405.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	api.HandlerFromMux(s, mux)
	mux.HandleFunc("GET /", s.fallback)
	return securityHeaders(http.NewCrossOriginProtection().Handler(mux))
}

// fallback responde JSON para rotas inexistentes da API e entrega o resto à interface.
func (s *Server) fallback(w http.ResponseWriter, r *http.Request) {
	if s.UI == nil || r.URL.Path == "/api" || strings.HasPrefix(r.URL.Path, "/api/") {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "rota não encontrada"})
		return
	}
	s.UI.ServeHTTP(w, r)
}

// GetHealth responde 200 com o executor conectado e 503 sem ele; o corpo é o mesmo nos dois casos.
func (s *Server) GetHealth(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
	defer cancel()
	resp := api.Health{Status: api.Ok, Version: s.Version, Executor: toAPIStatus(s.Probe(ctx))}
	code := http.StatusOK
	if !resp.Executor.Connected {
		resp.Status = api.Degraded
		code = http.StatusServiceUnavailable
	}
	writeJSON(w, code, resp)
}

func toAPIStatus(st ExecutorStatus) api.ExecutorStatus {
	out := api.ExecutorStatus{Connected: st.Connected, Version: optional(st.Version), Protocol: optional(st.Protocol), Error: optional(st.Error)}
	if c := st.System; c != nil {
		out.System = &api.SystemCapabilities{
			DistroId: c.DistroID, DistroVersion: c.DistroVersion, DistroName: c.DistroName,
			Kernel: c.Kernel, Arch: c.Arch, Systemd: c.Systemd, CgroupV2: c.CgroupV2, Psi: c.PSI,
		}
		if len(c.DistroLike) > 0 {
			like := c.DistroLike
			out.System.DistroLike = &like
		}
	}
	return out
}

func optional(v string) *string {
	if v == "" {
		return nil
	}
	return &v
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		// Sem 'unsafe-inline': a interface não usa script nem estilo embutido no HTML.
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

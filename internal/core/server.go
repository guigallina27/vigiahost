// Package core implementa o serviço web sem privilégios: API, interface e orquestração.
// Tudo que exige root passa pelo executor (pacote ipc).
package core

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/guigallina27/vigiahost/internal/api"
	"github.com/guigallina27/vigiahost/internal/auth"
	"github.com/guigallina27/vigiahost/internal/ipc"
	"github.com/guigallina27/vigiahost/internal/orchestrator"
	"github.com/guigallina27/vigiahost/internal/store"
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

	DB   *store.DB
	Auth *auth.Service
	Orch *orchestrator.Service
	Hub  *orchestrator.Hub
	// Exec atende consultas diretas ao executor (saúde dos motores).
	Exec orchestrator.Executor
	// TrustProxy aceita X-Forwarded-Proto/For de um proxy reverso no endereço local.
	TrustProxy bool
	// HSTS só com certificado válido (autoassinado com HSTS impediria aceitar a exceção no navegador).
	HSTS bool
	// FirstAccessFile guarda o token de primeiro acesso (lido pelo root com "vigiahost first-access"); é apagado
	// quando o primeiro administrador é criado.
	FirstAccessFile string

	engMu    sync.Mutex
	engCache *engineCache
}

var _ api.ServerInterface = (*Server)(nil)

func (s *Server) now() time.Time {
	if s.DB != nil {
		return s.DB.Now()
	}
	return time.Now().UTC()
}

// Handler monta as rotas com os cabeçalhos de segurança, a proteção contra requisições de outra origem e a matriz
// de autorização. A interface fica em "GET /" para que métodos errados nas rotas da API continuem recebendo 405.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	api.HandlerWithOptions(s, api.StdHTTPServerOptions{
		BaseRouter:       mux,
		Middlewares:      []api.MiddlewareFunc{s.authorize},
		ErrorHandlerFunc: s.paramError,
	})
	mux.HandleFunc("GET /", s.fallback)
	return securityHeaders(http.NewCrossOriginProtection().Handler(mux), s.HSTS)
}

// paramError responde a parâmetro inválido; sem sessão em rota protegida, responde 401 antes de explicar o parâmetro.
func (s *Server) paramError(w http.ResponseWriter, r *http.Request, err error) {
	if rl, ok := routes[r.Pattern]; ok && rl.access != accessPublic && s.Auth != nil {
		if _, aerr := s.identify(r); aerr != nil {
			writeError(w, http.StatusUnauthorized, "faça login para continuar", "unauthorized")
			return
		}
	}
	writeError(w, http.StatusBadRequest, "parâmetro inválido: "+err.Error(), "bad_request")
}

// fallback responde JSON para rotas inexistentes da API e entrega o resto à interface.
func (s *Server) fallback(w http.ResponseWriter, r *http.Request) {
	if s.UI == nil || r.URL.Path == "/api" || strings.HasPrefix(r.URL.Path, "/api/") {
		writeError(w, http.StatusNotFound, "rota não encontrada", "not_found")
		return
	}
	s.UI.ServeHTTP(w, r)
}

// GetHealth responde 200 com o executor conectado e 503 sem ele; o corpo é o mesmo nos dois casos.
func (s *Server) GetHealth(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
	defer cancel()
	resp := api.Health{Status: api.HealthStatusOk, Version: s.Version, Executor: toAPIStatus(s.Probe(ctx))}
	code := http.StatusOK
	if !resp.Executor.Connected {
		resp.Status = api.HealthStatusDegraded
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

func writeError(w http.ResponseWriter, code int, msg, errCode string) {
	e := api.Error{Error: msg}
	if errCode != "" {
		e.Code = &errCode
	}
	writeJSON(w, code, e)
}

// decode lê o corpo JSON com limite de tamanho e recusa campos desconhecidos (o contrato tem
// additionalProperties: false).
func decode(w http.ResponseWriter, r *http.Request, v any) bool {
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		writeError(w, http.StatusBadRequest, "corpo inválido: "+err.Error(), "bad_request")
		return false
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		writeError(w, http.StatusBadRequest, "corpo inválido: conteúdo depois do objeto JSON", "bad_request")
		return false
	}
	return true
}

// storeError traduz erros da camada de dados e do orquestrador para HTTP.
func (s *Server) storeError(w http.ResponseWriter, err error) {
	var ie *ipc.Error
	switch {
	case errors.Is(err, store.ErrNotFound):
		writeError(w, http.StatusNotFound, "não encontrado", "not_found")
	case errors.Is(err, store.ErrConflict):
		writeError(w, http.StatusConflict, "o estado atual não permite esta operação", "conflict")
	case errors.Is(err, store.ErrDuplicate):
		writeError(w, http.StatusConflict, "registro já existe", "duplicate")
	case errors.Is(err, orchestrator.ErrInvalid):
		writeError(w, http.StatusBadRequest, err.Error(), "bad_request")
	case orchestrator.IsUnavailable(err):
		writeError(w, http.StatusServiceUnavailable, "executor indisponível; tente de novo em instantes", "executor_unavailable")
	case errors.As(err, &ie):
		code := http.StatusBadGateway
		switch ie.Code {
		case ipc.CodeNotFound:
			code = http.StatusConflict
		case ipc.CodeLimitRefused, ipc.CodePathRefused, ipc.CodeBadRequest:
			code = http.StatusBadRequest
		case ipc.CodeUnsupported:
			code = http.StatusConflict
		}
		writeError(w, code, "executor: "+ie.Message, ie.Code)
	default:
		s.Logger.Error("erro interno na API", "erro", err)
		writeError(w, http.StatusInternalServerError, "erro interno; detalhes no journal do serviço", "internal")
	}
}

// audit registra uma ação de quem fez a requisição.
func (s *Server) audit(r *http.Request, action, target, detail string) {
	p := principalFrom(r.Context())
	actor := "anônimo"
	if p != nil {
		actor = p.Actor()
	}
	if err := s.DB.Audit(r.Context(), actor, action, target, detail, s.clientIP(r)); err != nil {
		s.Logger.Error("falha ao gravar auditoria", "acao", action, "erro", err)
	}
}

func securityHeaders(next http.Handler, hsts bool) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		// Sem 'unsafe-inline': a interface não usa script nem estilo embutido no HTML.
		h.Set("Content-Security-Policy", "default-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'; object-src 'none'")
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Cross-Origin-Opener-Policy", "same-origin")
		h.Set("Cache-Control", "no-store")
		if hsts && r.TLS != nil {
			h.Set("Strict-Transport-Security", "max-age=31536000")
		}
		next.ServeHTTP(w, r)
	})
}

// NewHTTPServer aplica limites de tempo e de cabeçalho para não deixar conexões lentas presas. O SSE estende o
// prazo de escrita da própria conexão.
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

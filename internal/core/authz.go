package core

import (
	"context"
	"errors"
	"net"
	"net/http"
	"strings"

	"github.com/guigallina27/vigiahost/internal/auth"
	"github.com/guigallina27/vigiahost/internal/store"
)

// Nome do cookie: o prefixo __Host- obriga Secure, Path=/ e ausência de Domain (ADR-016).
const sessionCookie = "__Host-vh_session"

// Níveis de acesso por rota.
type access int

const (
	accessPublic  access = iota // sem sessão (o handler confere a etapa quando precisa)
	accessView                  // qualquer perfil com sessão completa
	accessOperate               // administrador e operador
	accessAdmin                 // só administrador
	accessAudit                 // administrador e auditor
)

type rule struct {
	access access
	reauth bool // exige reautenticação recente (sessão; tokens de API não reautenticam e são recusados)
}

// routes é a matriz de autorização. Rota sem entrada é negada (falha fechada) e o teste da matriz confere que todas
// as rotas do contrato estão aqui.
var routes = map[string]rule{
	"GET /api/v1/health":                           {access: accessPublic},
	"GET /api/v1/auth/session":                     {access: accessPublic},
	"POST /api/v1/auth/login":                      {access: accessPublic},
	"POST /api/v1/auth/logout":                     {access: accessPublic},
	"POST /api/v1/auth/setup":                      {access: accessPublic},
	"POST /api/v1/auth/reset":                      {access: accessPublic},
	"POST /api/v1/auth/mfa/verify":                 {access: accessPublic},
	"POST /api/v1/auth/mfa/setup":                  {access: accessPublic},
	"POST /api/v1/auth/mfa/enable":                 {access: accessPublic},
	"POST /api/v1/auth/reauth":                     {access: accessView},
	"POST /api/v1/auth/password":                   {access: accessView},
	"GET /api/v1/overview":                         {access: accessView},
	"GET /api/v1/events":                           {access: accessView},
	"GET /api/v1/runs":                             {access: accessView},
	"POST /api/v1/runs":                            {access: accessOperate},
	"GET /api/v1/runs/{runId}":                     {access: accessView},
	"POST /api/v1/runs/{runId}/cancel":             {access: accessOperate},
	"POST /api/v1/runs/{runId}/pause":              {access: accessOperate},
	"POST /api/v1/runs/{runId}/resume":             {access: accessOperate},
	"POST /api/v1/runs/{runId}/limits":             {access: accessOperate},
	"GET /api/v1/findings":                         {access: accessView},
	"GET /api/v1/findings/{findingId}":             {access: accessView},
	"POST /api/v1/findings/{findingId}/transition": {access: accessOperate},
	"GET /api/v1/exceptions":                       {access: accessView},
	"POST /api/v1/exceptions":                      {access: accessOperate, reauth: true},
	"DELETE /api/v1/exceptions/{id}":               {access: accessOperate, reauth: true},
	"GET /api/v1/schedules":                        {access: accessView},
	"POST /api/v1/schedules":                       {access: accessOperate},
	"POST /api/v1/schedules/preview":               {access: accessView},
	"PUT /api/v1/schedules/{id}":                   {access: accessOperate},
	"DELETE /api/v1/schedules/{id}":                {access: accessOperate},
	"GET /api/v1/resources":                        {access: accessView},
	"PUT /api/v1/resources/profiles/{name}":        {access: accessAdmin, reauth: true},
	"DELETE /api/v1/resources/profiles/{name}":     {access: accessAdmin, reauth: true},
	"GET /api/v1/engines":                          {access: accessView},
	"GET /api/v1/users":                            {access: accessAdmin},
	"POST /api/v1/users":                           {access: accessAdmin, reauth: true},
	"PATCH /api/v1/users/{id}":                     {access: accessAdmin, reauth: true},
	"DELETE /api/v1/users/{id}":                    {access: accessAdmin, reauth: true},
	"POST /api/v1/users/{id}/mfa-reset":            {access: accessAdmin, reauth: true},
	"GET /api/v1/tokens":                           {access: accessView},
	"POST /api/v1/tokens":                          {access: accessView, reauth: true},
	"DELETE /api/v1/tokens/{id}":                   {access: accessView},
	"GET /api/v1/audit":                            {access: accessAudit},
}

func allowed(a access, role string) bool {
	switch a {
	case accessPublic, accessView:
		return true
	case accessOperate:
		return role == store.RoleAdmin || role == store.RoleOperator
	case accessAdmin:
		return role == store.RoleAdmin
	case accessAudit:
		return role == store.RoleAdmin || role == store.RoleAuditor
	}
	return false
}

type principalKey struct{}

// principalFrom devolve quem fez a requisição (nil em rota pública sem sessão).
func principalFrom(ctx context.Context) *auth.Principal {
	p, _ := ctx.Value(principalKey{}).(*auth.Principal)
	return p
}

// authorize é o middleware de todas as rotas da API: identifica a sessão ou o token e aplica a matriz.
func (s *Server) authorize(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rl, ok := routes[r.Pattern]
		if !ok {
			writeError(w, http.StatusForbidden, "rota sem regra de acesso", "forbidden")
			return
		}
		if s.Auth == nil {
			if rl.access != accessPublic {
				writeError(w, http.StatusServiceUnavailable, "autenticação indisponível", "unavailable")
				return
			}
			next.ServeHTTP(w, r)
			return
		}
		p, err := s.identify(r)
		if rl.access == accessPublic {
			if err == nil {
				r = r.WithContext(context.WithValue(r.Context(), principalKey{}, &p))
			}
			next.ServeHTTP(w, r)
			return
		}
		if err != nil {
			writeError(w, http.StatusUnauthorized, "faça login para continuar", "unauthorized")
			return
		}
		if p.Stage != store.StageFull {
			code := "mfa_required"
			if p.Stage == store.StageMFASetup {
				code = "mfa_setup_required"
			}
			writeError(w, http.StatusUnauthorized, "conclua o segundo fator para continuar", code)
			return
		}
		if !allowed(rl.access, p.Role) {
			writeError(w, http.StatusForbidden, "seu perfil não permite esta ação", "forbidden")
			return
		}
		if rl.reauth && (p.APIToken || !p.Reauthenticated(s.now())) {
			if p.APIToken {
				writeError(w, http.StatusForbidden, "esta ação exige sessão interativa com reautenticação", "interactive_required")
				return
			}
			writeError(w, http.StatusForbidden, "confirme sua senha para continuar", "reauth_required")
			return
		}
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), principalKey{}, &p)))
	})
}

// identify lê o token de API (Authorization: Bearer) ou o cookie de sessão.
func (s *Server) identify(r *http.Request) (auth.Principal, error) {
	var bearer, cookie string
	if h := r.Header.Get("Authorization"); h != "" {
		if v, ok := strings.CutPrefix(h, "Bearer "); ok {
			bearer = strings.TrimSpace(v)
		} else {
			return auth.Principal{}, errors.New("esquema de autorização não suportado")
		}
	} else if c, err := r.Cookie(sessionCookie); err == nil {
		cookie = c.Value
	}
	p, err := s.Auth.Authenticate(r.Context(), cookie, bearer)
	if err == nil {
		p.IP = s.clientIP(r)
	}
	return p, err
}

// secureTransport: HTTPS ou acesso pelo endereço local (túnel SSH). Os navegadores aceitam cookie Secure em
// localhost sem TLS; fora disso, o login é recusado para não trafegar a sessão em texto puro.
func (s *Server) secureTransport(r *http.Request) bool {
	if r.TLS != nil {
		return true
	}
	if s.TrustProxy && isLoopbackAddr(r.RemoteAddr) && strings.EqualFold(r.Header.Get("X-Forwarded-Proto"), "https") {
		return true
	}
	host := r.Host
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	host = strings.Trim(host, "[]")
	if host == "localhost" || strings.HasSuffix(host, ".localhost") {
		return isLoopbackAddr(r.RemoteAddr)
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback() && isLoopbackAddr(r.RemoteAddr)
}

func isLoopbackAddr(addr string) bool {
	h, _, err := net.SplitHostPort(addr)
	if err != nil {
		h = addr
	}
	ip := net.ParseIP(h)
	return ip != nil && ip.IsLoopback()
}

// clientIP é o endereço usado no bloqueio progressivo e na auditoria. Atrás de proxy confiável (só no endereço
// local), usa o último salto do X-Forwarded-For.
func (s *Server) clientIP(r *http.Request) string {
	h, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		h = r.RemoteAddr
	}
	if s.TrustProxy && isLoopbackAddr(r.RemoteAddr) {
		if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
			parts := strings.Split(xff, ",")
			if ip := net.ParseIP(strings.TrimSpace(parts[len(parts)-1])); ip != nil {
				return ip.String()
			}
		}
	}
	return h
}

func (s *Server) setSessionCookie(w http.ResponseWriter, token string) {
	http.SetCookie(w, &http.Cookie{Name: sessionCookie, Value: token, Path: "/", Secure: true, HttpOnly: true,
		SameSite: http.SameSiteStrictMode, MaxAge: 24 * 3600})
}

func clearSessionCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{Name: sessionCookie, Value: "", Path: "/", Secure: true, HttpOnly: true,
		SameSite: http.SameSiteStrictMode, MaxAge: -1})
}

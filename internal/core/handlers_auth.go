package core

import (
	"errors"
	"net/http"
	"time"

	"github.com/guigallina27/vigiahost/internal/api"
	"github.com/guigallina27/vigiahost/internal/auth"
	"github.com/guigallina27/vigiahost/internal/store"
)

// sessionView monta a resposta de sessão para a interface.
func (s *Server) sessionView(r *http.Request, p *auth.Principal) api.Session {
	out := api.Session{SecureTransport: s.secureTransport(r)}
	if n, err := s.DB.CountUsers(r.Context()); err == nil {
		out.SetupRequired = n == 0
	}
	if p == nil || p.APIToken {
		return out
	}
	out.Authenticated = p.Stage == store.StageFull
	out.Stage = ptr(api.SessionStage(p.Stage))
	out.ReauthUntil = optTime(p.ReauthUntil)
	idle := int(s.Auth.Config.Idle / time.Second)
	if idle == 0 {
		idle = 30 * 60
	}
	out.IdleTimeoutSeconds = &idle
	u := api.CurrentUser{Id: p.UserID, Username: p.Username, DisplayName: p.DisplayName, Role: api.Role(p.Role),
		MfaEnabled: p.MFAEnabled, MfaRequired: ptr(s.Auth.MFARequired(p.Role))}
	if p.MFAEnabled {
		if n, err := s.DB.RecoveryCodesLeft(r.Context(), p.UserID); err == nil {
			u.RecoveryCodesLeft = &n
		}
	}
	out.User = &u
	return out
}

// authError traduz os erros de autenticação.
func (s *Server) authError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, auth.ErrLocked):
		w.Header().Set("Retry-After", "900")
		writeError(w, http.StatusTooManyRequests, err.Error(), "locked")
	case errors.Is(err, auth.ErrBadCredentials), errors.Is(err, auth.ErrBadToken), errors.Is(err, auth.ErrBadCode):
		writeError(w, http.StatusUnauthorized, err.Error(), "invalid_credentials")
	case errors.Is(err, auth.ErrUnauthorized):
		writeError(w, http.StatusUnauthorized, err.Error(), "unauthorized")
	case errors.Is(err, auth.ErrStage):
		writeError(w, http.StatusConflict, err.Error(), "wrong_stage")
	case errors.Is(err, auth.ErrWeakPassword):
		writeError(w, http.StatusBadRequest, err.Error(), "weak_password")
	case errors.Is(err, store.ErrConflict):
		writeError(w, http.StatusConflict, "o primeiro acesso já foi concluído", "conflict")
	default:
		var msg string
		if err != nil {
			msg = err.Error()
		}
		// Validações (nome de usuário etc.) chegam como erro simples.
		if msg != "" && !errors.Is(err, store.ErrNotFound) {
			writeError(w, http.StatusBadRequest, msg, "bad_request")
			return
		}
		s.storeError(w, err)
	}
}

func (s *Server) requireSecure(w http.ResponseWriter, r *http.Request) bool {
	if !s.secureTransport(r) {
		writeError(w, http.StatusBadRequest,
			"acesse o painel por HTTPS ou pelo túnel SSH (endereço local) para fazer login", "insecure_transport")
		return false
	}
	return true
}

// GetAuthChallenge emite o desafio do widget "não sou um robô".
func (s *Server) GetAuthChallenge(w http.ResponseWriter, _ *http.Request) {
	if s.Captcha == nil {
		writeError(w, http.StatusServiceUnavailable, "verificação \"não sou um robô\" indisponível", "unavailable")
		return
	}
	ch, err := s.Captcha.Challenge()
	if err != nil {
		s.Logger.Error("desafio ALTCHA não emitido", "erro", err)
		writeError(w, http.StatusInternalServerError, "falha ao gerar a verificação", "internal")
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, ch)
}

// checkCaptcha confere o payload do widget antes de qualquer verificação de senha ou token.
func (s *Server) checkCaptcha(w http.ResponseWriter, payload string) bool {
	if s.Captcha == nil {
		writeError(w, http.StatusServiceUnavailable, "verificação \"não sou um robô\" indisponível", "unavailable")
		return false
	}
	if err := s.Captcha.Verify(payload); err != nil {
		code := "captcha_failed"
		if errors.Is(err, auth.ErrCaptchaExpired) {
			code = "captcha_expired"
		}
		writeError(w, http.StatusBadRequest, err.Error(), code)
		return false
	}
	return true
}

// GetSession informa o estado da sessão (também usado para saber se falta o primeiro acesso).
func (s *Server) GetSession(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, s.sessionView(r, principalFrom(r.Context())))
}

// Login confere usuário e senha.
func (s *Server) Login(w http.ResponseWriter, r *http.Request) {
	var in api.LoginRequest
	if !decode(w, r, &in) || !s.requireSecure(w, r) || !s.checkCaptcha(w, in.Altcha) {
		return
	}
	tok, p, err := s.Auth.Login(r.Context(), in.Username, in.Password, s.clientIP(r), r.UserAgent())
	if err != nil {
		s.authError(w, err)
		return
	}
	s.setSessionCookie(w, tok)
	writeJSON(w, http.StatusOK, s.sessionView(r, &p))
}

// VerifyMfa completa o login com o segundo fator.
func (s *Server) VerifyMfa(w http.ResponseWriter, r *http.Request) {
	var in api.CodeRequest
	if !decode(w, r, &in) {
		return
	}
	p := principalFrom(r.Context())
	if p == nil {
		writeError(w, http.StatusUnauthorized, "sessão expirada; faça login de novo", "unauthorized")
		return
	}
	tok, np, err := s.Auth.VerifyMFA(r.Context(), *p, in.Code, s.clientIP(r), r.UserAgent())
	if err != nil {
		s.authError(w, err)
		return
	}
	s.setSessionCookie(w, tok)
	writeJSON(w, http.StatusOK, s.sessionView(r, &np))
}

// BeginMfaSetup gera o segredo do aplicativo autenticador.
func (s *Server) BeginMfaSetup(w http.ResponseWriter, r *http.Request) {
	p := principalFrom(r.Context())
	if p == nil {
		writeError(w, http.StatusUnauthorized, "sessão expirada; faça login de novo", "unauthorized")
		return
	}
	setup, err := s.Auth.BeginMFASetup(r.Context(), *p)
	if err != nil {
		s.authError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, api.MfaSetup{Secret: setup.Secret, Uri: setup.URI, Matrix: setup.Matrix})
}

// EnableMfa confirma o segundo fator e devolve os códigos de recuperação.
func (s *Server) EnableMfa(w http.ResponseWriter, r *http.Request) {
	var in api.CodeRequest
	if !decode(w, r, &in) {
		return
	}
	p := principalFrom(r.Context())
	if p == nil {
		writeError(w, http.StatusUnauthorized, "sessão expirada; faça login de novo", "unauthorized")
		return
	}
	tok, np, codes, err := s.Auth.EnableMFA(r.Context(), *p, in.Code, s.clientIP(r), r.UserAgent())
	if err != nil {
		s.authError(w, err)
		return
	}
	s.setSessionCookie(w, tok)
	writeJSON(w, http.StatusOK, api.MfaEnabled{Session: s.sessionView(r, &np), RecoveryCodes: codes})
}

// Logout encerra a sessão.
func (s *Server) Logout(w http.ResponseWriter, r *http.Request) {
	if p := principalFrom(r.Context()); p != nil && !p.APIToken {
		_ = s.Auth.Logout(r.Context(), *p)
	}
	clearSessionCookie(w)
	w.WriteHeader(http.StatusNoContent)
}

// Reauth confirma a identidade para ações sensíveis.
func (s *Server) Reauth(w http.ResponseWriter, r *http.Request) {
	var in api.ReauthRequest
	if !decode(w, r, &in) {
		return
	}
	p := principalFrom(r.Context())
	code := ""
	if in.Code != nil {
		code = *in.Code
	}
	tok, np, err := s.Auth.Reauth(r.Context(), *p, in.Password, code, s.clientIP(r), r.UserAgent())
	if err != nil {
		s.authError(w, err)
		return
	}
	s.setSessionCookie(w, tok)
	writeJSON(w, http.StatusOK, s.sessionView(r, &np))
}

// ChangePassword troca a própria senha.
func (s *Server) ChangePassword(w http.ResponseWriter, r *http.Request) {
	var in api.PasswordChange
	if !decode(w, r, &in) {
		return
	}
	if err := s.Auth.ChangePassword(r.Context(), *principalFrom(r.Context()), in.Current, in.New); err != nil {
		s.authError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// SetupFirstAdmin cria o primeiro administrador com o token do terminal.
func (s *Server) SetupFirstAdmin(w http.ResponseWriter, r *http.Request) {
	var in api.SetupRequest
	if !decode(w, r, &in) || !s.requireSecure(w, r) || !s.checkCaptcha(w, in.Altcha) {
		return
	}
	display := ""
	if in.DisplayName != nil {
		display = *in.DisplayName
	}
	tok, p, err := s.Auth.Setup(r.Context(), in.Token, in.Username, display, in.Password, s.clientIP(r), r.UserAgent())
	if err != nil {
		s.authError(w, err)
		return
	}
	s.setSessionCookie(w, tok)
	s.removeFirstAccessFile()
	writeJSON(w, http.StatusOK, s.sessionView(r, &p))
}

// ResetWithToken redefine a senha com o token de recuperação.
func (s *Server) ResetWithToken(w http.ResponseWriter, r *http.Request) {
	var in api.ResetRequest
	if !decode(w, r, &in) || !s.requireSecure(w, r) || !s.checkCaptcha(w, in.Altcha) {
		return
	}
	if err := s.Auth.ResetWithToken(r.Context(), in.Token, in.Password, s.clientIP(r)); err != nil {
		s.authError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

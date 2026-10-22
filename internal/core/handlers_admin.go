package core

import (
	"errors"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/guigallina27/vigiahost/internal/api"
	"github.com/guigallina27/vigiahost/internal/auth"
	"github.com/guigallina27/vigiahost/internal/store"
)

// ListUsers lista usuários.
func (s *Server) ListUsers(w http.ResponseWriter, r *http.Request) {
	list, err := s.DB.ListUsers(r.Context())
	if err != nil {
		s.storeError(w, err)
		return
	}
	out := make([]api.User, 0, len(list))
	for _, u := range list {
		out = append(out, toAPIUser(u))
	}
	writeJSON(w, http.StatusOK, out)
}

// CreateUser cria usuário com senha inicial; o segundo fator é configurado no primeiro login.
func (s *Server) CreateUser(w http.ResponseWriter, r *http.Request) {
	var in api.UserCreate
	if !decode(w, r, &in) {
		return
	}
	in.Username = strings.TrimSpace(in.Username)
	if err := auth.CheckUsername(in.Username); err != nil {
		writeError(w, http.StatusBadRequest, err.Error(), "bad_request")
		return
	}
	if !store.ValidRole(string(in.Role)) {
		writeError(w, http.StatusBadRequest, "perfil inválido", "bad_request")
		return
	}
	if err := auth.CheckPassword(in.Password); err != nil {
		writeError(w, http.StatusBadRequest, err.Error(), "weak_password")
		return
	}
	h, err := auth.HashPassword(in.Password)
	if err != nil {
		s.storeError(w, err)
		return
	}
	u := store.User{Username: in.Username, Role: string(in.Role), PasswordHash: h}
	if in.DisplayName != nil {
		u.DisplayName = strings.TrimSpace(*in.DisplayName)
	}
	if err := s.DB.CreateUser(r.Context(), &u); err != nil {
		if errors.Is(err, store.ErrDuplicate) {
			writeError(w, http.StatusConflict, "já existe um usuário com esse nome", "duplicate")
			return
		}
		s.storeError(w, err)
		return
	}
	s.audit(r, "user_created", u.Username, "perfil "+u.Role)
	writeJSON(w, http.StatusCreated, toAPIUser(u))
}

// lastAdminGuard impede deixar o painel sem administrador habilitado.
func (s *Server) lastAdminGuard(w http.ResponseWriter, r *http.Request, u store.User) bool {
	if u.Role != store.RoleAdmin || u.Disabled {
		return true
	}
	n, err := s.DB.CountActiveAdmins(r.Context())
	if err != nil {
		s.storeError(w, err)
		return false
	}
	if n <= 1 {
		writeError(w, http.StatusConflict, "é o único administrador habilitado; crie outro antes", "last_admin")
		return false
	}
	return true
}

// UpdateUser altera nome, perfil ou bloqueio.
func (s *Server) UpdateUser(w http.ResponseWriter, r *http.Request, id api.Id) {
	var in api.UserUpdate
	if !decode(w, r, &in) {
		return
	}
	u, err := s.DB.GetUser(r.Context(), id)
	if err != nil {
		s.storeError(w, err)
		return
	}
	next := u
	if in.DisplayName != nil {
		next.DisplayName = strings.TrimSpace(*in.DisplayName)
	}
	if in.Role != nil {
		if !store.ValidRole(string(*in.Role)) {
			writeError(w, http.StatusBadRequest, "perfil inválido", "bad_request")
			return
		}
		next.Role = string(*in.Role)
	}
	if in.Disabled != nil {
		next.Disabled = *in.Disabled
	}
	if (next.Role != store.RoleAdmin || next.Disabled) && !s.lastAdminGuard(w, r, u) {
		return
	}
	if err := s.DB.UpdateUser(r.Context(), next); err != nil {
		s.storeError(w, err)
		return
	}
	if next.Disabled || next.Role != u.Role {
		// Perfil novo ou bloqueio valem já: as sessões abertas são encerradas.
		_ = s.DB.DeleteUserSessions(r.Context(), u.ID)
	}
	s.audit(r, "user_updated", u.Username, fmt.Sprintf("perfil %s→%s, bloqueado %v", u.Role, next.Role, next.Disabled))
	writeJSON(w, http.StatusOK, toAPIUser(next))
}

// DeleteUser remove usuário.
func (s *Server) DeleteUser(w http.ResponseWriter, r *http.Request, id api.Id) {
	u, err := s.DB.GetUser(r.Context(), id)
	if err != nil {
		s.storeError(w, err)
		return
	}
	if p := principalFrom(r.Context()); p.UserID == u.ID {
		writeError(w, http.StatusConflict, "você não pode remover o próprio usuário", "self")
		return
	}
	if !s.lastAdminGuard(w, r, u) {
		return
	}
	if err := s.DB.DeleteUser(r.Context(), id); err != nil {
		s.storeError(w, err)
		return
	}
	s.audit(r, "user_deleted", u.Username, "")
	w.WriteHeader(http.StatusNoContent)
}

// ResetUserMfa apaga o segundo fator de outro usuário.
func (s *Server) ResetUserMfa(w http.ResponseWriter, r *http.Request, id api.Id) {
	u, err := s.DB.GetUser(r.Context(), id)
	if err != nil {
		s.storeError(w, err)
		return
	}
	if err := s.DB.ResetMFA(r.Context(), id); err != nil {
		s.storeError(w, err)
		return
	}
	s.audit(r, "user_mfa_reset", u.Username, "")
	w.WriteHeader(http.StatusNoContent)
}

// ListApiTokens lista os tokens do usuário (o administrador vê todos).
func (s *Server) ListApiTokens(w http.ResponseWriter, r *http.Request) {
	p := principalFrom(r.Context())
	uid := p.UserID
	if p.Role == store.RoleAdmin {
		uid = 0
	}
	list, err := s.DB.ListAPITokens(r.Context(), uid)
	if err != nil {
		s.storeError(w, err)
		return
	}
	out := make([]api.ApiToken, 0, len(list))
	for _, t := range list {
		out = append(out, toAPIToken(t))
	}
	writeJSON(w, http.StatusOK, out)
}

// CreateApiToken cria token de automação (o valor aparece só nesta resposta).
func (s *Server) CreateApiToken(w http.ResponseWriter, r *http.Request) {
	var in api.ApiTokenCreate
	if !decode(w, r, &in) {
		return
	}
	p := principalFrom(r.Context())
	raw, t, err := s.Auth.NewAPIToken(r.Context(), *p, in.Name, string(in.Role), time.Duration(in.ExpiresInDays)*24*time.Hour)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error(), "bad_request")
		return
	}
	writeJSON(w, http.StatusCreated, api.ApiTokenCreated{Token: raw, Info: toAPIToken(t)})
}

// RevokeApiToken revoga token (o próprio; o administrador revoga qualquer um).
func (s *Server) RevokeApiToken(w http.ResponseWriter, r *http.Request, id api.Id) {
	p := principalFrom(r.Context())
	if p.Role != store.RoleAdmin {
		list, err := s.DB.ListAPITokens(r.Context(), p.UserID)
		if err != nil {
			s.storeError(w, err)
			return
		}
		mine := false
		for _, t := range list {
			mine = mine || t.ID == id
		}
		if !mine {
			writeError(w, http.StatusNotFound, "não encontrado", "not_found")
			return
		}
	}
	if err := s.DB.RevokeAPIToken(r.Context(), id); err != nil {
		s.storeError(w, err)
		return
	}
	s.audit(r, "api_token_revoked", fmt.Sprint(id), "")
	w.WriteHeader(http.StatusNoContent)
}

// ListAudit devolve a auditoria e confere a cadeia de hashes.
func (s *Server) ListAudit(w http.ResponseWriter, r *http.Request, params api.ListAuditParams) {
	var before int64
	if params.Before != nil {
		before = *params.Before
	}
	limit := limitOf(params.Limit)
	list, err := s.DB.ListAudit(r.Context(), before, limit)
	if err != nil {
		s.storeError(w, err)
		return
	}
	broken, err := s.DB.VerifyAudit(r.Context())
	if err != nil {
		s.storeError(w, err)
		return
	}
	out := api.AuditPage{Entries: make([]api.AuditEntry, 0, len(list)), ChainOk: broken == 0}
	if broken != 0 {
		out.BrokenAt = &broken
	}
	for _, e := range list {
		out.Entries = append(out.Entries, api.AuditEntry{Id: e.ID, At: e.At, Actor: e.Actor, Action: e.Action,
			Target: e.Target, Detail: e.Detail, Ip: e.IP})
	}
	if len(list) == limit && len(list) > 0 {
		out.NextBefore = ptr(list[len(list)-1].ID)
	}
	writeJSON(w, http.StatusOK, out)
}

// removeFirstAccessFile apaga o arquivo com o token de primeiro acesso depois de usado.
func (s *Server) removeFirstAccessFile() {
	if s.FirstAccessFile != "" {
		_ = os.Remove(s.FirstAccessFile)
	}
}

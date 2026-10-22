package core

import (
	"context"
	"errors"
	"net/http"
	"slices"
	"time"

	"github.com/guigallina27/vigiahost/internal/api"
	"github.com/guigallina27/vigiahost/internal/engines/lmd"
	"github.com/guigallina27/vigiahost/internal/ipc"
	"github.com/guigallina27/vigiahost/internal/rules"
	"github.com/guigallina27/vigiahost/internal/scan"
)

// lmdHealth resume o LMD como motor opcional: desligado por padrão; "não instalado" quando falta (ou não pode ser
// usado) e está desligado; indisponível quando o administrador ligou e a instalação não serve.
func lmdHealth(info scan.EngineInfo, execErr error, enabled bool, last *api.LastSelfTest) api.EngineHealth {
	h := api.EngineHealth{Id: api.Lmd, Name: "LMD", State: api.EngineStateUnavailable, LastSelftest: last}
	if execErr != nil {
		h.Detail = ptr("executor indisponível")
		return h
	}
	if in := info.LMD; in != nil {
		h.Version, h.SignaturesVersion, h.SignaturesDate = optional(in.Version), optional(in.SigVersion), optional(in.SigDate)
	}
	usable := info.LMD != nil && info.LMDError == ""
	switch {
	case !enabled && usable:
		h.State = api.EngineStateDisabled
	case !enabled:
		h.State, h.Detail = api.EngineStateNotInstalled, optional(info.LMDError)
	case usable:
		h.State = api.EngineStateOperational
		if last != nil && !last.Passed {
			h.State, h.Detail = api.EngineStateDegraded, ptr("o autoteste da última execução falhou")
		}
	default:
		h.Detail = optional(info.LMDError)
	}
	return h
}

// rulesCall consulta ou aciona as regras no executor.
func (s *Server) rulesCall(ctx context.Context, op ipc.Op, body any) (ipc.RulesStatus, error) {
	var st ipc.RulesStatus
	if s.Exec == nil {
		return st, errors.New("executor não configurado")
	}
	cctx, cancel := context.WithTimeout(ctx, 25*time.Second)
	defer cancel()
	err := s.Exec.Call(cctx, op, body, &st)
	return st, err
}

// sourceState cruza a fonte como está agora com o resultado da última compilação: mudou o conteúdo, foi ativada ou
// não há compilação registrada, a fonte fica "pendente" até a próxima.
func sourceState(src rules.SourceInfo, enabled bool, last *rules.CompileStatus) (api.RuleSourceState, string) {
	if src.Problem != "" {
		return api.RuleSourceStateRefused, src.Problem
	}
	if !enabled {
		return api.RuleSourceStateDisabled, ""
	}
	if last == nil {
		return api.RuleSourceStatePending, ""
	}
	for _, r := range last.Sources {
		if r.Name != src.Name {
			continue
		}
		if r.State == rules.StateDisabled || (r.Hash != "" && r.Hash != src.Hash) {
			return api.RuleSourceStatePending, ""
		}
		switch r.State {
		case rules.StateOK:
			return api.RuleSourceStateOk, ""
		case rules.StateError:
			return api.RuleSourceStateError, r.Error
		case rules.StateRefused:
			return api.RuleSourceStateRefused, r.Error
		}
	}
	return api.RuleSourceStatePending, ""
}

func toAPIRuleSource(src rules.SourceInfo, disabled []string, last *rules.CompileStatus) api.RuleSource {
	enabled := src.Mandatory || !slices.Contains(disabled, src.Name)
	state, problem := sourceState(src, enabled, last)
	out := api.RuleSource{Name: src.Name, Origin: api.RuleSourceOrigin(src.Origin), Enabled: enabled, Mandatory: src.Mandatory,
		Files: src.Files, Rules: src.Rules, Bytes: src.Bytes, State: state, Path: optional(src.Path),
		Description: optional(src.Description), License: optional(src.License), Author: optional(src.Author),
		Url: optional(src.URL), Version: optional(src.Version), Hash: optional(src.Hash), Problem: optional(problem)}
	if !src.UpdatedAt.IsZero() {
		t := src.UpdatedAt.UTC()
		out.UpdatedAt = &t
	}
	return out
}

// rulesOverview monta a tela "Regras e fontes": fontes YARA, assinaturas do ClamAV e o LMD.
func (s *Server) rulesOverview(ctx context.Context, st ipc.RulesStatus, stErr error) api.RulesOverview {
	info, infoErr := s.engineInfo(ctx)
	health, execErr := s.engineHealth(ctx)
	disabled, err := s.DB.DisabledRuleSources(ctx)
	if err != nil {
		s.Logger.Warn("fontes de regras desativadas não lidas", "erro", err)
	}
	lmdOn, err := s.DB.LMDEnabled(ctx)
	if err != nil {
		s.Logger.Warn("configuração do LMD não lida", "erro", err)
	}

	out := api.RulesOverview{
		Yara:   api.YaraRules{UserDir: rules.UserDir, Compiling: st.Compiling, Sources: []api.RuleSource{}, YrVersion: optional(info.YRVersion)},
		Clamav: api.ClamavSignatures{State: api.EngineStateUnavailable, LmdSignatures: []string{}},
		Lmd:    api.LmdStatus{Installed: info.LMD != nil, Usable: info.LMD != nil && info.LMDError == "", Enabled: lmdOn, Path: "/" + lmd.Dir},
	}
	if st.UserDir != "" {
		out.Yara.UserDir = st.UserDir
	}
	for _, src := range st.Sources {
		out.Yara.Sources = append(out.Yara.Sources, toAPIRuleSource(src, disabled, st.Last))
	}
	if l := st.Last; l != nil {
		out.Yara.LastCompile = &api.RulesCompileResult{At: l.At.UTC(), Trigger: api.RulesCompileResultTrigger(l.Trigger), Ok: l.OK,
			Error: optional(l.Error), SetVersion: optional(l.SetVersion), YrVersion: optional(l.YRVersion), Selftest: l.SelfTest,
			Detail: optional(l.Detail)}
		if out.Yara.YrVersion == nil {
			out.Yara.YrVersion = optional(l.YRVersion)
		}
	}
	for _, h := range health {
		switch h.Id {
		case api.Clamav:
			out.Clamav.State, out.Clamav.Version, out.Clamav.Mode, out.Clamav.Detail = h.State, h.Version, h.Mode, h.Detail
			out.Clamav.SignaturesVersion, out.Clamav.SignaturesDate = h.SignaturesVersion, h.SignaturesDate
		case api.Lmd:
			out.Lmd.State, out.Lmd.Detail, out.Lmd.LastSelftest = h.State, h.Detail, h.LastSelftest
			out.Lmd.Version, out.Lmd.SignaturesVersion, out.Lmd.SignaturesDate = h.Version, h.SignaturesVersion, h.SignaturesDate
		}
	}
	if in := info.LMD; infoErr == nil && in != nil {
		c := in.Signatures
		out.Lmd.Signatures = &api.LmdSignatureCounts{Md5: c.MD5, Sha256: c.SHA256, Hex: c.HEX, Csig: c.CSIG, Yara: c.YARA, User: c.User}
		if in.Dir != "" {
			out.Lmd.Path = in.Dir
		}
		if len(in.ClamAVLinked) > 0 {
			out.Clamav.LmdSignatures = in.ClamAVLinked
		}
	}
	switch {
	case stErr != nil:
		out.ExecutorError = ptr(stErr.Error())
	case execErr != nil:
		out.ExecutorError = execErr
	}
	return out
}

// GetRules mostra fontes de regras, assinaturas e o estado da última compilação.
func (s *Server) GetRules(w http.ResponseWriter, r *http.Request) {
	st, err := s.rulesCall(r.Context(), ipc.OpRulesStatus, nil)
	if errors.Is(err, context.Canceled) {
		s.storeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, s.rulesOverview(r.Context(), st, err))
}

// startCompile pede a compilação com a lista de fontes desativadas gravada.
func (s *Server) startCompile(ctx context.Context) (ipc.RulesStatus, error) {
	disabled, err := s.DB.DisabledRuleSources(ctx)
	if err != nil {
		return ipc.RulesStatus{}, err
	}
	st, err := s.rulesCall(ctx, ipc.OpRulesCompile, ipc.RulesCompile{Disabled: disabled})
	if err == nil {
		// A próxima consulta aos motores já deve refletir o conjunto novo.
		s.engMu.Lock()
		s.engCache = nil
		s.engMu.Unlock()
	}
	return st, err
}

// CompileRules recompila e valida as regras numa unidade isolada; a resposta volta com compiling=true.
func (s *Server) CompileRules(w http.ResponseWriter, r *http.Request) {
	st, err := s.startCompile(r.Context())
	var ie *ipc.Error
	if errors.As(err, &ie) && ie.Code == ipc.CodeAlreadyExists {
		writeError(w, http.StatusConflict, "já há uma compilação de regras em andamento", "conflict")
		return
	}
	if err != nil {
		s.storeError(w, err)
		return
	}
	s.audit(r, "rules_compile_requested", "yara", "")
	writeJSON(w, http.StatusOK, s.rulesOverview(r.Context(), st, nil))
}

// SetRuleSource ativa ou desativa uma fonte e pede nova compilação (a fonte entra ou sai na próxima execução).
func (s *Server) SetRuleSource(w http.ResponseWriter, r *http.Request, name string) {
	var in api.ToggleInput
	if !decode(w, r, &in) {
		return
	}
	if !rules.SourceNamePattern.MatchString(name) {
		writeError(w, http.StatusBadRequest, "nome de fonte inválido", "bad_request")
		return
	}
	st, err := s.rulesCall(r.Context(), ipc.OpRulesStatus, nil)
	if err != nil {
		s.storeError(w, err)
		return
	}
	var found *rules.SourceInfo
	for i := range st.Sources {
		if st.Sources[i].Name == name {
			found = &st.Sources[i]
			if st.Sources[i].Origin == rules.OriginBuiltin {
				break
			}
		}
	}
	if found == nil {
		writeError(w, http.StatusNotFound, "fonte de regras não encontrada", "not_found")
		return
	}
	if found.Mandatory && !in.Enabled {
		writeError(w, http.StatusBadRequest, "o controle positivo não pode ser desativado", "bad_request")
		return
	}
	disabled, err := s.DB.DisabledRuleSources(r.Context())
	if err != nil {
		s.storeError(w, err)
		return
	}
	next := slices.DeleteFunc(slices.Clone(disabled), func(n string) bool { return n == name })
	if !in.Enabled {
		next = append(next, name)
	}
	if err := rules.ValidDisabled(next); err != nil {
		writeError(w, http.StatusBadRequest, err.Error(), "bad_request")
		return
	}
	if err := s.DB.SetDisabledRuleSources(r.Context(), next); err != nil {
		s.storeError(w, err)
		return
	}
	action := "rule_source_disabled"
	if in.Enabled {
		action = "rule_source_enabled"
	}
	s.audit(r, action, name, found.Origin)

	// A compilação valida o conjunto novo; se já houver uma em andamento, a próxima execução compila de qualquer modo.
	var stErr error
	if cst, err := s.startCompile(r.Context()); err == nil {
		st = cst
	} else {
		var ie *ipc.Error
		if !errors.As(err, &ie) || ie.Code != ipc.CodeAlreadyExists {
			stErr = err
		}
		if fresh, err := s.rulesCall(r.Context(), ipc.OpRulesStatus, nil); err == nil {
			st = fresh
		}
	}
	writeJSON(w, http.StatusOK, s.rulesOverview(r.Context(), st, stErr))
}

// SetLmd liga ou desliga o LMD nas varreduras de arquivos; ligar exige a instalação utilizável.
func (s *Server) SetLmd(w http.ResponseWriter, r *http.Request) {
	var in api.ToggleInput
	if !decode(w, r, &in) {
		return
	}
	if in.Enabled {
		info, err := s.engineInfo(r.Context())
		if err != nil {
			writeError(w, http.StatusServiceUnavailable, "executor indisponível; tente de novo em instantes", "executor_unavailable")
			return
		}
		if info.LMD == nil || info.LMDError != "" {
			msg := "o LMD 2.x não está instalado neste servidor"
			if info.LMDError != "" {
				msg = "o LMD não pode ser usado: " + info.LMDError
			}
			writeError(w, http.StatusConflict, msg, "lmd_unavailable")
			return
		}
	}
	if err := s.DB.SetLMDEnabled(r.Context(), in.Enabled); err != nil {
		s.storeError(w, err)
		return
	}
	action := "lmd_disabled"
	if in.Enabled {
		action = "lmd_enabled"
	}
	s.audit(r, action, "lmd", "")
	st, err := s.rulesCall(r.Context(), ipc.OpRulesStatus, nil)
	writeJSON(w, http.StatusOK, s.rulesOverview(r.Context(), st, err))
}

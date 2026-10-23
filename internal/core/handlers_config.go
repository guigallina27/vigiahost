package core

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"path"
	"regexp"
	"strings"
	"time"

	"github.com/guigallina27/vigiahost/internal/api"
	"github.com/guigallina27/vigiahost/internal/ipc"
	"github.com/guigallina27/vigiahost/internal/orchestrator"
	"github.com/guigallina27/vigiahost/internal/profile"
	"github.com/guigallina27/vigiahost/internal/report"
	"github.com/guigallina27/vigiahost/internal/scan"
	"github.com/guigallina27/vigiahost/internal/store"
)

var sha256Pattern = regexp.MustCompile(`^[0-9a-f]{64}$`)

// ListExceptions lista exceções.
func (s *Server) ListExceptions(w http.ResponseWriter, r *http.Request, params api.ListExceptionsParams) {
	list, err := s.DB.ListExceptions(r.Context(), params.All != nil && *params.All)
	if err != nil {
		s.storeError(w, err)
		return
	}
	now := s.now()
	out := make([]api.Exception, 0, len(list))
	for _, e := range list {
		out = append(out, toAPIException(e, now))
	}
	writeJSON(w, http.StatusOK, out)
}

// CreateException valida o escopo (seção 11 do escopo) e grava a exceção.
func (s *Server) CreateException(w http.ResponseWriter, r *http.Request) {
	var in api.ExceptionCreate
	if !decode(w, r, &in) {
		return
	}
	p := principalFrom(r.Context())
	e := store.Exception{Scope: string(in.Scope), Reason: strings.TrimSpace(in.Reason), CreatedBy: p.Actor(), ExpiresAt: in.ExpiresAt}
	if in.FindingId != nil {
		f, err := s.DB.GetFinding(r.Context(), *in.FindingId)
		if err != nil {
			s.storeError(w, err)
			return
		}
		e.SHA256, e.Signature = f.SHA256, f.Signature
		if f.Location != nil {
			e.PathPrefix = path.Dir(f.Location.Path)
		}
	}
	if in.Sha256 != nil {
		e.SHA256 = strings.ToLower(strings.TrimSpace(*in.Sha256))
	}
	if in.Signature != nil {
		e.Signature = strings.TrimSpace(*in.Signature)
	}
	if in.PathPrefix != nil {
		e.PathPrefix = path.Clean(strings.TrimSpace(*in.PathPrefix))
	}
	bad := func(msg string) { writeError(w, http.StatusBadRequest, msg, "bad_request") }
	if len(e.Reason) < 3 {
		bad("informe o motivo da exceção")
		return
	}
	if e.ExpiresAt != nil && !e.ExpiresAt.After(s.now()) {
		bad("a validade precisa estar no futuro")
		return
	}
	switch e.Scope {
	case store.ScopeHash:
		e.Signature, e.PathPrefix = "", ""
		if !sha256Pattern.MatchString(e.SHA256) {
			bad("exceção por hash exige o SHA-256 do objeto")
			return
		}
	case store.ScopeHashRule:
		e.PathPrefix = ""
		if !sha256Pattern.MatchString(e.SHA256) || e.Signature == "" {
			bad("exceção por hash e regra exige o SHA-256 e a assinatura")
			return
		}
	case store.ScopeRulePrefix:
		e.SHA256 = ""
		if e.Signature == "" || !strings.HasPrefix(e.PathPrefix, "/") || e.PathPrefix == "/" {
			bad("exceção por regra e prefixo exige a assinatura e um diretório (não a raiz)")
			return
		}
		if e.ExpiresAt == nil {
			bad("exceção por regra e prefixo exige validade")
			return
		}
	case store.ScopeRuleGlobal:
		e.SHA256, e.PathPrefix = "", ""
		if p.Role != store.RoleAdmin {
			writeError(w, http.StatusForbidden, "só o administrador cria exceção global de regra", "forbidden")
			return
		}
		if e.Signature == "" {
			bad("exceção global exige a assinatura")
			return
		}
	default:
		bad("escopo de exceção inválido")
		return
	}
	if err := s.DB.CreateException(r.Context(), &e); err != nil {
		s.storeError(w, err)
		return
	}
	s.audit(r, "exception_created", fmt.Sprint(e.ID), fmt.Sprintf("%s %s %s %s: %s", e.Scope, e.Signature, e.SHA256,
		e.PathPrefix, e.Reason))
	if s.Hub != nil {
		s.Hub.Publish(orchestrator.Event{Type: "finding"})
	}
	writeJSON(w, http.StatusCreated, toAPIException(e, s.now()))
}

// RevokeException revoga a exceção.
func (s *Server) RevokeException(w http.ResponseWriter, r *http.Request, id api.Id) {
	if err := s.DB.RevokeException(r.Context(), id, principalFrom(r.Context()).Actor()); err != nil {
		s.storeError(w, err)
		return
	}
	s.audit(r, "exception_revoked", fmt.Sprint(id), "")
	w.WriteHeader(http.StatusNoContent)
}

func upcoming(sc store.Schedule, from time.Time, n int) []time.Time {
	out := []time.Time{}
	t := from
	for i := 0; i < n; i++ {
		next, err := sc.NextAfter(t)
		if err != nil {
			break
		}
		out = append(out, next)
		t = next
	}
	return out
}

func (s *Server) toAPISchedule(sc store.Schedule) api.Schedule {
	return api.Schedule{Id: sc.ID, Name: sc.Name, Kind: api.RunKind(sc.Kind), Cron: sc.Cron, Timezone: sc.Timezone,
		Paths: nonNil(sc.Paths), Exclude: nonNil(sc.Exclude), Incremental: sc.Incremental, Profile: sc.Profile,
		MissedPolicy: api.MissedPolicy(sc.MissedPolicy), Enabled: sc.Enabled, NextRunAt: optTime(sc.NextRunAt),
		LastRunAt: optTime(sc.LastRunAt), CreatedBy: sc.CreatedBy, CreatedAt: sc.CreatedAt, UpdatedAt: sc.UpdatedAt,
		Upcoming: upcoming(sc, s.now(), 5), Accounts: toAPISelection(sc.Accounts)}
}

// ListSchedules lista agendamentos.
func (s *Server) ListSchedules(w http.ResponseWriter, r *http.Request) {
	list, err := s.DB.ListSchedules(r.Context())
	if err != nil {
		s.storeError(w, err)
		return
	}
	out := make([]api.Schedule, 0, len(list))
	for _, sc := range list {
		out = append(out, s.toAPISchedule(sc))
	}
	writeJSON(w, http.StatusOK, out)
}

// scheduleFrom valida a entrada; devolve mensagem de erro para o operador.
func (s *Server) scheduleFrom(ctx context.Context, in api.ScheduleInput, sc *store.Schedule) error {
	sc.Name, sc.Kind, sc.Cron = strings.TrimSpace(in.Name), report.Kind(in.Kind), strings.TrimSpace(in.Cron)
	sc.Timezone, sc.Profile, sc.MissedPolicy = "UTC", profile.Standard, store.MissedRunOnce
	sc.Incremental, sc.Enabled = true, true
	if in.Timezone != nil && *in.Timezone != "" {
		sc.Timezone = *in.Timezone
	}
	if in.Profile != nil && *in.Profile != "" {
		sc.Profile = *in.Profile
	}
	if in.MissedPolicy != nil {
		sc.MissedPolicy = string(*in.MissedPolicy)
	}
	if in.Incremental != nil {
		sc.Incremental = *in.Incremental
	}
	if in.Enabled != nil {
		sc.Enabled = *in.Enabled
	}
	if sc.Name == "" {
		return errors.New("informe um nome para o agendamento")
	}
	if !report.ValidKind(sc.Kind) {
		return errors.New("tipo de execução inválido")
	}
	if sc.MissedPolicy != store.MissedSkip && sc.MissedPolicy != store.MissedRunOnce {
		return errors.New("política de horário perdido inválida")
	}
	if _, _, err := store.ParseCron(sc.Cron, sc.Timezone); err != nil {
		return err
	}
	var paths, excl []string
	if in.Paths != nil {
		paths = *in.Paths
	}
	if in.Exclude != nil {
		excl = *in.Exclude
	}
	var err error
	if sc.Paths, err = orchestrator.CleanPaths(paths, 64); err != nil {
		return err
	}
	if sc.Exclude, err = orchestrator.CleanPaths(excl, 256); err != nil {
		return err
	}
	if sc.Accounts, err = selectionFrom(in.Accounts); err != nil {
		return err
	}
	if sc.Kind == report.KindFiles && len(sc.Paths) == 0 && sc.Accounts.Empty() {
		return errors.New("informe ao menos um caminho ou uma conta para a varredura de arquivos")
	}
	if sc.Kind != report.KindFiles {
		// Inspeção de processos e verificações do sistema têm escopo fixo.
		sc.Paths, sc.Exclude, sc.Accounts = nil, nil, store.AccountSelection{}
	}
	if _, err := s.Orch.ResolveProfile(ctx, sc.Profile); err != nil {
		return err
	}
	return nil
}

// CreateSchedule cria agendamento.
func (s *Server) CreateSchedule(w http.ResponseWriter, r *http.Request) {
	var in api.ScheduleInput
	if !decode(w, r, &in) {
		return
	}
	sc := store.Schedule{CreatedBy: principalFrom(r.Context()).Actor()}
	if err := s.scheduleFrom(r.Context(), in, &sc); err != nil {
		writeError(w, http.StatusBadRequest, strings.TrimPrefix(err.Error(), "pedido inválido: "), "bad_request")
		return
	}
	if err := s.DB.SaveSchedule(r.Context(), &sc); err != nil {
		s.storeError(w, err)
		return
	}
	s.audit(r, "schedule_created", fmt.Sprint(sc.ID), sc.Name+" ("+sc.Cron+" "+sc.Timezone+")")
	writeJSON(w, http.StatusCreated, s.toAPISchedule(sc))
}

// UpdateSchedule altera agendamento.
func (s *Server) UpdateSchedule(w http.ResponseWriter, r *http.Request, id api.Id) {
	var in api.ScheduleInput
	if !decode(w, r, &in) {
		return
	}
	sc, err := s.DB.GetSchedule(r.Context(), id)
	if err != nil {
		s.storeError(w, err)
		return
	}
	if err := s.scheduleFrom(r.Context(), in, &sc); err != nil {
		writeError(w, http.StatusBadRequest, strings.TrimPrefix(err.Error(), "pedido inválido: "), "bad_request")
		return
	}
	if err := s.DB.SaveSchedule(r.Context(), &sc); err != nil {
		s.storeError(w, err)
		return
	}
	s.audit(r, "schedule_updated", fmt.Sprint(sc.ID), sc.Name+" ("+sc.Cron+" "+sc.Timezone+")")
	writeJSON(w, http.StatusOK, s.toAPISchedule(sc))
}

// DeleteSchedule remove agendamento.
func (s *Server) DeleteSchedule(w http.ResponseWriter, r *http.Request, id api.Id) {
	if err := s.DB.DeleteSchedule(r.Context(), id); err != nil {
		s.storeError(w, err)
		return
	}
	s.audit(r, "schedule_deleted", fmt.Sprint(id), "")
	w.WriteHeader(http.StatusNoContent)
}

// PreviewSchedule valida a expressão e mostra os próximos horários.
func (s *Server) PreviewSchedule(w http.ResponseWriter, r *http.Request) {
	var in api.CronPreviewRequest
	if !decode(w, r, &in) {
		return
	}
	sc := store.Schedule{Cron: strings.TrimSpace(in.Cron), Timezone: "UTC"}
	if in.Timezone != nil && *in.Timezone != "" {
		sc.Timezone = *in.Timezone
	}
	if _, _, err := store.ParseCron(sc.Cron, sc.Timezone); err != nil {
		writeError(w, http.StatusBadRequest, err.Error(), "bad_request")
		return
	}
	writeJSON(w, http.StatusOK, api.CronPreview{Next: upcoming(sc, s.now(), 5)})
}

func (s *Server) resources(ctx context.Context) (api.Resources, error) {
	out := api.Resources{Profiles: []api.ProfileEntry{}}
	hw, herr := s.Orch.Hardware(ctx)
	if herr == nil {
		out.Hardware = &api.Hardware{Cpus: hw.CPUs, MemoryBytes: hw.MemoryBytes, Rotational: hw.Rotational,
			AllowNoReserve: hw.AllowNoReserv, SystemdVersion: hw.Systemd, Freezer: hw.Freezer}
		if hw.DiskType != "" {
			out.Hardware.DiskType = ptr(api.DiskType(hw.DiskType))
		}
		if p := hw.Pressure; p != nil && p.Available {
			out.Hardware.Pressure = &api.HostPressure{Cpu: toAPIPressure(p.CPU), Io: toAPIPressure(p.IO), Memory: toAPIPressure(p.Memory)}
		}
		if hw.LoadAvg > 0 {
			out.Hardware.LoadAvg = ptr(float32(hw.LoadAvg))
		}
	} else {
		out.ExecutorError = ptr(herr.Error())
	}
	list, custom, err := s.Orch.Profiles(ctx)
	if err != nil {
		return out, err
	}
	for _, p := range list {
		preset := p.Name == profile.Light || p.Name == profile.Standard || p.Name == profile.Intensive
		out.Profiles = append(out.Profiles, api.ProfileEntry{Profile: toAPIProfile(p), Custom: custom[p.Name], Preset: preset})
	}
	return out, nil
}

// GetResources devolve hardware e perfis.
func (s *Server) GetResources(w http.ResponseWriter, r *http.Request) {
	out, err := s.resources(r.Context())
	if err != nil {
		s.storeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, out)
}

// SaveResourceProfile grava perfil personalizado, validado pelas mesmas travas do executor.
func (s *Server) SaveResourceProfile(w http.ResponseWriter, r *http.Request, name string) {
	var in api.ResourceProfile
	if !decode(w, r, &in) {
		return
	}
	in.Name = name
	p := fromAPIProfile(in)
	hw, err := s.Orch.Hardware(r.Context())
	if err != nil {
		s.storeError(w, err)
		return
	}
	enforced, err := profile.Enforce(p, orchestrator.ProfileHardware(hw), false, false)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error(), "limit_refused")
		return
	}
	if err := s.DB.SaveResourceProfile(r.Context(), enforced, principalFrom(r.Context()).Actor()); err != nil {
		s.storeError(w, err)
		return
	}
	s.audit(r, "resource_profile_saved", name, fmt.Sprintf("cpu %d%%, memória %d, workers %d, pressão cpu/es/mem %d/%d/%d%%",
		enforced.CPUQuotaPercent, enforced.MemoryMaxBytes, enforced.Workers, enforced.PressureCPU, enforced.PressureIO,
		enforced.PressureMemory))
	s.GetResources(w, r)
}

// DeleteResourceProfile volta o perfil ao pré-definido.
func (s *Server) DeleteResourceProfile(w http.ResponseWriter, r *http.Request, name string) {
	if err := s.DB.DeleteResourceProfile(r.Context(), name); err != nil {
		s.storeError(w, err)
		return
	}
	s.audit(r, "resource_profile_reset", name, "")
	s.GetResources(w, r)
}

type engineCache struct {
	at   time.Time
	info scan.EngineInfo
	err  error
}

// engineInfo consulta o executor (com cache de 60 s: a consulta ao clamd e ao yr custa alguns processos).
func (s *Server) engineInfo(ctx context.Context) (scan.EngineInfo, error) {
	s.engMu.Lock()
	defer s.engMu.Unlock()
	if c := s.engCache; c != nil && time.Since(c.at) < time.Minute {
		return c.info, c.err
	}
	var info scan.EngineInfo
	err := errors.New("executor não configurado")
	if s.Exec != nil {
		cctx, cancel := context.WithTimeout(ctx, 25*time.Second)
		err = s.Exec.Call(cctx, ipc.OpEngines, nil, &info)
		cancel()
	}
	s.engCache = &engineCache{at: time.Now(), info: info, err: err}
	return info, err
}

// engineHealth combina o que o executor encontrou com o autoteste da última execução de arquivos.
func (s *Server) engineHealth(ctx context.Context) ([]api.EngineHealth, *string) {
	info, err := s.engineInfo(ctx)
	var execErr *string
	if err != nil {
		execErr = ptr(err.Error())
	}
	var last map[string]store.RunEngine
	var lastRun store.Run
	if r, err := s.DB.LastFinishedRun(ctx, report.KindFiles); err == nil {
		lastRun = r
		if eng, err := s.DB.RunEngines(ctx, r.ID); err == nil {
			last = map[string]store.RunEngine{}
			for _, e := range eng {
				last[e.Engine] = e
			}
		}
	}
	selftest := func(id string) *api.LastSelfTest {
		e, ok := last[id]
		if !ok {
			return nil
		}
		return &api.LastSelfTest{RunId: lastRun.ID, Passed: e.SelfTestPassed, Detail: e.SelfTestDetail, At: optTime(lastRun.FinishedAt)}
	}

	yr := api.EngineHealth{Id: api.YaraX, Name: "YARA-X", State: api.EngineStateUnavailable, LastSelftest: selftest(scan.EngineYARA)}
	clam := api.EngineHealth{Id: api.Clamav, Name: "ClamAV", State: api.EngineStateUnavailable, LastSelftest: selftest(scan.EngineClamAV)}
	lmdOn, lerr := s.DB.LMDEnabled(ctx)
	if lerr != nil {
		s.Logger.Warn("configuração do LMD não lida", "erro", lerr)
	}
	lmdH := lmdHealth(info, err, lmdOn, selftest(scan.EngineLMD))
	if err != nil {
		yr.Detail, clam.Detail = ptr("executor indisponível"), ptr("executor indisponível")
		return []api.EngineHealth{yr, clam, lmdH}, execErr
	}
	if info.YRVersion != "" {
		yr.State, yr.Version = api.EngineStateOperational, ptr(info.YRVersion)
		if e, ok := last[scan.EngineYARA]; ok && e.RulesVersion != "" {
			yr.RulesVersion = ptr(e.RulesVersion)
		}
	} else {
		yr.Detail = optional(info.YRError)
	}
	if yr.LastSelftest != nil && !yr.LastSelftest.Passed && yr.State == api.EngineStateOperational {
		yr.State, yr.Detail = api.EngineStateDegraded, ptr("o autoteste da última execução falhou")
	}
	if v := info.ClamVersion; v.Engine != "" || info.Clamscan != "" || info.Clamd != nil {
		clam.Version, clam.SignaturesVersion, clam.SignaturesDate = optional(v.Engine), optional(v.Database), optional(v.BuiltAt)
		switch {
		case info.Clamd != nil:
			clam.State, clam.Mode = api.EngineStateOperational, ptr("clamd")
		case info.Clamscan != "":
			clam.State, clam.Mode = api.EngineStateDegraded, ptr("clamscan")
			clam.Detail = ptr("clamd não respondeu; a varredura usa o clamscan, bem mais lento (" + info.ClamdError + ")")
		}
	} else {
		clam.Detail = optional(info.ClamError)
	}
	if clam.LastSelftest != nil && !clam.LastSelftest.Passed && clam.State == api.EngineStateOperational {
		clam.State, clam.Detail = api.EngineStateDegraded, ptr("o autoteste da última execução falhou")
	}
	return []api.EngineHealth{yr, clam, lmdH}, execErr
}

// GetEngines devolve a saúde dos motores.
func (s *Server) GetEngines(w http.ResponseWriter, r *http.Request) {
	eng, execErr := s.engineHealth(r.Context())
	writeJSON(w, http.StatusOK, api.EngineStatus{Engines: eng, ExecutorError: execErr})
}

// GetOverview monta o resumo da Visão geral.
func (s *Server) GetOverview(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	pctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	exec := toAPIStatus(s.Probe(pctx))
	cancel()
	out := api.Overview{Executor: exec, ActiveRuns: []api.Run{}, RecentFindings: []api.Finding{}}
	sev, err := s.DB.OpenFindingsBySeverity(ctx)
	if err != nil {
		s.storeError(w, err)
		return
	}
	out.OpenFindings = api.SeverityCounts{Critical: sev["critical"], High: sev["high"], Medium: sev["medium"],
		Low: sev["low"], Info: sev["info"]}
	out.OpenFindings.Total = out.OpenFindings.Critical + out.OpenFindings.High + out.OpenFindings.Medium +
		out.OpenFindings.Low + out.OpenFindings.Info
	active, err := s.DB.ListRuns(ctx, store.RunFilter{Statuses: []string{store.RunQueued, store.RunReserved, store.RunRunning}, Limit: 20})
	if err != nil {
		s.storeError(w, err)
		return
	}
	out.ActiveRuns = toAPIRuns(active)
	if run, err := s.DB.LastFinishedRun(ctx, report.KindFiles); err == nil {
		out.LastFilesRun = ptr(toAPIRun(run))
	}
	if run, err := s.DB.LastFinishedRun(ctx, report.KindProcesses); err == nil {
		out.LastProcessesRun = ptr(toAPIRun(run))
	}
	recent, err := s.DB.ListFindings(ctx, store.FindingFilter{States: store.OpenStates, Limit: 5})
	if err != nil {
		s.storeError(w, err)
		return
	}
	out.RecentFindings = toAPIFindings(recent)
	if first, err := s.DB.ListRuns(ctx, store.RunFilter{Limit: 1}); err == nil {
		out.HasRuns = len(first) > 0
	}
	if sc, err := s.DB.ListSchedules(ctx); err == nil {
		out.HasSchedules = len(sc) > 0
	}
	out.Engines, _ = s.engineHealth(ctx)
	writeJSON(w, http.StatusOK, out)
}

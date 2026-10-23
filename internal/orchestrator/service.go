package orchestrator

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/guigallina27/vigiahost/internal/integrity"
	"github.com/guigallina27/vigiahost/internal/ipc"
	"github.com/guigallina27/vigiahost/internal/notify"
	"github.com/guigallina27/vigiahost/internal/profile"
	"github.com/guigallina27/vigiahost/internal/report"
	"github.com/guigallina27/vigiahost/internal/store"
	"github.com/guigallina27/vigiahost/internal/updates"
)

// Config ajusta o orquestrador; zero usa os padrões.
type Config struct {
	// Concurrency por tipo de execução (padrão 1: uma de cada tipo por vez; tipo ausente no mapa vale 1).
	Concurrency map[report.Kind]int
	Tick        time.Duration // intervalo do laço (padrão 2 s)
	Lease       time.Duration // validade da reserva sem notícia do executor (padrão 2 min)
	MissedGrace time.Duration // atraso tolerado antes de aplicar a política de horário perdido (padrão 15 min)
	Retention   time.Duration // quanto o diretório bruto de uma execução terminada fica no executor (padrão 14 dias)
}

func (c *Config) defaults() {
	if c.Concurrency == nil {
		c.Concurrency = map[report.Kind]int{}
	}
	for _, k := range report.Kinds {
		if _, ok := c.Concurrency[k]; !ok {
			c.Concurrency[k] = 1
		}
	}
	if c.Tick <= 0 {
		c.Tick = 2 * time.Second
	}
	if c.Lease <= 0 {
		c.Lease = 2 * time.Minute
	}
	if c.MissedGrace <= 0 {
		c.MissedGrace = 15 * time.Minute
	}
	if c.Retention <= 0 {
		c.Retention = 14 * 24 * time.Hour
	}
}

// Notifier recebe os eventos que podem virar notificação (achado novo, fim de execução com problema). Só grava na
// caixa de saída; o envio roda em outra goroutine e nunca segura o laço da fila.
type Notifier interface {
	Emit(ctx context.Context, events ...notify.Event) error
}

// Service é o orquestrador.
type Service struct {
	DB     *store.DB
	Exec   Executor
	Hub    *Hub
	Logger *slog.Logger
	Config Config
	// Notifier nil desliga as notificações (testes e ferramentas de linha de comando).
	Notifier Notifier

	mu        sync.Mutex
	hw        *ipc.Hardware
	hwAt      time.Time
	accts     *ipc.AccountList
	acctsAt   time.Time
	canceling map[string]bool
	lastSweep time.Time
	wake      chan struct{}
}

// Erros de validação do pedido (viram 400 na API).
var (
	ErrInvalid  = errors.New("pedido inválido")
	ErrNotFound = store.ErrNotFound
	ErrConflict = store.ErrConflict
)

func invalid(format string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrInvalid, fmt.Sprintf(format, args...))
}

// NewRunID gera o identificador: data e sufixo aleatório, no formato aceito pelo executor.
func NewRunID(now time.Time) string {
	var b [4]byte
	_, _ = rand.Read(b[:])
	return now.UTC().Format("20060102-150405") + "-" + hex.EncodeToString(b[:])
}

// RunRequest é o que o operador ou o agendador pedem.
type RunRequest struct {
	Kind           report.Kind
	Paths          []string
	Exclude        []string
	Incremental    bool
	Profile        string
	Priority       int
	RequestedBy    string
	IdempotencyKey string
	// Accounts escolhe contas do servidor: os caminhos vêm delas (diretório pessoal e arquivos do UID nas áreas
	// temporárias) e somam-se aos Paths informados.
	Accounts store.AccountSelection
}

// CleanPaths valida caminhos absolutos e remove repetições. O executor revalida com a política dele.
func CleanPaths(in []string, max int) ([]string, error) {
	if len(in) > max {
		return nil, invalid("no máximo %d caminhos", max)
	}
	seen := map[string]bool{}
	var out []string
	for _, p := range in {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		if !strings.HasPrefix(p, "/") || strings.ContainsRune(p, 0) || len(p) > 4096 {
			return nil, invalid("caminho inválido: %q", p)
		}
		p = path.Clean(p)
		if !seen[p] {
			seen[p] = true
			out = append(out, p)
		}
	}
	return out, nil
}

// Enqueue valida e coloca a execução na fila.
func (s *Service) Enqueue(ctx context.Context, req RunRequest) (store.Run, error) {
	run, err := s.buildRun(ctx, req)
	if err != nil {
		return store.Run{}, err
	}
	if err := s.DB.InsertRun(ctx, &run); err != nil {
		if errors.Is(err, store.ErrDuplicate) && req.IdempotencyKey != "" {
			// Mesmo pedido repetido (clique duplo, nova tentativa do cliente): devolve a execução original.
			runs, lerr := s.DB.ListRuns(ctx, store.RunFilter{Limit: 500})
			if lerr == nil {
				for _, r := range runs {
					if r.IdempotencyKey == req.IdempotencyKey {
						return r, nil
					}
				}
			}
		}
		return store.Run{}, err
	}
	s.publishRun(ctx, run.ID)
	s.Wake()
	return s.DB.GetRun(ctx, run.ID)
}

func (s *Service) buildRun(ctx context.Context, req RunRequest) (store.Run, error) {
	run := store.Run{ID: NewRunID(s.DB.Now()), Kind: req.Kind, Origin: "manual", RequestedBy: req.RequestedBy,
		IdempotencyKey: req.IdempotencyKey, Incremental: req.Incremental, Priority: req.Priority}
	switch req.Kind {
	case report.KindFiles:
		paths, err := CleanPaths(req.Paths, 64)
		if err != nil {
			return run, err
		}
		if !req.Accounts.Empty() {
			uids, apaths, owners, err := s.accountScope(ctx, req.Accounts)
			if err != nil {
				return run, err
			}
			for _, p := range apaths {
				if !slices.Contains(paths, p) {
					paths = append(paths, p)
				}
			}
			run.Accounts, run.Owners = uids, owners
		}
		if len(paths) == 0 {
			return run, invalid("informe ao menos um caminho ou uma conta")
		}
		excl, err := CleanPaths(req.Exclude, 256)
		if err != nil {
			return run, err
		}
		run.Paths, run.Exclude = paths, excl
	case report.KindProcesses:
		run.Incremental = false
	case report.KindIntegrity, report.KindUpdates:
		// Verificações do sistema inteiro: o escopo é fixo (o executor recusa caminhos).
		if len(req.Paths) > 0 || len(req.Exclude) > 0 || !req.Accounts.Empty() {
			return run, invalid("execução do tipo %s não recebe caminhos nem contas", req.Kind)
		}
		run.Incremental = false
	default:
		return run, invalid("tipo de execução desconhecido: %q", req.Kind)
	}
	if req.Priority < -10 || req.Priority > 10 {
		return run, invalid("prioridade fora de -10..10")
	}
	p, err := s.ResolveProfile(ctx, req.Profile)
	if err != nil {
		return run, err
	}
	run.Profile = p
	return run, nil
}

// Hardware devolve o hardware informado pelo executor (guardado por 10 minutos).
func (s *Service) Hardware(ctx context.Context) (ipc.Hardware, error) {
	s.mu.Lock()
	if s.hw != nil && time.Since(s.hwAt) < 10*time.Minute {
		hw := *s.hw
		s.mu.Unlock()
		return hw, nil
	}
	s.mu.Unlock()
	var hw ipc.Hardware
	if err := s.Exec.Call(ctx, ipc.OpHardware, nil, &hw); err != nil {
		return hw, err
	}
	s.mu.Lock()
	s.hw, s.hwAt = &hw, time.Now()
	s.mu.Unlock()
	return hw, nil
}

func toProfileHW(hw ipc.Hardware) profile.Hardware {
	return profile.Hardware{CPUs: hw.CPUs, MemoryBytes: hw.MemoryBytes, Rotational: hw.Rotational, DiskType: hw.DiskType}
}

// ProfileHardware converte o hardware do executor no usado pelas travas dos perfis.
func ProfileHardware(hw ipc.Hardware) profile.Hardware { return toProfileHW(hw) }

// Profiles devolve os perfis efetivos: os pré-definidos para o hardware, sobrepostos pelos personalizados.
func (s *Service) Profiles(ctx context.Context) ([]report.Profile, map[string]bool, error) {
	custom, err := s.DB.ResourceProfiles(ctx)
	if err != nil {
		return nil, nil, err
	}
	var presets []report.Profile
	if hw, err := s.Hardware(ctx); err == nil {
		presets = profile.Presets(toProfileHW(hw))
	} else {
		// Sem executor ainda não dá para calcular os limites; usa um servidor mínimo (1 núcleo, 1 GiB), que só
		// produz limites conservadores. O executor recalcula as travas de qualquer forma.
		presets = profile.Presets(profile.Hardware{CPUs: 1, MemoryBytes: 1 << 30})
	}
	isCustom := map[string]bool{}
	out := make([]report.Profile, 0, len(presets)+len(custom))
	seen := map[string]bool{}
	for _, p := range presets {
		if c, ok := custom[p.Name]; ok {
			p = c.Profile
			isCustom[p.Name] = true
		}
		seen[p.Name] = true
		out = append(out, p)
	}
	for name, c := range custom {
		if !seen[name] {
			isCustom[name] = true
			out = append(out, c.Profile)
		}
	}
	return out, isCustom, nil
}

// ResolveProfile encontra o perfil pelo nome (vazio = padrão).
func (s *Service) ResolveProfile(ctx context.Context, name string) (report.Profile, error) {
	if name == "" {
		name = profile.Standard
	}
	all, _, err := s.Profiles(ctx)
	if err != nil {
		return report.Profile{}, err
	}
	for _, p := range all {
		if p.Name == name {
			return p, nil
		}
	}
	return report.Profile{}, invalid("perfil desconhecido: %q", name)
}

// Wake antecipa o próximo ciclo (execução nova na fila).
func (s *Service) Wake() {
	if s.wake == nil {
		return
	}
	select {
	case s.wake <- struct{}{}:
	default:
	}
}

// Run executa o laço até o contexto acabar: recuperação, agendamentos, despacho, acompanhamento e limpeza.
func (s *Service) Run(ctx context.Context) {
	s.Config.defaults()
	s.mu.Lock()
	if s.wake == nil {
		s.wake = make(chan struct{}, 1)
	}
	if s.canceling == nil {
		s.canceling = map[string]bool{}
	}
	s.mu.Unlock()
	s.Recover(ctx)
	t := time.NewTicker(s.Config.Tick)
	defer t.Stop()
	for {
		s.Step(ctx)
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		case <-s.wake:
		}
	}
}

// Step é um ciclo do laço (exportado para os testes).
func (s *Service) Step(ctx context.Context) {
	s.Config.defaults()
	s.fireSchedules(ctx)
	s.monitor(ctx)
	s.dispatch(ctx)
	if time.Since(s.lastSweep) > time.Hour {
		s.lastSweep = time.Now()
		s.sweep(ctx)
	}
}

// Recover reconcilia depois de um reinício do core: reservas que não chegaram ao executor voltam para a fila;
// execuções em andamento seguem sendo acompanhadas (a unidade transitória não depende do core).
func (s *Service) Recover(ctx context.Context) {
	active, err := s.DB.ActiveRuns(ctx)
	if err != nil {
		s.Logger.Error("recuperação: falha ao ler execuções ativas", "erro", err)
		return
	}
	for _, r := range active {
		if r.Status != store.RunReserved {
			continue
		}
		var st ipc.RunState
		err := s.Exec.Call(ctx, ipc.OpRunStatus, ipc.RunRef{RunID: r.ID}, &st)
		switch {
		case err == nil:
			_ = s.DB.MarkRunning(ctx, r.ID, s.Config.Lease)
		case isCode(err, ipc.CodeNotFound):
			_ = s.DB.Requeue(ctx, r.ID, "reserva perdida no reinício do core")
		default:
			// Executor fora: deixa reservada; o próximo ciclo tenta de novo.
		}
	}
	if len(active) > 0 {
		s.Logger.Info("recuperação concluída", "ativas", len(active))
	}
}

func isCode(err error, code string) bool {
	var ie *ipc.Error
	return errors.As(err, &ie) && ie.Code == code
}

func (s *Service) dispatch(ctx context.Context) {
	for _, kind := range report.Kinds {
		limit := s.Config.Concurrency[kind]
		for {
			n, err := s.DB.CountActive(ctx, kind)
			if err != nil || n >= limit {
				break
			}
			r, err := s.DB.ReserveNext(ctx, kind, s.Config.Lease)
			if errors.Is(err, store.ErrNotFound) {
				break
			}
			if err != nil {
				s.Logger.Error("falha ao reservar execução", "erro", err)
				return
			}
			if !s.start(ctx, r) {
				return // executor fora: tenta no próximo ciclo
			}
		}
	}
}

// start entrega a execução ao executor; devolve false quando o executor está fora (a execução volta para a fila).
func (s *Service) start(ctx context.Context, r store.Run) bool {
	req := report.Request{RunID: r.ID, Kind: r.Kind, Paths: r.Paths, Exclude: r.Exclude, Incremental: r.Incremental,
		Profile: r.Profile, Owners: r.Owners}
	// Configuração de regras e do LMD vigente no início da execução (fica gravada no pedido, no relatório).
	if r.Kind == report.KindFiles {
		if on, err := s.DB.LMDEnabled(ctx); err == nil {
			req.LMD = on
		} else {
			s.Logger.Warn("configuração do LMD não lida; segue desligado", "execucao", r.ID, "erro", err)
		}
	}
	if list, err := s.DB.DisabledRuleSources(ctx); err == nil {
		req.DisabledRuleSources = list
	} else {
		s.Logger.Warn("fontes de regras desativadas não lidas; seguem todas ativas", "execucao", r.ID, "erro", err)
	}
	var st ipc.RunState
	err := s.Exec.Call(ctx, ipc.OpRunStart, ipc.RunStart{Request: req}, &st)
	switch {
	case err == nil, isCode(err, ipc.CodeAlreadyExists):
		if err := s.DB.MarkRunning(ctx, r.ID, s.Config.Lease); err != nil {
			s.Logger.Error("falha ao marcar execução iniciada", "execucao", r.ID, "erro", err)
		}
		s.Logger.Info("execução entregue ao executor", "execucao", r.ID, "tipo", r.Kind, "perfil", r.Profile.Name)
	case IsUnavailable(err) || ctx.Err() != nil:
		_ = s.DB.Requeue(ctx, r.ID, err.Error())
		s.publishRun(ctx, r.ID)
		return false
	default:
		// Recusa do executor (caminho, limite, pedido inválido): não adianta tentar de novo.
		if s.DB.FinishRun(ctx, r.ID, string(report.StatusFailed), nil, "recusada pelo executor: "+err.Error()) == nil {
			s.notifyRun(ctx, r.ID, nil)
		}
		s.Logger.Warn("execução recusada pelo executor", "execucao", r.ID, "erro", err)
	}
	s.publishRun(ctx, r.ID)
	return true
}

func (s *Service) monitor(ctx context.Context) {
	active, err := s.DB.ActiveRuns(ctx)
	if err != nil {
		return
	}
	for _, r := range active {
		if r.Status != store.RunRunning {
			if r.Status == store.RunReserved && r.LeaseUntil != nil && s.DB.Now().After(*r.LeaseUntil) {
				_ = s.DB.Requeue(ctx, r.ID, "reserva expirou")
			}
			continue
		}
		if err := s.follow(ctx, r); err != nil {
			if IsUnavailable(err) {
				return // executor fora; as unidades continuam rodando e a ingestão retoma pelo offset
			}
			s.Logger.Warn("falha ao acompanhar execução", "execucao", r.ID, "erro", err)
		}
	}
}

// follow lê o estado da unidade, grava progresso, ingere achados novos e finaliza quando a unidade terminou.
func (s *Service) follow(ctx context.Context, r store.Run) error {
	var st ipc.RunState
	err := s.Exec.Call(ctx, ipc.OpRunStatus, ipc.RunRef{RunID: r.ID}, &st)
	if isCode(err, ipc.CodeNotFound) {
		s.finish(ctx, r, string(report.StatusInterrupted), nil, "o executor não conhece mais esta execução")
		return nil
	}
	if err != nil {
		return err
	}
	if st.Progress != nil {
		if err := s.DB.UpdateProgress(ctx, r.ID, *st.Progress, st.Frozen, s.Config.Lease); err != nil {
			return err
		}
	}
	ended := st.Active != "active" && st.Active != "activating" && st.Active != "deactivating" && st.Active != "reloading"
	// Ingere em blocos até alcançar o fim do arquivo (com teto por ciclo para não travar o laço).
	drained := false
	for i := 0; i < 50 && !drained; i++ {
		more, err := s.ingest(ctx, r.ID, st.Dir)
		if err != nil {
			return err
		}
		drained = !more
	}
	// Só finaliza com todos os achados no banco; o resto entra nos próximos ciclos.
	if !ended || !drained {
		s.publishRun(ctx, r.ID)
		return nil
	}
	if st.Summary != nil {
		status := string(st.Summary.Status)
		if !store.IsFinal(status) {
			status = string(report.StatusFailed)
		}
		s.snapshot(ctx, r, st.Dir)
		s.hostReports(ctx, r, st.Dir, status)
		s.finish(ctx, r, status, st.Summary, st.Summary.Error)
		return nil
	}
	s.mu.Lock()
	canceled := s.canceling[r.ID]
	s.mu.Unlock()
	switch {
	case canceled:
		s.finish(ctx, r, string(report.StatusCanceled), nil, "cancelada pelo operador")
	case st.Result == "timeout":
		s.finish(ctx, r, string(report.StatusInterrupted), nil, "tempo máximo da execução atingido")
	case st.Result == "oom-kill":
		s.finish(ctx, r, string(report.StatusInterrupted), nil, "memória do perfil esgotada (encerrada pelo limite)")
	default:
		s.finish(ctx, r, string(report.StatusFailed), nil,
			fmt.Sprintf("a execução terminou sem resumo (resultado %q, código %d)", st.Result, st.ExitCode))
	}
	return nil
}

// snapshot guarda a lista de processos e o inventário de persistência de uma inspeção. Sem os arquivos (inspeção que
// falhou cedo) a execução finaliza do mesmo jeito e as telas mostram o instantâneo anterior.
func (s *Service) snapshot(ctx context.Context, r store.Run, dir string) {
	if r.Kind != report.KindProcesses || dir == "" {
		return
	}
	procs, err := readJSONFile(filepath.Join(dir, report.ProcessesFile))
	if err == nil {
		var pers []byte
		if pers, err = readJSONFile(filepath.Join(dir, report.PersistenceFile)); err == nil {
			err = s.DB.SaveSnapshot(ctx, store.Snapshot{RunID: r.ID, TakenAt: s.DB.Now(), Processes: procs, Persistence: pers})
		}
	}
	if err != nil {
		s.Logger.Warn("instantâneo da inspeção não guardado", "execucao", r.ID, "erro", err)
	}
}

// Relatório e motor de cada tipo de verificação do sistema. O motor é o dos achados que a execução completa refaz
// por inteiro: o que não aparece mais foi resolvido (pacote reinstalado, correção aplicada).
var systemReports = map[report.Kind][]struct {
	file, name, engine string
}{
	report.KindIntegrity: {{report.IntegrityFile, store.HostReportIntegrity, integrity.Engine}},
	report.KindUpdates:   {{report.UpdatesFile, store.HostReportUpdates, updates.Engine}},
	// Processos e portas ocultos: só o relatório; achado de oculto nunca se resolve sozinho.
	report.KindProcesses: {{report.HiddenFile, store.HostReportHidden, ""}},
}

// hostReports guarda os relatórios das verificações do sistema e resolve o que sumiu numa execução completa.
func (s *Service) hostReports(ctx context.Context, r store.Run, dir, status string) {
	if dir == "" {
		return
	}
	for _, sr := range systemReports[r.Kind] {
		data, err := readJSONFile(filepath.Join(dir, sr.file))
		if err == nil {
			err = s.DB.SaveHostReport(ctx, store.HostReport{RunID: r.ID, Name: sr.name, TakenAt: s.DB.Now(), Data: data})
		}
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			s.Logger.Warn("relatório da verificação não guardado", "execucao", r.ID, "relatorio", sr.name, "erro", err)
		}
		if sr.engine == "" || status != string(report.StatusCompleted) {
			continue
		}
		n, err := s.DB.ResolveMissing(ctx, r.ID, sr.engine)
		if err != nil {
			s.Logger.Warn("achados ausentes não resolvidos", "execucao", r.ID, "erro", err)
		} else if n > 0 {
			s.Logger.Info("achados que sumiram resolvidos", "execucao", r.ID, "motor", sr.engine, "achados", n)
		}
	}
}

// ingest lê um bloco de achados e devolve se ainda há mais.
func (s *Service) ingest(ctx context.Context, runID, dir string) (bool, error) {
	if dir == "" {
		return false, nil
	}
	r, err := s.DB.GetRun(ctx, runID)
	if err != nil {
		return false, err
	}
	list, next, bad, err := readFindings(filepath.Join(dir, report.FindingsFile), r.FindingsOffset)
	if err != nil {
		return false, err
	}
	if next == r.FindingsOffset {
		return false, nil
	}
	if bad > 0 {
		s.Logger.Warn("linhas de achado inválidas descartadas", "execucao", runID, "linhas", bad)
	}
	res, err := s.DB.IngestFindings(ctx, runID, list, next)
	if err != nil {
		return false, err
	}
	for _, id := range res.Changed {
		s.publish(Event{Type: "finding", ID: fmt.Sprint(id)})
	}
	s.notifyFindings(ctx, runID, res.Changed)
	return true, nil
}

// notifyFindings entrega à caixa de saída os achados novos ou reabertos (as regras filtram por severidade).
func (s *Service) notifyFindings(ctx context.Context, runID string, ids []int64) {
	if s.Notifier == nil || len(ids) == 0 {
		return
	}
	events := make([]notify.Event, 0, len(ids))
	for _, id := range ids {
		f, err := s.DB.GetFinding(ctx, id)
		if err != nil {
			continue
		}
		events = append(events, notify.FindingEvent(f, runID))
	}
	if err := s.Notifier.Emit(ctx, events...); err != nil {
		s.Logger.Warn("achados não entraram na caixa de saída de notificações", "execucao", runID, "erro", err)
	}
}

// notifyRun avisa falha, interrupção, resultado parcial e problema de motor no fim da execução.
func (s *Service) notifyRun(ctx context.Context, id string, sum *report.Summary) {
	if s.Notifier == nil {
		return
	}
	r, err := s.DB.GetRun(ctx, id)
	if err != nil {
		return
	}
	if err := s.Notifier.Emit(ctx, notify.RunEvents(r, sum)...); err != nil {
		s.Logger.Warn("fim da execução não entrou na caixa de saída de notificações", "execucao", id, "erro", err)
	}
}

func (s *Service) finish(ctx context.Context, r store.Run, status string, sum *report.Summary, msg string) {
	err := s.DB.FinishRun(ctx, r.ID, status, sum, msg)
	if err != nil && !errors.Is(err, store.ErrConflict) {
		s.Logger.Error("falha ao finalizar execução", "execucao", r.ID, "erro", err)
		return
	}
	if err == nil {
		s.notifyRun(ctx, r.ID, sum)
	}
	s.mu.Lock()
	delete(s.canceling, r.ID)
	s.mu.Unlock()
	s.Logger.Info("execução finalizada", "execucao", r.ID, "estado", status)
	s.publishRun(ctx, r.ID)
}

// Cancel cancela uma execução na fila ou em andamento.
func (s *Service) Cancel(ctx context.Context, id string) (store.Run, error) {
	r, err := s.DB.GetRun(ctx, id)
	if err != nil {
		return r, err
	}
	switch {
	case store.IsFinal(r.Status):
		return r, ErrConflict
	case r.Status == store.RunQueued:
		if ok, err := s.DB.CancelQueued(ctx, id); err != nil {
			return r, err
		} else if !ok {
			return r, ErrConflict
		}
	default:
		s.mu.Lock()
		if s.canceling == nil {
			s.canceling = map[string]bool{}
		}
		s.canceling[id] = true
		s.mu.Unlock()
		var st ipc.RunState
		if err := s.Exec.Call(ctx, ipc.OpRunCancel, ipc.RunRef{RunID: id}, &st); err != nil && !isCode(err, ipc.CodeNotFound) {
			return r, err
		}
		s.Wake()
	}
	s.publishRun(ctx, id)
	return s.DB.GetRun(ctx, id)
}

// SetPaused pausa ou retoma uma execução em andamento.
func (s *Service) SetPaused(ctx context.Context, id string, paused bool) (store.Run, error) {
	r, err := s.DB.GetRun(ctx, id)
	if err != nil {
		return r, err
	}
	if r.Status != store.RunRunning {
		return r, ErrConflict
	}
	op := ipc.OpRunResume
	if paused {
		op = ipc.OpRunPause
	}
	var st ipc.RunState
	if err := s.Exec.Call(ctx, op, ipc.RunRef{RunID: id}, &st); err != nil {
		return r, err
	}
	if err := s.DB.SetPaused(ctx, id, paused); err != nil {
		return r, err
	}
	s.publishRun(ctx, id)
	return s.DB.GetRun(ctx, id)
}

// SetLimits troca os limites de uma execução em andamento pelos de outro perfil (aplicado na hora pelo cgroup).
func (s *Service) SetLimits(ctx context.Context, id, profileName, actor string) (store.Run, error) {
	r, err := s.DB.GetRun(ctx, id)
	if err != nil {
		return r, err
	}
	if r.Status != store.RunRunning {
		return r, ErrConflict
	}
	p, err := s.ResolveProfile(ctx, profileName)
	if err != nil {
		return r, err
	}
	var st ipc.RunState
	if err := s.Exec.Call(ctx, ipc.OpRunLimits, ipc.RunLimits{RunID: id, Profile: p}, &st); err != nil {
		return r, err
	}
	eff := withLimits(r.Profile, p)
	eff.Name = p.Name
	if st.Limits != nil {
		eff = withLimits(eff, *st.Limits)
	}
	return s.recordAdjustment(ctx, r, eff, actor)
}

// Adjust muda limites de CPU, memória e E/S da execução em andamento, campo a campo. O executor confere as travas
// sobre o perfil efetivo que ele guarda; o core só registra o resultado que o executor devolveu.
func (s *Service) Adjust(ctx context.Context, id string, adj ipc.RunAdjust, actor string) (store.Run, error) {
	r, err := s.DB.GetRun(ctx, id)
	if err != nil {
		return r, err
	}
	if r.Status != store.RunRunning {
		return r, ErrConflict
	}
	if adj.Empty() {
		return r, invalid("informe ao menos um limite para ajustar")
	}
	adj.RunID = id
	var st ipc.RunState
	if err := s.Exec.Call(ctx, ipc.OpRunAdjust, adj, &st); err != nil {
		return r, err
	}
	eff := r.Profile
	if st.Limits != nil {
		eff = withLimits(eff, *st.Limits)
	} else {
		// Executor que não devolveu o efetivo: registra o pedido (já aceito pelas travas do executor).
		if adj.CPUQuotaPercent != nil {
			eff.CPUQuotaPercent = *adj.CPUQuotaPercent
		}
		if adj.MemoryMaxBytes != nil {
			eff.MemoryMaxBytes = *adj.MemoryMaxBytes
		}
		if adj.IOReadBytesPerSec != nil {
			eff.IOReadBytesPerSec = *adj.IOReadBytesPerSec
		}
		if adj.IOWeight != nil {
			eff.IOWeight = *adj.IOWeight
		}
	}
	return s.recordAdjustment(ctx, r, eff, actor)
}

// withLimits copia para base os quatro limites ajustáveis de from.
func withLimits(base, from report.Profile) report.Profile {
	base.CPUQuotaPercent, base.MemoryMaxBytes = from.CPUQuotaPercent, from.MemoryMaxBytes
	base.IOReadBytesPerSec, base.IOWeight = from.IOReadBytesPerSec, from.IOWeight
	return base
}

func (s *Service) recordAdjustment(ctx context.Context, r store.Run, eff report.Profile, actor string) (store.Run, error) {
	adj := store.Adjustment{At: s.DB.Now(), Actor: actor, Before: store.LimitsOf(r.Profile), After: store.LimitsOf(eff)}
	if err := s.DB.RecordAdjustment(ctx, r.ID, eff, adj); err != nil {
		return r, err
	}
	s.publishRun(ctx, r.ID)
	return s.DB.GetRun(ctx, r.ID)
}

// HardwareFresh consulta o hardware no executor sem o cache (a pressão muda a todo instante).
func (s *Service) HardwareFresh(ctx context.Context) (ipc.Hardware, error) {
	var hw ipc.Hardware
	if err := s.Exec.Call(ctx, ipc.OpHardware, nil, &hw); err != nil {
		return hw, err
	}
	s.mu.Lock()
	s.hw, s.hwAt = &hw, time.Now()
	s.mu.Unlock()
	return hw, nil
}

// Suggest calcula o perfil sugerido para o hardware, a pressão típica (média de 5 minutos) e o histórico das
// últimas execuções de arquivos (fração do tempo limitada por pressão).
func (s *Service) Suggest(ctx context.Context) (profile.Suggestion, ipc.Hardware, profile.Load, error) {
	hw, err := s.HardwareFresh(ctx)
	if err != nil {
		return profile.Suggestion{}, hw, profile.Load{}, err
	}
	load := profile.Load{LoadAvg: hw.LoadAvg}
	if p := hw.Pressure; p != nil && p.Available {
		load.PSI, load.CPU, load.IO, load.Memory = true, p.CPU.Avg300, p.IO.Avg300, p.Memory.Avg300
	}
	if runs, err := s.DB.RecentFinishedRuns(ctx, report.KindFiles, 10); err == nil {
		var limited, total float64
		for _, r := range runs {
			if r.Summary == nil || r.Summary.Metrics == nil {
				continue
			}
			d := r.Summary.FinishedAt.Sub(r.Summary.StartedAt).Seconds()
			if d <= 0 {
				continue
			}
			load.Runs++
			total += d
			limited += min(d, r.Summary.Metrics.Throttle.LimitedSeconds)
		}
		if total > 0 {
			load.LimitedRatio = limited / total
		}
	}
	return profile.Suggest(toProfileHW(hw), load), hw, load, nil
}

func (s *Service) fireSchedules(ctx context.Context) {
	due, err := s.DB.DueSchedules(ctx, s.DB.Now())
	if err != nil {
		return
	}
	for _, sc := range due {
		run, err := s.buildRun(ctx, RunRequest{Kind: sc.Kind, Paths: sc.Paths, Exclude: sc.Exclude,
			Incremental: sc.Incremental, Profile: sc.Profile, RequestedBy: "agendamento: " + sc.Name,
			Accounts: sc.Accounts})
		if err != nil {
			// Agendamento com dado que não vale mais (perfil apagado): registra e avança para não repetir sem parar.
			s.Logger.Warn("agendamento não pôde gerar execução", "agendamento", sc.ID, "erro", err)
			run = store.Run{ID: NewRunID(s.DB.Now()), Kind: sc.Kind}
			if _, ferr := s.DB.FireSchedule(ctx, sc, &run, 0); ferr == nil {
				if s.DB.FinishRun(ctx, run.ID, string(report.StatusFailed), nil, "agendamento inválido: "+err.Error()) == nil {
					s.notifyRun(ctx, run.ID, nil)
				}
			}
			continue
		}
		fired, err := s.DB.FireSchedule(ctx, sc, &run, s.Config.MissedGrace)
		if err != nil {
			s.Logger.Error("falha ao disparar agendamento", "agendamento", sc.ID, "erro", err)
			continue
		}
		if fired {
			s.Logger.Info("agendamento disparado", "agendamento", sc.ID, "execucao", run.ID)
			s.publishRun(ctx, run.ID)
		} else {
			s.Logger.Info("horário perdido pulado pela política do agendamento", "agendamento", sc.ID)
		}
		s.publish(Event{Type: "schedule", ID: fmt.Sprint(sc.ID)})
	}
}

// sweep apaga, no executor, os diretórios brutos de execuções terminadas há mais que a retenção (os achados já
// estão no banco).
func (s *Service) sweep(ctx context.Context) {
	var list ipc.RunList
	if err := s.Exec.Call(ctx, ipc.OpRunList, nil, &list); err != nil {
		return
	}
	limit := s.DB.Now().Add(-s.Config.Retention)
	for _, st := range list.Runs {
		r, err := s.DB.GetRun(ctx, st.RunID)
		if err != nil || !store.IsFinal(r.Status) || r.FinishedAt == nil || r.FinishedAt.After(limit) {
			continue
		}
		if err := s.Exec.Call(ctx, ipc.OpRunCleanup, ipc.RunRef{RunID: st.RunID}, nil); err == nil {
			s.Logger.Info("diretório de execução antiga removido", "execucao", st.RunID)
		}
	}
}

func (s *Service) publish(ev Event) {
	if s.Hub != nil {
		s.Hub.Publish(ev)
	}
}

// publishRun avisa a interface com o estado resumido da execução.
func (s *Service) publishRun(ctx context.Context, id string) {
	if s.Hub == nil {
		return
	}
	r, err := s.DB.GetRun(ctx, id)
	if err != nil {
		return
	}
	data, _ := json.Marshal(map[string]any{"status": r.Status, "phase": r.Phase, "paused": r.Paused,
		"files_processed": r.FilesProcessed, "files_eligible": r.FilesEligible, "findings": r.FindingsCount})
	s.Hub.Publish(Event{Type: "run", ID: id, Data: data})
}

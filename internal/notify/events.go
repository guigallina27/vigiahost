package notify

import (
	"context"
	"fmt"
	"time"

	"github.com/guigallina27/vigiahost/internal/report"
	"github.com/guigallina27/vigiahost/internal/store"
)

var engineNames = map[string]string{"yara-x": "YARA-X", "clamav": "ClamAV"}

func engineLabel(e string) string {
	if n, ok := engineNames[e]; ok {
		return n
	}
	return e
}

// FindingEvent descreve um achado novo ou reaberto. A chave é o achado: reaparecer dentro da janela não notifica.
func FindingEvent(f store.Finding, runID string) Event {
	it := Item{Event: store.EventFindingNew, Severity: f.Severity, FindingID: f.ID, RunID: runID, Engine: f.Engine,
		Title: engineLabel(f.Engine) + ": " + f.Signature, Detail: truncateRunes(f.Description, 300), SHA256: f.SHA256,
		At: f.LastSeen}
	switch {
	case f.Location != nil:
		it.Path = f.Location.Path
	case f.Process != nil:
		it.Path = f.Process.Exe
		if it.SHA256 == "" {
			it.SHA256 = f.Process.ExeSHA256
		}
	case f.Persistence != nil:
		it.Path = f.Persistence.Path
	}
	if !ValidSeverity(it.Severity) {
		it.Severity = string(report.SeverityMedium)
	}
	return Event{Item: it, Key: fmt.Sprintf("finding:%d", f.ID)}
}

var kindLabel = map[report.Kind]string{report.KindFiles: "varredura de arquivos", report.KindProcesses: "inspeção de processos"}

// RunEvents descreve o fim de uma execução: falha ou interrupção, resultado parcial e falha de motor ou do
// autoteste (com o resumo da execução). Execução concluída ou cancelada pelo operador não gera evento.
func RunEvents(r store.Run, sum *report.Summary) []Event {
	var out []Event
	at := time.Time{}
	if r.FinishedAt != nil {
		at = *r.FinishedAt
	}
	what := kindLabel[r.Kind]
	if what == "" {
		what = "execução"
	}
	switch report.Status(r.Status) {
	case report.StatusFailed, report.StatusEngineError, report.StatusInterrupted:
		title := fmt.Sprintf("Execução %s (%s) terminou com falha", r.ID, what)
		if report.Status(r.Status) == report.StatusInterrupted {
			title = fmt.Sprintf("Execução %s (%s) foi interrompida", r.ID, what)
		}
		out = append(out, Event{Item: Item{Event: store.EventRunFailed, Severity: string(report.SeverityHigh),
			Title: title, Detail: truncateRunes(r.Error, 400), RunID: r.ID, At: at}, Key: "run:" + r.ID})
	case report.StatusPartial:
		out = append(out, Event{Item: Item{Event: store.EventRunPartial, Severity: string(report.SeverityMedium),
			Title:  fmt.Sprintf("Execução %s (%s) terminou parcial", r.ID, what),
			Detail: truncateRunes(firstNonEmpty(r.Error, "parte dos arquivos elegíveis não foi analisada; veja a cobertura no painel"), 400),
			RunID:  r.ID, At: at}, Key: "run:" + r.ID})
	}
	if sum != nil {
		for _, e := range sum.Engines {
			var title, detail string
			switch {
			case !e.Available:
				title, detail = "Motor "+engineLabel(e.Engine)+" indisponível na execução", e.Error
			case e.SelfTest.Ran && !e.SelfTest.Passed():
				title, detail = "Autoteste do "+engineLabel(e.Engine)+" falhou", e.SelfTest.Detail
			default:
				continue
			}
			out = append(out, Event{Item: Item{Event: store.EventEngineSelfTest, Severity: string(report.SeverityHigh),
				Title: title, Detail: truncateRunes(detail, 400), RunID: r.ID, Engine: e.Engine, At: at},
				Key: "engine:" + e.Engine})
		}
	}
	return out
}

// BackupFailedEvent descreve a falha da cópia automática do banco.
func BackupFailedEvent(err error, at time.Time) Event {
	return Event{Item: Item{Event: store.EventBackupFailed, Severity: string(report.SeverityHigh),
		Title: "Cópia automática do banco falhou", Detail: truncateRunes(err.Error(), 400), At: at}, Key: "backup:failed"}
}

func firstNonEmpty(v ...string) string {
	for _, s := range v {
		if s != "" {
			return s
		}
	}
	return ""
}

// watchExecutor confere o executor no intervalo configurado. Depois de ProbeFailures falhas seguidas avisa que ele
// está indisponível; quando volta, avisa a normalização (mesma regra).
func (s *Service) watchExecutor(ctx context.Context) {
	if s.ExecutorProbe == nil || time.Since(s.lastProbe) < s.ProbeEvery {
		return
	}
	s.lastProbe = time.Now()
	pctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	err := s.ExecutorProbe(pctx)
	cancel()
	if ctx.Err() != nil {
		return
	}
	var ev *Event
	if err != nil {
		s.execFails++
		if !s.execDown && s.execFails >= s.ProbeFailures {
			s.execDown = true
			ev = &Event{Item: Item{Event: store.EventExecutorUnavailable, Severity: string(report.SeverityCritical),
				Title: "Executor indisponível", Detail: "O core não consegue falar com o executor: " +
					truncateRunes(err.Error(), 300) + ". Varreduras e inspeções ficam paradas até ele voltar.",
				At: s.now()}, Key: "executor:down"}
		}
	} else {
		if s.execDown {
			ev = &Event{Item: Item{Event: store.EventExecutorUnavailable, Severity: string(report.SeverityInfo),
				Title: "Executor voltou a responder", Detail: "As execuções na fila seguem normalmente.",
				Resolved: true, At: s.now()}, Key: "executor:up"}
		}
		s.execDown, s.execFails = false, 0
	}
	if ev != nil {
		if err := s.Emit(ctx, *ev); err != nil {
			s.Logger.Warn("aviso de executor não entrou na caixa de saída", "erro", err)
		}
	}
}

// DefaultDedupMinutes é a janela de deduplicação sugerida para cada evento: achados não se repetem por um dia; avisos
// de motor e de cópia do banco, por seis horas; o resto, por uma hora.
func DefaultDedupMinutes(event string) int {
	switch event {
	case store.EventFindingNew:
		return 1440
	case store.EventEngineSelfTest, store.EventBackupFailed:
		return 360
	}
	return 60
}

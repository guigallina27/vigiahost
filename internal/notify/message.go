package notify

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"slices"
	"strings"
	"time"
	"unicode"

	"github.com/guigallina27/vigiahost/internal/store"
)

// Message é o que sai por um canal: uma mensagem da caixa de saída já decodificada.
type Message struct {
	// ID é estável entre tentativas (msg_<id da caixa de saída>): o receptor do webhook usa para descartar repetição.
	ID             string
	Event          string
	Count          int
	SeverityCounts map[string]int
	Items          []Item
	Host           string
	Version        string
	CreatedAt      time.Time
}

// MessageFrom monta a mensagem a partir da linha da caixa de saída.
func MessageFrom(e store.OutboxEntry, host, version string) Message {
	m := Message{ID: fmt.Sprintf("msg_%d", e.ID), Event: e.Event, Count: e.ItemCount, SeverityCounts: e.SeverityCounts,
		Host: host, Version: version, CreatedAt: e.CreatedAt}
	for _, raw := range e.Items {
		var it Item
		if json.Unmarshal(raw, &it) == nil {
			m.Items = append(m.Items, it)
		}
	}
	if m.Count < len(m.Items) {
		m.Count = len(m.Items)
	}
	return m
}

var severityLabel = map[string]string{
	"critical": "crítica", "high": "alta", "medium": "média", "low": "baixa", "info": "informativa",
}

// SeverityLabel traduz a severidade para o texto das mensagens.
func SeverityLabel(s string) string {
	if l, ok := severityLabel[s]; ok {
		return l
	}
	return s
}

// highest devolve a maior severidade presente na contagem.
func highest(counts map[string]int) string {
	best, rank := "", 0
	for sev, n := range counts {
		if n > 0 && severityRank[sev] > rank {
			best, rank = sev, severityRank[sev]
		}
	}
	return best
}

// Summary é a frase que resume a mensagem (assunto do e-mail sem o prefixo, campo summary do webhook).
func Summary(event string, count int, items []Item, severityCounts map[string]int) string {
	var first Item
	if len(items) > 0 {
		first = items[0]
	}
	switch event {
	case store.EventTest:
		return "mensagem de teste"
	case store.EventFindingNew:
		if count <= 1 {
			return "achado novo de severidade " + SeverityLabel(first.Severity)
		}
		return fmt.Sprintf("%d achados novos (maior severidade: %s)", count, SeverityLabel(highest(severityCounts)))
	case store.EventRunFailed, store.EventRunPartial, store.EventEngineSelfTest, store.EventBackupFailed,
		store.EventExecutorUnavailable:
		title := CleanText(first.Title, 120)
		if count > 1 {
			return fmt.Sprintf("%s (e mais %d)", title, count-1)
		}
		return title
	}
	return event
}

// Subject é o assunto do e-mail: produto, servidor e resumo.
func (m Message) Subject() string {
	return "[VigiaHost] " + CleanText(m.Host, 64) + ": " + Summary(m.Event, m.Count, m.Items, m.SeverityCounts)
}

// Text é o corpo do e-mail em texto puro. Caminhos vêm do servidor monitorado e podem ser controlados por um
// atacante: caracteres de controle e de direção de texto aparecem escapados.
func (m Message) Text() string {
	var b strings.Builder
	fmt.Fprintf(&b, "VigiaHost no servidor %s\n\n", CleanText(m.Host, 128))
	summary := Summary(m.Event, m.Count, m.Items, m.SeverityCounts)
	b.WriteString(capitalize(summary) + ".\n")
	if m.Count > 1 && len(m.SeverityCounts) > 0 {
		var parts []string
		for _, sev := range []string{"critical", "high", "medium", "low", "info"} {
			if n := m.SeverityCounts[sev]; n > 0 {
				parts = append(parts, fmt.Sprintf("%d %s", n, SeverityLabel(sev)))
			}
		}
		b.WriteString("Por severidade: " + strings.Join(parts, ", ") + ".\n")
	}
	b.WriteString("\n")
	for i, it := range m.Items {
		fmt.Fprintf(&b, "%d. [%s] %s\n", i+1, SeverityLabel(it.Severity), CleanText(it.Title, 300))
		if it.Detail != "" {
			fmt.Fprintf(&b, "   %s\n", CleanText(it.Detail, 600))
		}
		if it.Path != "" {
			fmt.Fprintf(&b, "   Caminho: %s\n", CleanText(it.Path, 1024))
		}
		if it.SHA256 != "" {
			fmt.Fprintf(&b, "   SHA-256: %s\n", CleanText(it.SHA256, 64))
		}
		if it.FindingID > 0 {
			fmt.Fprintf(&b, "   Achado: %d\n", it.FindingID)
		}
		if it.RunID != "" {
			fmt.Fprintf(&b, "   Execução: %s\n", CleanText(it.RunID, 64))
		}
		if !it.At.IsZero() {
			fmt.Fprintf(&b, "   Quando: %s\n", it.At.UTC().Format("2006-01-02 15:04:05 UTC"))
		}
		b.WriteString("\n")
	}
	if rest := m.Count - len(m.Items); rest > 0 {
		fmt.Fprintf(&b, "E mais %d itens não listados nesta mensagem; veja todos no painel.\n\n", rest)
	}
	b.WriteString("Abra o painel do VigiaHost para revisar. As notificações nunca levam conteúdo de arquivos.\n")
	if m.Version != "" {
		fmt.Fprintf(&b, "VigiaHost %s · mensagem %s\n", CleanText(m.Version, 64), m.ID)
	}
	return b.String()
}

// Payload é o corpo JSON do webhook, no formato do Standard Webhooks (type, timestamp, data).
type Payload struct {
	Type      string      `json:"type"`
	Timestamp time.Time   `json:"timestamp"`
	Data      PayloadData `json:"data"`
}

// PayloadData é o conteúdo do evento.
type PayloadData struct {
	ID             string         `json:"id"`
	Server         string         `json:"server"`
	Version        string         `json:"version,omitempty"`
	Test           bool           `json:"test"`
	Summary        string         `json:"summary"`
	Count          int            `json:"count"`
	SeverityCounts map[string]int `json:"severity_counts"`
	Items          []Item         `json:"items"`
	ItemsTruncated bool           `json:"items_truncated"`
}

// JSON monta o corpo do webhook.
func (m Message) JSON(at time.Time) ([]byte, error) {
	items := m.Items
	if items == nil {
		items = []Item{}
	}
	counts := m.SeverityCounts
	if counts == nil {
		counts = map[string]int{}
	}
	return json.Marshal(Payload{Type: m.Event, Timestamp: at.UTC(), Data: PayloadData{ID: m.ID, Server: m.Host,
		Version: m.Version, Test: m.Event == store.EventTest, Summary: Summary(m.Event, m.Count, m.Items, counts),
		Count: m.Count, SeverityCounts: counts, Items: items, ItemsTruncated: m.Count > len(m.Items)}})
}

// bidi são os caracteres de controle de direção de texto (Trojan Source): aparecem escapados.
var bidi = []rune{'\u200e', '\u200f', '\u202a', '\u202b', '\u202c', '\u202d', '\u202e', '\u2066', '\u2067', '\u2068', '\u2069'}

// CleanText troca caracteres de controle e de direção por escapes visíveis (\u00XX) e corta em n caracteres.
func CleanText(s string, n int) string {
	var b strings.Builder
	for _, r := range s {
		switch {
		case r == unicode.ReplacementChar:
			b.WriteString(`\ufffd`)
		case unicode.IsControl(r) || slices.Contains(bidi, r):
			fmt.Fprintf(&b, `\u%04x`, r)
		default:
			b.WriteRune(r)
		}
	}
	return truncateRunes(strings.TrimSpace(b.String()), n)
}

func capitalize(s string) string {
	r := []rune(s)
	if len(r) == 0 {
		return s
	}
	r[0] = unicode.ToUpper(r[0])
	return string(r)
}

func randomHex(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

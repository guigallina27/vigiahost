package notify

import (
	"encoding/json"
	"net"
	"net/mail"
	"net/netip"
	"net/url"
	"strings"
	"unicode"
)

// Modos de segurança do SMTP.
const (
	SecuritySTARTTLS = "starttls" // conexão simples que sobe para TLS; recusa servidor sem STARTTLS
	SecurityTLS      = "tls"      // TLS desde o início (porta 465)
	SecurityNone     = "none"     // texto puro: só para relé no próprio servidor (endereço local)
)

// MaxRecipients limita os destinatários de um canal de e-mail.
const MaxRecipients = 20

// EmailConfig é a configuração sem segredos de um canal de e-mail (a senha fica cifrada à parte).
type EmailConfig struct {
	Host     string   `json:"host"`
	Port     int      `json:"port"`
	Security string   `json:"security"`
	Username string   `json:"username,omitempty"`
	From     string   `json:"from"`
	To       []string `json:"to"`
}

// WebhookConfig é a configuração sem segredos de um canal de webhook.
type WebhookConfig struct {
	URL string `json:"url"`
	// AllowPrivateNetwork libera destinos em rede privada ou local (10/8, 172.16/12, 192.168/16, 127/8, fc00::/7).
	// Link-local e endereços de metadados de nuvem continuam recusados.
	AllowPrivateNetwork bool `json:"allow_private_network"`
}

// ParseEmailConfig lê a configuração gravada.
func ParseEmailConfig(raw string) (EmailConfig, error) {
	var c EmailConfig
	if err := json.Unmarshal([]byte(raw), &c); err != nil {
		return c, invalid("configuração de e-mail ilegível")
	}
	return c, nil
}

// ParseWebhookConfig lê a configuração gravada.
func ParseWebhookConfig(raw string) (WebhookConfig, error) {
	var c WebhookConfig
	if err := json.Unmarshal([]byte(raw), &c); err != nil {
		return c, invalid("configuração de webhook ilegível")
	}
	return c, nil
}

// DefaultPort é a porta usual de cada modo.
func DefaultPort(security string) int {
	switch security {
	case SecurityTLS:
		return 465
	case SecurityNone:
		return 25
	}
	return 587
}

func hasControl(s string) bool {
	return strings.IndexFunc(s, func(r rune) bool { return unicode.IsControl(r) }) >= 0
}

// Normalize limpa espaços e completa a porta.
func (c *EmailConfig) Normalize() {
	c.Host = strings.TrimSpace(strings.TrimSuffix(strings.TrimPrefix(strings.TrimSpace(c.Host), "["), "]"))
	c.Username = strings.TrimSpace(c.Username)
	c.From = strings.TrimSpace(c.From)
	c.Security = strings.TrimSpace(c.Security)
	if c.Security == "" {
		c.Security = SecuritySTARTTLS
	}
	if c.Port == 0 {
		c.Port = DefaultPort(c.Security)
	}
	var to []string
	for _, a := range c.To {
		if a = strings.TrimSpace(a); a != "" {
			to = append(to, a)
		}
	}
	c.To = to
}

// Validate confere a configuração; hasPassword diz se há senha guardada (usuário sem senha não autentica).
func (c EmailConfig) Validate(hasPassword bool) error {
	if !validHost(c.Host) {
		return invalid("informe o servidor SMTP só com o nome ou o IP (sem esquema, porta ou usuário)")
	}
	if c.Port < 1 || c.Port > 65535 {
		return invalid("porta SMTP fora de 1..65535")
	}
	switch c.Security {
	case SecuritySTARTTLS, SecurityTLS:
	case SecurityNone:
		if !isLoopbackHost(c.Host) {
			return invalid("sem TLS só é aceito para relé no próprio servidor (localhost); use STARTTLS ou TLS")
		}
	default:
		return invalid("segurança SMTP inválida: use starttls, tls ou none")
	}
	if len(c.Username) > 256 || hasControl(c.Username) {
		return invalid("usuário SMTP inválido")
	}
	if c.Username != "" && !hasPassword {
		return invalid("informe a senha do usuário SMTP")
	}
	if err := validAddress(c.From); err != nil {
		return invalid("remetente inválido: %s", c.From)
	}
	if len(c.To) == 0 {
		return invalid("informe ao menos um destinatário")
	}
	if len(c.To) > MaxRecipients {
		return invalid("no máximo %d destinatários", MaxRecipients)
	}
	for _, a := range c.To {
		if err := validAddress(a); err != nil {
			return invalid("destinatário inválido: %s", CleanText(a, 80))
		}
	}
	return nil
}

// validHost aceita nome DNS ou IP literal (o IPv6 sem colchetes).
func validHost(h string) bool {
	if h == "" || len(h) > 253 || hasControl(h) {
		return false
	}
	if _, err := netip.ParseAddr(h); err == nil {
		return true
	}
	return !strings.ContainsAny(h, " /:@?#[]\\")
}

func validAddress(s string) error {
	if s == "" || len(s) > 320 || hasControl(s) {
		return ErrInvalid
	}
	a, err := mail.ParseAddress(s)
	if err != nil || !strings.Contains(a.Address, "@") {
		return ErrInvalid
	}
	return nil
}

func isLoopbackHost(h string) bool {
	if strings.EqualFold(h, "localhost") {
		return true
	}
	ip, err := netip.ParseAddr(h)
	return err == nil && ip.Unmap().IsLoopback()
}

// Normalize limpa espaços.
func (c *WebhookConfig) Normalize() { c.URL = strings.TrimSpace(c.URL) }

// Validate confere o endereço: só http(s), sem usuário e senha embutidos e, quando o host é um IP, fora das
// faixas recusadas. Nomes são conferidos de novo a cada conexão, com o IP resolvido.
func (c WebhookConfig) Validate() error {
	if c.URL == "" || len(c.URL) > 2048 || hasControl(c.URL) {
		return invalid("informe o endereço do webhook (até 2048 caracteres)")
	}
	u, err := url.Parse(c.URL)
	if err != nil {
		return invalid("endereço do webhook inválido")
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return invalid("o webhook aceita só http:// ou https://")
	}
	if u.Host == "" || u.Hostname() == "" {
		return invalid("o endereço do webhook precisa de um servidor")
	}
	if u.User != nil {
		return invalid("não coloque usuário e senha no endereço; a autenticação é a assinatura HMAC")
	}
	if u.Fragment != "" {
		return invalid("o endereço do webhook não pode ter fragmento (#)")
	}
	if p := u.Port(); p != "" {
		if _, err := net.LookupPort("tcp", p); err != nil {
			return invalid("porta do webhook inválida")
		}
	}
	if ip, err := netip.ParseAddr(u.Hostname()); err == nil {
		if err := checkAddr(ip, c.AllowPrivateNetwork); err != nil {
			return invalid("%s", err.Error())
		}
	} else if isLoopbackHost(u.Hostname()) && !c.AllowPrivateNetwork {
		return invalid("destino local recusado; permita rede privada no canal se for intencional")
	}
	return nil
}

// Destination resume o destino para auditoria e logs: esquema e servidor, sem caminho nem consulta (que podem
// carregar tokens do receptor).
func (c WebhookConfig) Destination() string {
	u, err := url.Parse(c.URL)
	if err != nil {
		return ""
	}
	return u.Scheme + "://" + u.Host
}

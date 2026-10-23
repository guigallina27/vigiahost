package notify

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// Cabeçalhos do Standard Webhooks (https://www.standardwebhooks.com/): identificador da mensagem, carimbo de tempo
// em segundos Unix e assinatura "v1,<base64 do HMAC-SHA256>" sobre "id.timestamp.corpo".
const (
	HeaderID        = "webhook-id"
	HeaderTimestamp = "webhook-timestamp"
	HeaderSignature = "webhook-signature"
	// SecretPrefix marca o segredo no formato do Standard Webhooks: o resto é a chave em base64.
	SecretPrefix = "whsec_"
	// MinSecretBytes é o tamanho mínimo da chave do HMAC.
	MinSecretBytes = 24
	// DefaultTolerance é a diferença máxima de relógio que o receptor deve aceitar (proteção contra repetição).
	DefaultTolerance = 5 * time.Minute
)

// WebhookKey converte o segredo informado na chave do HMAC: "whsec_<base64>" vira os bytes decodificados; qualquer
// outro texto é usado como está. Exige ao menos 24 bytes.
func WebhookKey(secret string) ([]byte, error) {
	secret = strings.TrimSpace(secret)
	if secret == "" {
		return nil, invalid("o webhook precisa de um segredo de assinatura")
	}
	key := []byte(secret)
	if rest, ok := strings.CutPrefix(secret, SecretPrefix); ok {
		dec, err := base64.StdEncoding.DecodeString(rest)
		if err != nil {
			return nil, invalid("segredo whsec_ com base64 inválido")
		}
		key = dec
	}
	if len(key) < MinSecretBytes || len(key) > 256 {
		return nil, invalid("o segredo do webhook precisa de %d a 256 bytes", MinSecretBytes)
	}
	return key, nil
}

// Sign calcula o valor do cabeçalho webhook-signature.
func Sign(key []byte, msgID string, ts time.Time, body []byte) string {
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(msgID + "." + strconv.FormatInt(ts.Unix(), 10) + "."))
	mac.Write(body)
	return "v1," + base64.StdEncoding.EncodeToString(mac.Sum(nil))
}

// Erros da verificação no receptor.
var (
	ErrSignatureMissing  = errors.New("cabeçalhos de assinatura ausentes")
	ErrSignatureExpired  = errors.New("carimbo de tempo fora da tolerância (possível repetição)")
	ErrSignatureMismatch = errors.New("assinatura não confere")
)

// Verify faz o que o receptor deve fazer: confere o carimbo de tempo dentro da tolerância e compara a assinatura em
// tempo constante. Aceita várias assinaturas separadas por espaço (troca de segredo). O receptor também deve guardar
// os webhook-id recentes e descartar repetidos.
func Verify(key []byte, h http.Header, body []byte, now time.Time, tolerance time.Duration) error {
	id, tsRaw, sigs := h.Get(HeaderID), h.Get(HeaderTimestamp), h.Get(HeaderSignature)
	if id == "" || tsRaw == "" || sigs == "" {
		return ErrSignatureMissing
	}
	sec, err := strconv.ParseInt(tsRaw, 10, 64)
	if err != nil {
		return ErrSignatureExpired
	}
	ts := time.Unix(sec, 0)
	if d := now.Sub(ts); d > tolerance || d < -tolerance {
		return ErrSignatureExpired
	}
	want := Sign(key, id, ts, body)
	for _, s := range strings.Fields(sigs) {
		if hmac.Equal([]byte(s), []byte(want)) {
			return nil
		}
	}
	return ErrSignatureMismatch
}

func (s *Service) webhookClient(allowPrivate bool) *http.Client {
	dialer := &net.Dialer{Timeout: 10 * time.Second, Control: guardControl(allowPrivate)}
	tr := &http.Transport{
		// Sem proxy do ambiente: o destino conferido é o destino conectado.
		Proxy:                  nil,
		DialContext:            dialer.DialContext,
		TLSClientConfig:        &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: s.RootCAs},
		TLSHandshakeTimeout:    10 * time.Second,
		ResponseHeaderTimeout:  s.Timeout,
		MaxResponseHeaderBytes: 64 << 10,
		DisableKeepAlives:      true,
		ForceAttemptHTTP2:      true,
	}
	return &http.Client{Transport: tr, Timeout: s.Timeout,
		// Redirecionamento não é seguido: levaria a assinatura a um destino que não foi conferido.
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
}

func (s *Service) sendWebhook(ctx context.Context, cfg WebhookConfig, key []byte, m Message) error {
	at := s.now()
	body, err := m.JSON(at)
	if err != nil {
		return permanent{err}
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, cfg.URL, bytes.NewReader(body))
	if err != nil {
		return permanent{invalid("endereço do webhook inválido")}
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "VigiaHost/"+userAgentVersion(s.Version))
	req.Header.Set(HeaderID, m.ID)
	req.Header.Set(HeaderTimestamp, strconv.FormatInt(at.Unix(), 10))
	req.Header.Set(HeaderSignature, Sign(key, m.ID, at, body))
	resp, err := s.webhookClient(cfg.AllowPrivateNetwork).Do(req)
	if err != nil {
		if Permanent(err) {
			return err
		}
		return fmt.Errorf("webhook: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	snippet, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		return nil
	}
	err = fmt.Errorf("webhook respondeu HTTP %d: %s", resp.StatusCode, CleanText(string(snippet), 200))
	switch {
	case resp.StatusCode >= 300 && resp.StatusCode < 400:
		return permanent{fmt.Errorf("webhook respondeu HTTP %d (redirecionamento não é seguido; use o endereço final)", resp.StatusCode)}
	case resp.StatusCode == http.StatusRequestTimeout, resp.StatusCode == http.StatusTooEarly,
		resp.StatusCode == http.StatusTooManyRequests, resp.StatusCode >= 500:
		return err
	default:
		return permanent{err}
	}
}

func userAgentVersion(v string) string {
	if v == "" {
		return "dev"
	}
	return strings.Map(func(r rune) rune {
		if r <= ' ' || r > '~' {
			return -1
		}
		return r
	}, v)
}

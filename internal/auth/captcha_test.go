package auth

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	altcha "github.com/altcha-org/altcha-lib-go/v2"
)

// SolveCaptcha resolve um desafio como o widget faria (usado também pelos testes da API).
func SolveCaptcha(t testing.TB, ch altcha.Challenge) string {
	t.Helper()
	sol, err := altcha.SolveChallenge(altcha.SolveChallengeOptions{Challenge: ch, DeriveKey: altcha.DeriveKeyPBKDF2()})
	if err != nil || sol == nil {
		t.Fatalf("resolver desafio: %v", err)
	}
	b, _ := json.Marshal(altcha.Payload{Challenge: ch, Solution: *sol})
	return base64.StdEncoding.EncodeToString(b)
}

func TestCaptchaAceitaUmaVezERecusaAdulteracao(t *testing.T) {
	c := NewCaptcha()
	c.Cost, c.CounterMin, c.CounterMax = 10, 5, 20
	ch, err := c.Challenge()
	if err != nil {
		t.Fatal(err)
	}
	payload := SolveCaptcha(t, ch)
	if err := c.Verify(payload); err != nil {
		t.Fatalf("solução válida recusada: %v", err)
	}
	if err := c.Verify(payload); !errors.Is(err, ErrCaptcha) {
		t.Fatalf("reuso aceito: %v", err)
	}
	for name, p := range map[string]string{"vazio": "", "lixo": "não é base64", "json": base64.StdEncoding.EncodeToString([]byte("{}"))} {
		if err := c.Verify(p); !errors.Is(err, ErrCaptcha) {
			t.Errorf("%s aceito: %v", name, err)
		}
	}
	// Desafio de outro servidor (outros segredos) ou com contador forjado.
	other := NewCaptcha()
	other.Cost, other.CounterMin, other.CounterMax = 10, 5, 20
	och, _ := other.Challenge()
	if err := c.Verify(SolveCaptcha(t, och)); !errors.Is(err, ErrCaptcha) {
		t.Errorf("desafio alheio aceito: %v", err)
	}
	ch2, _ := c.Challenge()
	var p altcha.Payload
	raw, _ := base64.StdEncoding.DecodeString(SolveCaptcha(t, ch2))
	_ = json.Unmarshal(raw, &p)
	tail := "ff"
	if strings.HasSuffix(p.Solution.DerivedKey, tail) {
		tail = "00"
	}
	p.Solution.DerivedKey = p.Solution.DerivedKey[:len(p.Solution.DerivedKey)-2] + tail
	b, _ := json.Marshal(p)
	if err := c.Verify(base64.StdEncoding.EncodeToString(b)); !errors.Is(err, ErrCaptcha) {
		t.Errorf("chave forjada aceita: %v", err)
	}
	// Expirado.
	c.TTL = -time.Second
	ch3, _ := c.Challenge()
	if err := c.Verify(SolveCaptcha(t, ch3)); !errors.Is(err, ErrCaptchaExpired) {
		t.Errorf("expirado: %v", err)
	}
}

func BenchmarkCaptchaCustoPadrao(b *testing.B) {
	c := NewCaptcha()
	for b.Loop() {
		ch, _ := c.Challenge()
		SolveCaptcha(b, ch)
	}
}

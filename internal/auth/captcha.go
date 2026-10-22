package auth

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"math/big"
	"sync"
	"time"

	altcha "github.com/altcha-org/altcha-lib-go/v2"
)

// Erros da verificação "não sou um robô".
var (
	ErrCaptcha        = errors.New("confirme que você não é um robô antes de continuar")
	ErrCaptchaExpired = errors.New("a verificação \"não sou um robô\" expirou; marque a caixa de novo")
)

const captchaAlgorithm = "PBKDF2/SHA-256"

// Captcha emite e confere desafios ALTCHA: o navegador resolve uma prova de trabalho quando o usuário marca a caixa
// "não sou um robô" e o servidor confere a solução sem refazer o cálculo (assinatura da chave, modo determinístico).
// Os segredos ficam só na memória: reiniciar o serviço invalida apenas os desafios em aberto.
type Captcha struct {
	TTL        time.Duration // validade do desafio (10 min)
	Cost       int           // iterações do PBKDF2 por tentativa
	CounterMin int           // o contador secreto fica em [CounterMin, CounterMax)
	CounterMax int
	MaxPending int // limite de soluções lembradas para impedir reuso

	secret    string
	keySecret string
	mu        sync.Mutex
	used      map[string]int64 // assinatura do desafio → expiração (unix)
}

// NewCaptcha cria o emissor com segredos aleatórios e o custo padrão (cerca de 1 s num computador comum).
func NewCaptcha() *Captcha {
	return &Captcha{TTL: 10 * time.Minute, Cost: 1000, CounterMin: 1000, CounterMax: 4000, MaxPending: 200000,
		secret: RandomToken(32), keySecret: RandomToken(32), used: map[string]int64{}}
}

// Challenge emite um desafio novo.
func (c *Captcha) Challenge() (altcha.Challenge, error) {
	n, err := rand.Int(rand.Reader, big.NewInt(int64(max(c.CounterMax-c.CounterMin, 1))))
	if err != nil {
		return altcha.Challenge{}, err
	}
	counter := c.CounterMin + int(n.Int64())
	exp := time.Now().Add(c.TTL)
	return altcha.CreateChallenge(altcha.CreateChallengeOptions{
		Algorithm:              captchaAlgorithm,
		DeriveKey:              altcha.DeriveKeyPBKDF2(),
		HMACSignatureSecret:    c.secret,
		HMACKeySignatureSecret: c.keySecret,
		Cost:                   c.Cost,
		KeyLength:              32,
		Counter:                &counter,
		ExpiresAt:              &exp,
	})
}

// Verify confere o payload do widget (JSON em base64) e impede que a mesma solução seja usada duas vezes.
func (c *Captcha) Verify(payload string) error {
	if payload == "" || len(payload) > 16384 {
		return ErrCaptcha
	}
	raw, err := base64.StdEncoding.DecodeString(payload)
	if err != nil {
		return ErrCaptcha
	}
	var p altcha.Payload
	if json.Unmarshal(raw, &p) != nil || p.Challenge.Parameters.Algorithm != captchaAlgorithm {
		return ErrCaptcha
	}
	// O modo rápido exige a assinatura da chave; sem ela o desafio não foi emitido aqui.
	if _, err := hex.DecodeString(p.Challenge.Parameters.KeySignature); err != nil || p.Challenge.Parameters.KeySignature == "" {
		return ErrCaptcha
	}
	res, err := altcha.VerifySolution(altcha.VerifySolutionOptions{
		Challenge:              p.Challenge,
		Solution:               p.Solution,
		DeriveKey:              altcha.DeriveKeyPBKDF2(),
		HMACSignatureSecret:    c.secret,
		HMACKeySignatureSecret: c.keySecret,
	})
	switch {
	case err != nil:
		return ErrCaptcha
	case res.Expired:
		return ErrCaptchaExpired
	case !res.Verified:
		return ErrCaptcha
	}
	return c.markUsed(p.Challenge.Signature, p.Challenge.Parameters.ExpiresAt)
}

func (c *Captcha) markUsed(sig string, exp int64) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	now := time.Now().Unix()
	if _, ok := c.used[sig]; ok {
		return ErrCaptcha
	}
	if len(c.used) >= c.MaxPending || len(c.used)%1024 == 1023 {
		for k, e := range c.used {
			if e < now {
				delete(c.used, k)
			}
		}
		if len(c.used) >= c.MaxPending {
			return ErrCaptcha // volume anormal: falha fechada até os desafios vencerem
		}
	}
	c.used[sig] = exp
	return nil
}

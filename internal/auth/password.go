// Package auth implementa a autenticação do painel (ADR-016): senha com Argon2id, TOTP, códigos de recuperação,
// sessões no servidor, reautenticação, bloqueio progressivo e tokens de API.
package auth

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"unicode/utf8"

	"golang.org/x/crypto/argon2"
)

// Parâmetros do Argon2id: segunda opção recomendada pela OWASP (46 MiB, 1 passada, 1 via), viável em servidores
// pequenos. Gravados em cada hash, então podem subir depois sem invalidar senhas antigas.
const (
	argonMemoryKiB = 47104
	argonTime      = 1
	argonThreads   = 1
	argonKeyLen    = 32
	saltLen        = 16

	MinPasswordLen = 12
	MaxPasswordLen = 256
)

// Limita cálculos simultâneos: cada um usa 46 MiB; sem limite, uma rajada de logins esgotaria a memória do core.
var hashSlots = make(chan struct{}, 2)

// ErrWeakPassword descreve a regra de senha.
var ErrWeakPassword = fmt.Errorf("a senha precisa ter de %d a %d caracteres", MinPasswordLen, MaxPasswordLen)

// CheckPassword aplica a política: só comprimento (NIST 800-63B), sem regras de composição.
func CheckPassword(pw string) error {
	n := utf8.RuneCountInString(pw)
	if n < MinPasswordLen || len(pw) > MaxPasswordLen || !utf8.ValidString(pw) {
		return ErrWeakPassword
	}
	return nil
}

func derive(pw string, salt []byte, mem uint32, t uint32, p uint8) []byte {
	hashSlots <- struct{}{}
	defer func() { <-hashSlots }()
	return argon2.IDKey([]byte(pw), salt, t, mem, p, argonKeyLen)
}

// HashPassword devolve o hash no formato PHC ($argon2id$v=19$m=...,t=...,p=...$sal$hash).
func HashPassword(pw string) (string, error) {
	if len(pw) > MaxPasswordLen {
		return "", ErrWeakPassword
	}
	salt := make([]byte, saltLen)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	key := derive(pw, salt, argonMemoryKiB, argonTime, argonThreads)
	enc := base64.RawStdEncoding
	return fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s", argon2.Version, argonMemoryKiB, argonTime, argonThreads,
		enc.EncodeToString(salt), enc.EncodeToString(key)), nil
}

// VerifyPassword confere a senha em tempo constante.
func VerifyPassword(encoded, pw string) (bool, error) {
	if len(pw) > MaxPasswordLen {
		return false, nil
	}
	parts := strings.Split(encoded, "$")
	if len(parts) != 6 || parts[1] != "argon2id" {
		return false, errors.New("formato de hash desconhecido")
	}
	var v int
	var mem, t uint32
	var p uint8
	if _, err := fmt.Sscanf(parts[2], "v=%d", &v); err != nil || v != argon2.Version {
		return false, errors.New("versão do argon2 incompatível")
	}
	if _, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &mem, &t, &p); err != nil || mem == 0 || mem > 1<<20 || t == 0 || t > 10 || p == 0 {
		return false, errors.New("parâmetros do argon2 inválidos")
	}
	enc := base64.RawStdEncoding
	salt, err := enc.DecodeString(parts[4])
	if err != nil {
		return false, err
	}
	want, err := enc.DecodeString(parts[5])
	if err != nil || len(want) == 0 {
		return false, errors.New("hash inválido")
	}
	got := derive(pw, salt, mem, t, p)
	if len(got) != len(want) {
		got = argon2.IDKey([]byte(pw), salt, t, mem, p, uint32(len(want))) //nolint:gosec // tamanho do hash gravado
	}
	return subtle.ConstantTimeCompare(got, want) == 1, nil
}

// dummyHash equaliza o tempo de resposta quando o usuário não existe.
var dummyHash, _ = HashPassword("vigiahost-usuario-inexistente")

// RandomToken devolve n bytes aleatórios em base64 URL sem preenchimento.
func RandomToken(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

// Package secrets cifra em repouso os segredos de integrações (senha SMTP, segredo de webhook) com AES-256-GCM
// (ADR-021; escopo, seção 13). A chave nunca fica no banco: vem do systemd (LoadCredential) quando configurado ou de
// um arquivo 0600 no diretório de estado, criado na primeira vez.
package secrets

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// KeyFileName é o arquivo da chave no diretório de estado; CredentialName é o nome esperado em LoadCredential=.
const (
	KeyFileName    = "secrets.key"
	CredentialName = "vigiahost-secrets-key"
	keySize        = 32
	version1       = 1
)

// ErrUndecryptable indica segredo que não abre com a chave atual (chave trocada ou banco de outro servidor).
var ErrUndecryptable = errors.New("segredo ilegível com a chave atual; informe o segredo de novo")

// Box cifra e decifra segredos.
type Box struct{ aead cipher.AEAD }

// New cria o cofre com uma chave de 32 bytes.
func New(key []byte) (*Box, error) {
	if len(key) != keySize {
		return nil, fmt.Errorf("chave de segredos precisa de %d bytes, tem %d", keySize, len(key))
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return &Box{aead: aead}, nil
}

// Seal cifra o valor. context liga o texto cifrado ao uso (dado adicional autenticado): o mesmo blob não serve para
// outro propósito. Formato: versão (1 byte) | nonce (12) | texto cifrado com etiqueta.
func (b *Box) Seal(plaintext []byte, context string) ([]byte, error) {
	nonce := make([]byte, b.aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	out := make([]byte, 0, 1+len(nonce)+len(plaintext)+b.aead.Overhead())
	out = append(out, version1)
	out = append(out, nonce...)
	return b.aead.Seal(out, nonce, plaintext, []byte(context)), nil
}

// Open decifra o valor gravado por Seal com o mesmo contexto.
func (b *Box) Open(blob []byte, context string) ([]byte, error) {
	ns := b.aead.NonceSize()
	if len(blob) < 1+ns+b.aead.Overhead() || blob[0] != version1 {
		return nil, ErrUndecryptable
	}
	pt, err := b.aead.Open(nil, blob[1:1+ns], blob[1+ns:], []byte(context))
	if err != nil {
		return nil, ErrUndecryptable
	}
	return pt, nil
}

// LoadKey lê a chave do diretório de credenciais do systemd ($CREDENTIALS_DIRECTORY/vigiahost-secrets-key) quando
// existir; senão, do arquivo secrets.key do diretório de estado, criado com 0600 se ainda não existir. Aceita 32
// bytes crus ou o texto base64 deles.
func LoadKey(stateDir string) ([]byte, string, error) {
	if dir := os.Getenv("CREDENTIALS_DIRECTORY"); dir != "" {
		path := filepath.Join(dir, CredentialName)
		if data, err := os.ReadFile(path); err == nil { //nolint:gosec // diretório entregue pelo systemd
			key, err := parseKey(data)
			return key, path, err
		}
	}
	path := filepath.Join(stateDir, KeyFileName)
	data, err := os.ReadFile(path) //nolint:gosec // arquivo do diretório de estado do serviço
	if err == nil {
		key, err := parseKey(data)
		return key, path, err
	}
	if !errors.Is(err, os.ErrNotExist) {
		return nil, path, err
	}
	key := make([]byte, keySize)
	if _, err := rand.Read(key); err != nil {
		return nil, path, err
	}
	// O_EXCL: dois processos iniciando juntos não sobrescrevem a chave um do outro.
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600) //nolint:gosec // idem
	if err != nil {
		if errors.Is(err, os.ErrExist) {
			return LoadKey(stateDir)
		}
		return nil, path, err
	}
	_, werr := f.WriteString(base64.StdEncoding.EncodeToString(key) + "\n")
	cerr := f.Close()
	if werr != nil || cerr != nil {
		_ = os.Remove(path)
		return nil, path, errors.Join(werr, cerr)
	}
	return key, path, nil
}

func parseKey(data []byte) ([]byte, error) {
	if len(data) == keySize {
		return data, nil
	}
	key, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(data)))
	if err != nil || len(key) != keySize {
		return nil, fmt.Errorf("chave de segredos inválida: esperado %d bytes ou o base64 deles", keySize)
	}
	return key, nil
}

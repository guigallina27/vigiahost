package secrets

import (
	"bytes"
	"encoding/base64"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestCifraEDecifraComContexto(t *testing.T) {
	box, err := New(bytes.Repeat([]byte{7}, 32))
	if err != nil {
		t.Fatal(err)
	}
	blob, err := box.Seal([]byte("s3nh@"), "smtp")
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(blob, []byte("s3nh@")) {
		t.Fatal("o valor aparece em claro no texto cifrado")
	}
	if pt, err := box.Open(blob, "smtp"); err != nil || string(pt) != "s3nh@" {
		t.Fatalf("decifrar: %q %v", pt, err)
	}
	if _, err := box.Open(blob, "webhook"); !errors.Is(err, ErrUndecryptable) {
		t.Fatalf("outro contexto deveria falhar: %v", err)
	}
	blob[len(blob)-1] ^= 1
	if _, err := box.Open(blob, "smtp"); !errors.Is(err, ErrUndecryptable) {
		t.Fatalf("texto adulterado deveria falhar: %v", err)
	}
	other, _ := New(bytes.Repeat([]byte{8}, 32))
	blob2, _ := box.Seal([]byte("x"), "smtp")
	if _, err := other.Open(blob2, "smtp"); !errors.Is(err, ErrUndecryptable) {
		t.Fatalf("outra chave deveria falhar: %v", err)
	}
	if _, err := New([]byte("curta")); err == nil {
		t.Fatal("chave curta deveria ser recusada")
	}
}

func TestChaveCriadaUmaVezEDoSystemd(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("CREDENTIALS_DIRECTORY", "")
	k1, path, err := LoadKey(dir)
	if err != nil || len(k1) != 32 || path != filepath.Join(dir, KeyFileName) {
		t.Fatalf("criação: %v %s", err, path)
	}
	if runtime.GOOS != "windows" {
		if st, err := os.Stat(path); err != nil || st.Mode().Perm() != 0o600 {
			t.Fatalf("permissão do arquivo da chave: %v %v", st.Mode(), err)
		}
	}
	k2, _, err := LoadKey(dir)
	if err != nil || !bytes.Equal(k1, k2) {
		t.Fatal("a chave deveria ser a mesma na segunda leitura")
	}
	// LoadCredential= do systemd tem precedência.
	cred := t.TempDir()
	want := bytes.Repeat([]byte{9}, 32)
	if err := os.WriteFile(filepath.Join(cred, CredentialName), []byte(base64.StdEncoding.EncodeToString(want)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("CREDENTIALS_DIRECTORY", cred)
	k3, path, err := LoadKey(dir)
	if err != nil || !bytes.Equal(k3, want) || path != filepath.Join(cred, CredentialName) {
		t.Fatalf("credencial do systemd: %v %s", err, path)
	}
	if err := os.WriteFile(filepath.Join(cred, CredentialName), []byte("inválida"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := LoadKey(dir); err == nil {
		t.Fatal("chave inválida deveria ser recusada")
	}
}

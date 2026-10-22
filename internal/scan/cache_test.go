package scan

import (
	"path/filepath"
	"testing"
)

func TestCacheValeSoComAsMesmasVersoes(t *testing.T) {
	path := filepath.Join(t.TempDir(), "cache.gob")
	k := CacheKey{Dev: 1, Ino: 2, Size: 3, Mtime: 4, Ctime: 5}
	sha := [32]byte{9}

	c := LoadCache(path, "regras-1", "clam-1")
	if _, _, _, ok := c.Lookup(k); ok {
		t.Fatal("cache novo deveria estar vazio")
	}
	c.Store(k, sha, true, true)
	if err := c.Save(); err != nil {
		t.Fatal(err)
	}

	c = LoadCache(path, "regras-1", "clam-1")
	got, y, cl, ok := c.Lookup(k)
	if !ok || got != sha || !y || !cl {
		t.Fatalf("mesmas versões: %v %v %v %v", got, y, cl, ok)
	}
	// Regras novas: o YARA precisa analisar de novo; o ClamAV continua valendo.
	c = LoadCache(path, "regras-2", "clam-1")
	if _, y, cl, ok := c.Lookup(k); !ok || y || !cl {
		t.Fatalf("regras novas: %v %v %v", y, cl, ok)
	}
	// ctime diferente é outro objeto.
	k2 := k
	k2.Ctime++
	if _, _, _, ok := c.Lookup(k2); ok {
		t.Fatal("ctime alterado não pode reaproveitar o cache")
	}
	// Só o que foi visto nesta execução segue adiante.
	if err := c.Save(); err != nil {
		t.Fatal(err)
	}
	if _, _, _, ok := LoadCache(path, "regras-2", "clam-1").Lookup(k); ok {
		t.Fatal("objeto não visto deveria sair do cache")
	}
}

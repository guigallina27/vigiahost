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

func TestCacheLMD(t *testing.T) {
	path := filepath.Join(t.TempDir(), "cache.gob")
	k := CacheKey{Dev: 1, Ino: 2, Size: 3, Mtime: 4, Ctime: 5}
	sha := [32]byte{7}

	c := LoadCache(path, "r", "c")
	c.SetLMDVersion("2.0.1/2026052490478/yr")
	// O LMD termina o lote antes ou depois dos outros motores: os bits se somam nas duas ordens.
	c.StoreLMD(k, sha, true)
	c.Store(k, sha, true, false)
	if err := c.Save(); err != nil {
		t.Fatal(err)
	}
	c = LoadCache(path, "r", "c")
	c.SetLMDVersion("2.0.1/2026052490478/yr")
	if !c.LMDClean(k) {
		t.Fatal("mesma versão do LMD deveria reaproveitar")
	}
	if _, y, cl, _ := c.Lookup(k); !y || cl {
		t.Fatalf("bits dos outros motores alterados: %v %v", y, cl)
	}
	c = LoadCache(path, "r", "c")
	c.SetLMDVersion("2.0.1/2026060100001/yr")
	if c.LMDClean(k) {
		t.Fatal("assinaturas novas do LMD não podem reaproveitar")
	}
	c = LoadCache(path, "r", "c")
	c.SetLMDVersion("")
	if c.LMDClean(k) {
		t.Fatal("LMD fora da execução não usa o cache")
	}
	// Detecção (clean=false) não marca nada.
	c.StoreLMD(CacheKey{Ino: 9}, sha, false)
	if _, ok := c.next[CacheKey{Ino: 9}]; ok {
		t.Fatal("arquivo com achado entrou no cache")
	}
}

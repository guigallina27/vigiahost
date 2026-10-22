package scan

import (
	"bufio"
	"encoding/gob"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
)

// CacheKey identifica uma versão de um arquivo sem lê-lo (ADR-007). O ctime entra porque o usuário não consegue
// ajustá-lo como o mtime (timestomping).
type CacheKey struct {
	Dev   uint64
	Ino   uint64
	Size  int64
	Mtime int64 // ns
	Ctime int64 // ns
}

// Bits de motores para os quais o objeto já foi analisado e saiu limpo.
const (
	cleanYARA uint8 = 1 << iota
	cleanClamAV
)

type cacheEntry struct {
	SHA256 [32]byte
	Clean  uint8
}

// cacheFile é o formato gravado em disco. As versões valem para o arquivo inteiro: mudou a versão das regras ou
// das assinaturas de um motor, o bit daquele motor deixa de valer para todos os objetos.
type cacheFile struct {
	Format      int
	YARAVersion string
	ClamVersion string
	Entries     map[CacheKey]cacheEntry
}

const cacheFormat = 1

// Cache guarda só objetos limpos: arquivo com achado é sempre analisado de novo, para o achado reaparecer.
type Cache struct {
	mu      sync.Mutex
	path    string
	yaraOK  bool // versão das regras igual à do cache
	clamOK  bool
	old     map[CacheKey]cacheEntry
	next    map[CacheKey]cacheEntry
	yaraVer string
	clamVer string
}

// LoadCache abre o cache (ou começa vazio) e compara as versões dos motores.
func LoadCache(path, yaraVersion, clamVersion string) *Cache {
	c := &Cache{path: path, yaraVer: yaraVersion, clamVer: clamVersion, old: map[CacheKey]cacheEntry{}, next: map[CacheKey]cacheEntry{}}
	if path == "" {
		return c
	}
	f, err := os.Open(path) //nolint:gosec // caminho do cache no diretório de estado do executor
	if err != nil {
		return c
	}
	defer func() { _ = f.Close() }()
	var cf cacheFile
	if err := gob.NewDecoder(bufio.NewReader(f)).Decode(&cf); err != nil || cf.Format != cacheFormat {
		return c
	}
	c.old = cf.Entries
	c.yaraOK = cf.YARAVersion != "" && cf.YARAVersion == yaraVersion
	c.clamOK = cf.ClamVersion != "" && cf.ClamVersion == clamVersion
	return c
}

// Lookup devolve o hash conhecido e para quais motores o objeto inalterado já saiu limpo.
func (c *Cache) Lookup(k CacheKey) (sha [32]byte, yaraClean, clamClean, ok bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	e, found := c.old[k]
	if !found {
		return sha, false, false, false
	}
	return e.SHA256, c.yaraOK && e.Clean&cleanYARA != 0, c.clamOK && e.Clean&cleanClamAV != 0, true
}

// Store registra o resultado desta execução; só os objetos vistos agora seguem para o próximo cache.
func (c *Cache) Store(k CacheKey, sha [32]byte, yaraClean, clamClean bool) {
	var bits uint8
	if yaraClean {
		bits |= cleanYARA
	}
	if clamClean {
		bits |= cleanClamAV
	}
	c.mu.Lock()
	// Motores diferentes podem registrar o mesmo objeto em momentos distintos (fila do clamscan): soma os bits.
	if prev, ok := c.next[k]; ok && prev.SHA256 == sha {
		bits |= prev.Clean
	}
	c.next[k] = cacheEntry{SHA256: sha, Clean: bits}
	c.mu.Unlock()
}

// Save grava o cache novo com troca atômica.
func (c *Cache) Save() error {
	if c.path == "" {
		return nil
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := os.MkdirAll(filepath.Dir(c.path), 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(c.path), ".cache-*")
	if err != nil {
		return err
	}
	defer func() { _ = os.Remove(tmp.Name()) }()
	w := bufio.NewWriter(tmp)
	cf := cacheFile{Format: cacheFormat, YARAVersion: c.yaraVer, ClamVersion: c.clamVer, Entries: c.next}
	if err := gob.NewEncoder(w).Encode(&cf); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("cache: %w", err)
	}
	if err := errors.Join(w.Flush(), tmp.Sync(), tmp.Close()); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), c.path)
}

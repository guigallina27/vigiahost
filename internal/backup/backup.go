// Package backup faz cópias consistentes do banco do core com VACUUM INTO (escopo, seção 15; E1.14): o serviço
// continua no ar durante a cópia, e cada cópia leva um manifesto com SHA-256 e a versão do esquema.
package backup

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/guigallina27/vigiahost/internal/store"
	"github.com/guigallina27/vigiahost/internal/version"
)

const prefix = "vigiahost-"

// ErrExists indica que já há uma cópia com o mesmo carimbo de tempo.
var ErrExists = errors.New("cópia já existe")

// KeepAutomatic é quantas cópias automáticas diárias ficam guardadas.
const KeepAutomatic = 7

// Info descreve uma cópia (gravada ao lado do .db como .json).
type Info struct {
	Name          string    `json:"name"`
	CreatedAt     time.Time `json:"created_at"`
	Size          int64     `json:"size"`
	SHA256        string    `json:"sha256"`
	SchemaVersion int64     `json:"schema_version"`
	Product       string    `json:"product"`
	Origin        string    `json:"origin"` // automatic, manual, cli, pre-migration, pre-restore
}

// createMu evita duas cópias simultâneas no mesmo processo (a diária e uma manual, por exemplo).
var createMu sync.Mutex

// Create grava dir/vigiahost-AAAAMMDD-HHMMSS.db com VACUUM INTO, confere a integridade e grava o manifesto.
func Create(ctx context.Context, db *sql.DB, dir, origin string, now time.Time) (Info, error) {
	createMu.Lock()
	defer createMu.Unlock()
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return Info{}, err
	}
	name := prefix + now.UTC().Format("20060102-150405") + ".db"
	final := filepath.Join(dir, name)
	if _, err := os.Stat(final); err == nil {
		return Info{}, fmt.Errorf("%w: já existe uma cópia de %s", ErrExists, now.UTC().Format("02/01/2006 15:04:05"))
	}
	tmp := final + ".parcial"
	_ = os.Remove(tmp)
	// VACUUM INTO não aceita parâmetro de ligação para o destino; o nome é gerado aqui, nunca vem do usuário.
	//nolint:gosec // G202: destino gerado aqui (diretório + carimbo de tempo), com aspas escapadas
	if _, err := db.ExecContext(ctx, "VACUUM INTO '"+strings.ReplaceAll(tmp, "'", "''")+"'"); err != nil {
		_ = os.Remove(tmp)
		return Info{}, fmt.Errorf("VACUUM INTO: %w", err)
	}
	// O SQLite cria o arquivo com a umask de quem chama (0644 para o root no terminal); a cópia tem senhas com hash,
	// auditoria e achados, então só o dono lê.
	if err := os.Chmod(tmp, 0o600); err != nil {
		_ = os.Remove(tmp)
		return Info{}, err
	}
	info, err := Inspect(ctx, tmp)
	if err != nil {
		_ = os.Remove(tmp)
		return Info{}, err
	}
	if err := os.Rename(tmp, final); err != nil {
		return Info{}, err
	}
	info.Name, info.CreatedAt, info.Origin, info.Product = name, now.UTC(), origin, version.Version
	b, _ := json.MarshalIndent(info, "", "  ")
	if err := os.WriteFile(strings.TrimSuffix(final, ".db")+".json", append(b, '\n'), 0o600); err != nil {
		return info, err
	}
	return info, nil
}

// Inspect confere a integridade de um arquivo de banco e devolve tamanho, hash e versão do esquema.
func Inspect(ctx context.Context, path string) (Info, error) {
	st, err := os.Stat(path)
	if err != nil {
		return Info{}, err
	}
	raw, err := store.Open(ctx, path)
	if err != nil {
		return Info{}, err
	}
	var check string
	err = raw.QueryRowContext(ctx, "PRAGMA integrity_check").Scan(&check)
	var schema sql.NullInt64
	if err == nil {
		_ = raw.QueryRowContext(ctx, "SELECT MAX(version_id) FROM goose_db_version WHERE is_applied").Scan(&schema)
	}
	_ = raw.Close()
	// Fechar a cópia remove os arquivos -wal/-shm que a abertura criou.
	_ = os.Remove(path + "-wal")
	_ = os.Remove(path + "-shm")
	if err != nil {
		return Info{}, fmt.Errorf("conferência de integridade: %w", err)
	}
	if check != "ok" {
		return Info{}, fmt.Errorf("cópia corrompida: %s", check)
	}
	sum, err := fileSHA256(path)
	if err != nil {
		return Info{}, err
	}
	return Info{Size: st.Size(), SHA256: sum, SchemaVersion: schema.Int64}, nil
}

func fileSHA256(path string) (string, error) {
	f, err := os.Open(path) //nolint:gosec // cópia do próprio produto
	if err != nil {
		return "", err
	}
	defer func() { _ = f.Close() }()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// List devolve as cópias do diretório, da mais nova para a mais antiga.
func List(dir string) ([]Info, error) {
	ents, err := os.ReadDir(dir)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var out []Info
	for _, e := range ents {
		if !strings.HasPrefix(e.Name(), prefix) || !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		b, err := os.ReadFile(filepath.Join(dir, e.Name())) //nolint:gosec // diretório de cópias do produto
		if err != nil {
			continue
		}
		var i Info
		if json.Unmarshal(b, &i) == nil && i.Name != "" {
			if _, err := os.Stat(filepath.Join(dir, i.Name)); err == nil {
				out = append(out, i)
			}
		}
	}
	sort.Slice(out, func(a, b int) bool { return out[a].CreatedAt.After(out[b].CreatedAt) })
	return out, nil
}

// Prune mantém as keep cópias automáticas mais novas; manuais e de antes da restauração ficam até serem apagadas.
func Prune(dir string, keep int) (removed int, err error) {
	list, err := List(dir)
	if err != nil {
		return 0, err
	}
	kept := 0
	for _, i := range list {
		if i.Origin != "automatic" {
			continue
		}
		kept++
		if kept <= keep {
			continue
		}
		base := filepath.Join(dir, strings.TrimSuffix(i.Name, ".db"))
		if err := errors.Join(os.Remove(base+".db"), os.Remove(base+".json")); err != nil {
			return removed, err
		}
		removed++
	}
	return removed, nil
}

// Find localiza uma cópia pelo nome (sem caminho) dentro do diretório.
func Find(dir, name string) (Info, string, error) {
	if name != filepath.Base(name) || !strings.HasPrefix(name, prefix) || !strings.HasSuffix(name, ".db") {
		return Info{}, "", errors.New("nome de cópia inválido")
	}
	list, err := List(dir)
	if err != nil {
		return Info{}, "", err
	}
	for _, i := range list {
		if i.Name == name {
			return i, filepath.Join(dir, name), nil
		}
	}
	return Info{}, "", os.ErrNotExist
}

// Restore troca o banco por uma cópia conferida. O serviço precisa estar parado (quem chama confere); o banco atual
// vira uma cópia "pre-restore" antes da troca, para poder voltar atrás.
func Restore(ctx context.Context, src, dbPath, backupDir string, maxSchema int64, now time.Time) (Info, error) {
	info, err := Inspect(ctx, src)
	if err != nil {
		return info, err
	}
	info.Name = filepath.Base(src)
	if info.SchemaVersion > maxSchema {
		return info, fmt.Errorf("a cópia é de uma versão mais nova do esquema (%d > %d): atualize o VigiaHost antes de restaurar",
			info.SchemaVersion, maxSchema)
	}
	if _, err := os.Stat(dbPath); err == nil {
		cur, err := store.Open(ctx, dbPath)
		if err != nil {
			return info, err
		}
		// Uma cópia manual feita no mesmo segundo ocuparia o nome: tenta os segundos seguintes.
		for i := range 5 {
			if _, err = Create(ctx, cur, backupDir, "pre-restore", now.Add(time.Duration(i)*time.Second)); !errors.Is(err, ErrExists) {
				break
			}
		}
		_ = cur.Close()
		if err != nil {
			return info, fmt.Errorf("cópia de segurança do banco atual: %w", err)
		}
	}
	data, err := os.ReadFile(src) //nolint:gosec // cópia conferida acima
	if err != nil {
		return info, err
	}
	tmp := dbPath + ".restaurando"
	if err := os.WriteFile(tmp, data, 0o600); err != nil { //nolint:gosec // G703: caminho do banco do serviço
		return info, err
	}
	for _, sfx := range []string{"-wal", "-shm"} {
		_ = os.Remove(dbPath + sfx)
	}
	return info, os.Rename(tmp, dbPath)
}

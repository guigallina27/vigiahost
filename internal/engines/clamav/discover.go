package clamav

import (
	"bufio"
	"bytes"
	"io/fs"
	"strconv"
	"strings"
)

// Arquivos de configuração do clamd conhecidos, na ordem de preferência (caminhos relativos à raiz).
var clamdConfigs = []string{
	"etc/clamd.d/scan.conf",                    // EL (clamd@scan)
	"etc/clamav/clamd.conf",                    // Debian e Ubuntu
	"etc/clamd.conf",                           // instalações antigas
	"usr/local/etc/clamd.conf",                 // pacote oficial da Cisco Talos
	"usr/local/cpanel/3rdparty/etc/clamd.conf", // cPanel
	"etc/clamd.d/clamd.conf",
}

// Sockets conhecidos quando nenhuma configuração aponta um.
var clamdSockets = []string{
	"run/clamd.scan/clamd.sock",
	"run/clamav/clamd.ctl",
	"var/run/clamav/clamd.ctl",
	"var/run/clamd.scan/clamd.sock",
	"var/clamd",
	"tmp/clamd.socket",
}

// Config é a parte da configuração do clamd que importa ao produto (escopo, seção 7.2: exibir os limites).
type Config struct {
	File        string           `json:"file"`
	LocalSocket string           `json:"local_socket"`
	Limits      map[string]int64 `json:"limits,omitempty"`
}

var limitKeys = []string{"MaxFileSize", "MaxScanSize", "MaxRecursion", "MaxFiles", "StreamMaxLength", "MaxThreads"}

// Discover procura a configuração do clamd e o socket. root é a raiz do sistema (os.DirFS("/")).
func Discover(root fs.FS) (Config, bool) {
	for _, p := range clamdConfigs {
		data, err := fs.ReadFile(root, p)
		if err != nil {
			continue
		}
		cfg := ParseConfig(data)
		cfg.File = "/" + p
		if cfg.LocalSocket != "" {
			return cfg, true
		}
	}
	for _, p := range clamdSockets {
		if info, err := fs.Stat(root, p); err == nil && info.Mode().Type() == fs.ModeSocket {
			return Config{LocalSocket: "/" + p}, true
		}
	}
	return Config{}, false
}

// ParseConfig lê "Chave Valor" por linha, ignorando comentários e o exemplo desativado ("Example").
func ParseConfig(data []byte) Config {
	cfg := Config{Limits: map[string]int64{}}
	sc := bufio.NewScanner(bytes.NewReader(data))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, val, _ := strings.Cut(line, " ")
		key, val = strings.TrimSpace(key), strings.Trim(strings.TrimSpace(val), `"`)
		switch key {
		case "Example":
			return Config{} // arquivo de exemplo: o clamd recusa iniciar com ele
		case "LocalSocket":
			cfg.LocalSocket = val
		}
		for _, k := range limitKeys {
			if key == k {
				if n, ok := parseSize(val); ok {
					cfg.Limits[k] = n
				}
			}
		}
	}
	return cfg
}

// parseSize aceita números com sufixo K/M (como na configuração do ClamAV).
func parseSize(s string) (int64, bool) {
	mult := int64(1)
	switch {
	case strings.HasSuffix(s, "M"), strings.HasSuffix(s, "m"):
		mult, s = 1<<20, s[:len(s)-1]
	case strings.HasSuffix(s, "K"), strings.HasSuffix(s, "k"):
		mult, s = 1<<10, s[:len(s)-1]
	}
	n, err := strconv.ParseInt(s, 10, 64)
	if err != nil || n < 0 {
		return 0, false
	}
	return n * mult, true
}

// Diretórios de assinaturas conhecidos (relativos à raiz), para ler a versão do banco quando o clamscan não a
// informa (o pacote oficial só mostra a versão do motor se o banco não estiver no diretório compilado).
var databaseDirs = []string{"var/lib/clamav", "var/clamav", "usr/local/share/clamav", "usr/local/cpanel/3rdparty/share/clamav"}

// DatabaseVersion lê a versão do banco "daily" pelo cabeçalho do arquivo (ClamAV-VDB:data:versão:...).
func DatabaseVersion(root fs.FS) string {
	for _, dir := range databaseDirs {
		for _, name := range []string{"daily.cld", "daily.cvd"} {
			f, err := root.Open(dir + "/" + name)
			if err != nil {
				continue
			}
			head := make([]byte, 512)
			n, _ := f.Read(head)
			_ = f.Close()
			fields := strings.Split(string(head[:n]), ":")
			if len(fields) > 2 && fields[0] == "ClamAV-VDB" {
				return strings.TrimSpace(fields[2])
			}
		}
	}
	return ""
}

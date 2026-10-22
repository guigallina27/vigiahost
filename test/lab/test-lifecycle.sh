#!/usr/bin/env bash
# Ciclo de vida do pacote com systemd real: instala, ativa pelo setup plan/apply, confere saúde e política do executor,
# atualiza, volta de versão, remove (dados preservados), reinstala e desinstala com -purge.
# Uso (como root, na máquina de laboratório): test-lifecycle.sh <dir-pacotes> <versão-antiga> <versão-nova>
set -euo pipefail

dir="$1" old="$2" new="$3"

fail() {
	echo "FALHA: $*" >&2
	journalctl -u vigiahost-core -u vigiahost-executor --no-pager -n 40 >&2 || true
	exit 1
}
ok() { echo "ok: $*"; }

[[ -d /run/systemd/system ]] || fail "este teste exige systemd em execução"

if command -v dnf >/dev/null 2>&1; then
	arch="$(uname -m)"
	pkg() { echo "$dir/vigiahost-$1-1.$arch.rpm"; }
	pkg_install() { dnf -y -q install "$1" >/dev/null; }
	pkg_downgrade() { dnf -y -q downgrade "$1" >/dev/null; }
	pkg_remove() { dnf -y -q remove vigiahost >/dev/null; }
else
	arch="$(dpkg --print-architecture)"
	pkg() { echo "$dir/vigiahost_$1_$arch.deb"; }
	pkg_install() { DEBIAN_FRONTEND=noninteractive apt-get -qq -y install "$1" >/dev/null; }
	pkg_downgrade() { DEBIAN_FRONTEND=noninteractive apt-get -qq -y install --allow-downgrades "$1" >/dev/null; }
	pkg_remove() { DEBIAN_FRONTEND=noninteractive apt-get -qq -y remove vigiahost >/dev/null; }
fi

health() { curl -sS --max-time 5 http://127.0.0.1:8743/api/v1/health; }

# Espera a API responder com a versão esperada e o executor conectado.
wait_health() {
	local want="$1" out
	for _ in $(seq 1 30); do
		if out="$(health 2>/dev/null)" &&
			[[ "$(jq -r .version <<<"$out")" == "$want" ]] &&
			[[ "$(jq -r .executor.connected <<<"$out")" == "true" ]]; then
			echo "$out"
			return 0
		fi
		sleep 1
	done
	return 1
}

echo "== instalação de $old"
pkg_install "$(pkg "$old")"
getent passwd vigiahost >/dev/null || fail "usuário vigiahost não criado"
systemctl is-active --quiet vigiahost-core && fail "a instalação não deveria iniciar o serviço"
ok "pacote instalado, usuário criado, serviços parados"

vigiahost setup plan >/tmp/setup-plan.txt || fail "setup plan com impedimentos: $(cat /tmp/setup-plan.txt)"
grep -q "habilitar e iniciar vigiahost-core.service" /tmp/setup-plan.txt || fail "plano sem ativar o core"
systemctl is-active --quiet vigiahost-core && fail "o plan não deveria alterar nada"
vigiahost setup apply >/tmp/setup-apply.txt || fail "setup apply falhou: $(cat /tmp/setup-apply.txt)"
grep -q "Token de primeiro acesso" /tmp/setup-apply.txt || fail "apply não mostrou o primeiro acesso"
[[ "$(stat -c '%a %U' /etc/vigiahost/setup-manifest.json)" == "600 root" ]] || fail "manifesto ausente ou com permissão errada"
vigiahost setup plan | grep -q "nada a fazer" || fail "reexecução do plano deveria estar em dia"
vigiahost setup apply >/dev/null || fail "segundo apply falhou"
[[ "$(jq '.changes | length' /etc/vigiahost/setup-manifest.json)" == "2" ]] || fail "reexecução duplicou o manifesto"
ok "setup plan/apply idempotente com manifesto"
out="$(wait_health "$old")" || fail "API não respondeu com $old e executor conectado"
ok "API e executor: $(jq -c '{status, version, executor: (.executor | {connected, protocol, distro: .system.distro_id, cgroup_v2: .system.cgroup_v2, psi: .system.psi})}' <<<"$out")"

[[ "$(stat -c '%a %U %G' /run/vigiahost-executor/executor.sock)" == "660 root vigiahost" ]] ||
	fail "permissão do socket incorreta: $(stat -c '%a %U %G' /run/vigiahost-executor/executor.sock)"
[[ "$(stat -c '%a %U' /var/lib/vigiahost)" == "700 vigiahost" ]] || fail "permissão de /var/lib/vigiahost incorreta"
ok "socket 660 root:vigiahost e dados 700 vigiahost"

# Interface embarcada: index com CSP, recurso com hash comprimido em brotli e cache imutável, API inexistente em JSON.
page="$(curl -sS -D /tmp/ui-headers.txt http://127.0.0.1:8743/execucoes)" || fail "interface não respondeu"
grep -q '<div id="root">' <<<"$page" || fail "index.html da interface não servido"
grep -qi "^content-security-policy: default-src 'self'" /tmp/ui-headers.txt || fail "interface sem CSP"
asset="$(grep -o '/assets/index-[A-Za-z0-9_-]*\.js' <<<"$page" | head -1)"
[[ -n "$asset" ]] || fail "index.html sem o script com hash"
curl -sS -o /dev/null -D /tmp/asset-headers.txt -H 'Accept-Encoding: br, gzip' "http://127.0.0.1:8743$asset"
grep -qi '^content-encoding: br' /tmp/asset-headers.txt || fail "recurso sem a versão brotli"
grep -qi '^cache-control: public, max-age=31536000, immutable' /tmp/asset-headers.txt || fail "recurso sem cache imutável"
[[ "$(curl -sS -o /dev/null -w '%{http_code} %{content_type}' http://127.0.0.1:8743/api/v1/nada)" == "404 application/json; charset=utf-8" ]] ||
	fail "rota inexistente da API não respondeu 404 em JSON"
ok "interface embarcada servida com CSP, brotli e cache imutável ($asset)"

vigiahost doctor >/tmp/doctor.txt || fail "doctor como root falhou: $(cat /tmp/doctor.txt)"
ok "doctor como root: $(grep Executor /tmp/doctor.txt | tr -s ' ')"

# Cópias do banco (E1.14): a automática sai ao iniciar; a manual pelo terminal fica com o dono do serviço; a
# restauração recusa com o core ativo e, com ele parado, guarda o banco atual como "pre-restore".
for _ in $(seq 1 15); do vigiahost backup list | grep -q automatic && break; sleep 1; done
vigiahost backup list | grep -q automatic || fail "cópia automática não foi feita ao iniciar"
sleep 1
vigiahost backup create >/tmp/backup-create.txt 2>&1 || fail "backup create falhou: $(cat /tmp/backup-create.txt)"
copy="$(grep -o 'vigiahost-[0-9]*-[0-9]*\.db' /tmp/backup-create.txt | head -1)"
[[ "$(stat -c '%a %U' "/var/lib/vigiahost/backups/$copy")" == "600 vigiahost" ]] || fail "cópia manual com dono ou permissão errados"
if vigiahost backup restore "$copy" >/tmp/backup-restore.txt 2>&1; then fail "restore aceito com o core ativo"; fi
grep -q "systemctl stop vigiahost-core" /tmp/backup-restore.txt || fail "restore sem orientar a parar o serviço"
systemctl is-active --quiet vigiahost-core || fail "o restore não deveria mexer no serviço"
systemctl stop vigiahost-core
vigiahost backup restore "$copy" >/tmp/backup-restore.txt 2>&1 || fail "restore falhou: $(cat /tmp/backup-restore.txt)"
[[ "$(stat -c '%U' /var/lib/vigiahost/vigiahost.db)" == "vigiahost" ]] || fail "banco restaurado ficou com outro dono"
vigiahost backup list | grep -q pre-restore || fail "faltou a cópia do banco anterior à restauração"
systemctl start vigiahost-core
wait_health "$old" >/dev/null || fail "o core não voltou após a restauração"
ok "backup: automática, manual ($copy), recusa com o core ativo e restauração com cópia pre-restore"

# Defesa em camadas: usuário comum não abre o socket; mesmo dentro do grupo, a política do executor recusa.
id labuser >/dev/null 2>&1 || useradd -m labuser
gpasswd -d labuser vigiahost >/dev/null 2>&1 || true
if runuser -u labuser -- vigiahost doctor >/tmp/doctor-user.txt 2>&1; then fail "usuário comum acessou o executor"; fi
grep -q "permission denied" /tmp/doctor-user.txt || fail "esperava permissão negada no socket: $(cat /tmp/doctor-user.txt)"
ok "usuário comum barrado pela permissão do socket"
usermod -aG vigiahost labuser
if runuser -u labuser -- vigiahost doctor >/tmp/doctor-group.txt 2>&1; then fail "usuário do grupo passou pela política"; fi
grep -q "unauthorized" /tmp/doctor-group.txt || fail "esperava recusa da política: $(cat /tmp/doctor-group.txt)"
journalctl -u vigiahost-executor --no-pager -n 20 | grep -q "conexão recusada pela política" || fail "recusa não registrada no journal"
ok "usuário no grupo barrado pela política do executor (SO_PEERCRED) e registrado no journal"
gpasswd -d labuser vigiahost >/dev/null

echo "== exposição medida pelo systemd-analyze security"
for unit in vigiahost-core vigiahost-executor; do
	echo "$unit: $(systemd-analyze security "$unit.service" --no-pager 2>/dev/null | tail -1)"
done

echo "== atualização para $new"
pkg_install "$(pkg "$new")"
out="$(wait_health "$new")" || fail "após atualizar, a API não respondeu com $new"
systemctl is-enabled --quiet vigiahost-core || fail "a atualização desabilitou o serviço"
ok "atualizado e reiniciado: $(jq -r .version <<<"$out")"

echo "== retorno para $old"
pkg_downgrade "$(pkg "$old")"
out="$(wait_health "$old")" || fail "após voltar de versão, a API não respondeu com $old"
ok "versão anterior em execução sobre o mesmo banco: $(jq -r .version <<<"$out")"

echo "== remoção"
pkg_remove
systemctl is-active --quiet vigiahost-core && fail "serviço continua ativo após remover"
[[ -f /var/lib/vigiahost/vigiahost.db ]] || fail "dados apagados na remoção sem purge"
getent passwd vigiahost >/dev/null || fail "usuário removido"
ok "serviços parados; banco e usuário preservados"

echo "== reinstalação de $new sobre os dados preservados"
pkg_install "$(pkg "$new")"
vigiahost setup apply >/dev/null || fail "setup apply na reinstalação falhou"
wait_health "$new" >/dev/null || fail "reinstalação não subiu"
journalctl -u vigiahost-core --no-pager -n 50 | grep -q "falha" && fail "erros no journal do core"
ok "reinstalado sobre os dados existentes"

echo "== desinstalação completa (setup uninstall -purge)"
vigiahost setup uninstall -purge -remove-package -yes >/tmp/uninstall.txt || fail "uninstall falhou: $(cat /tmp/uninstall.txt)"
systemctl is-active --quiet vigiahost-core && fail "serviço ativo após o uninstall"
[[ -e /var/lib/vigiahost || -e /etc/vigiahost ]] && fail "dados ou configuração restaram após o -purge"
hash -r # o bash guarda o caminho de comandos já usados
command -v vigiahost >/dev/null && fail "pacote não removido"
ok "desinstalação com -purge: serviços, dados, manifesto e pacote removidos"
echo "CICLO DE VIDA APROVADO ($(. /etc/os-release && echo "$PRETTY_NAME"))"

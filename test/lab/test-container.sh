#!/usr/bin/env bash
# Ciclo de vida do pacote em contêiner sem systemd: instala, executa os binários (executor como root,
# core como vigiahost), confere saúde e diagnóstico, atualiza, volta de versão, remove e, no DEB, faz purge.
# Não depende de rede: usa só o pacote local e o bash (/dev/tcp) para consultar a API.
# Uso (como root, dentro do contêiner): test-container.sh <dir-pacotes> <versão-antiga> <versão-nova>
set -euo pipefail

dir="$1" old="$2" new="$3"
fail() {
	echo "FALHA: $*" >&2
	tail -n 20 /tmp/core.log /tmp/executor.log 2>/dev/null >&2 || true
	exit 1
}
ok() { echo "ok: $*"; }

if command -v rpm >/dev/null 2>&1 && ! command -v dpkg >/dev/null 2>&1; then
	family=rpm
	arch="$(uname -m)"
	pkg() { echo "$dir/vigiahost-$1-1.$arch.rpm"; }
	if command -v dnf >/dev/null 2>&1; then
		pkg_install() { dnf -y -q --disablerepo='*' install "$1" >/dev/null; }
		pkg_downgrade() { dnf -y -q --disablerepo='*' downgrade "$1" >/dev/null; }
		pkg_remove() { dnf -y -q --disablerepo='*' remove vigiahost >/dev/null; }
	else
		pkg_install() { rpm -U --quiet "$1"; }
		pkg_downgrade() { rpm -U --oldpackage --quiet "$1"; }
		pkg_remove() { rpm -e vigiahost; }
	fi
else
	family=deb
	arch="$(dpkg --print-architecture)"
	pkg() { echo "$dir/vigiahost_$1_$arch.deb"; }
	pkg_install() { dpkg -i "$1" >/dev/null; }
	pkg_downgrade() { dpkg -i "$1" >/dev/null 2>&1; }
	pkg_remove() { dpkg -r vigiahost >/dev/null; }
fi

http_get() {
	exec 3<>"/dev/tcp/127.0.0.1/8743" || return 1
	printf 'GET %s HTTP/1.0\r\nHost: 127.0.0.1\r\n\r\n' "$1" >&3
	cat <&3
	exec 3>&-
}

# Executa como o usuário vigiahost. Imagens mínimas (ex.: AlmaLinux 10) não trazem o runuser;
# o chroot do coreutils, sempre presente, troca de usuário sem mudar a raiz.
as_vigiahost() {
	if command -v runuser >/dev/null 2>&1; then
		runuser -u vigiahost -- "$@"
	else
		chroot --userspec=vigiahost:vigiahost / "$@"
	fi
}

start_services() {
	mkdir -p /run/vigiahost-executor /var/lib/vigiahost
	chown vigiahost:vigiahost /var/lib/vigiahost
	chmod 700 /var/lib/vigiahost
	/usr/libexec/vigiahost/vigiahost-executor >/tmp/executor.log 2>&1 &
	executor_pid=$!
	for _ in $(seq 1 20); do [[ -S /run/vigiahost-executor/executor.sock ]] && break; sleep 0.25; done
	as_vigiahost env STATE_DIRECTORY=/var/lib/vigiahost /usr/bin/vigiahost serve >/tmp/core.log 2>&1 &
	core_pid=$!
}

stop_services() {
	kill "$core_pid" "$executor_pid" 2>/dev/null || true
	wait "$core_pid" "$executor_pid" 2>/dev/null || true
}

expect_version() {
	local want="$1" resp
	for _ in $(seq 1 40); do
		resp="$(http_get /api/v1/health 2>/dev/null || true)"
		if grep -q '^HTTP/1.0 200' <<<"$resp" && grep -q "\"version\":\"$want\"" <<<"$resp" &&
			grep -q '"connected":true' <<<"$resp"; then
			return 0
		fi
		sleep 0.25
	done
	fail "API não respondeu com a versão $want e executor conectado: $resp"
}

cycle() {
	local version="$1"
	start_services
	expect_version "$version"
	vigiahost doctor >/tmp/doctor.txt || fail "doctor falhou: $(cat /tmp/doctor.txt)"
	stop_services
	ok "$version em execução: API, executor (SO_PEERCRED) e doctor"
}

pkg_install "$(pkg "$old")"
getent passwd vigiahost >/dev/null || fail "usuário vigiahost não criado"
cycle "$old"

pkg_install "$(pkg "$new")"
cycle "$new"

pkg_downgrade "$(pkg "$old")"
cycle "$old"

pkg_remove
[[ ! -e /usr/bin/vigiahost ]] || fail "binário permaneceu após remover"
[[ -f /var/lib/vigiahost/vigiahost.db ]] || fail "dados apagados na remoção sem purge"
ok "removido com dados preservados"

if [[ "$family" == deb ]]; then
	dpkg -P vigiahost >/dev/null
	[[ ! -e /var/lib/vigiahost ]] || fail "purge não apagou os dados"
	ok "purge apagou os dados"
fi

echo "APROVADO: $(. /etc/os-release && echo "$PRETTY_NAME") ($family)"

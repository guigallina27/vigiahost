#!/bin/sh
# Após instalar ou atualizar.
# DEB: $1 = "configure" e $2 = versão anterior (vazia na primeira instalação).
# RPM: $1 = 1 na instalação e 2 (ou mais) na atualização.
# A instalação não habilita nem inicia os serviços: isso cabe ao "vigiahost setup apply".
set -e

is_upgrade() {
	case "$1" in
	configure) [ -n "$2" ] ;;
	[0-9]*) [ "$1" -gt 1 ] ;;
	*) return 1 ;;
	esac
}

if command -v systemd-sysusers >/dev/null 2>&1; then
	systemd-sysusers /usr/lib/sysusers.d/vigiahost.conf
elif ! getent passwd vigiahost >/dev/null 2>&1; then
	useradd --system --user-group --home-dir /var/lib/vigiahost --no-create-home \
		--shell /usr/sbin/nologin --comment "VigiaHost" vigiahost
fi

if [ -d /run/systemd/system ]; then
	systemctl daemon-reload >/dev/null 2>&1 || true
	if is_upgrade "$@"; then
		# Reinicia apenas os serviços do próprio produto que já estavam ativos.
		systemctl try-restart vigiahost-executor.service vigiahost-core.service >/dev/null 2>&1 || true
	fi
fi
exit 0

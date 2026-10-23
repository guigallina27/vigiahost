#!/bin/sh
# Antes de remover. Na atualização não faz nada, para não derrubar o serviço que a nova versão reinicia.
# DEB: $1 = "remove", "upgrade", "deconfigure" ou "failed-upgrade". RPM: $1 = 0 na remoção, 1 na atualização.
set -e

case "$1" in
remove | deconfigure | 0)
	if [ -d /run/systemd/system ]; then
		systemctl disable --now vigiahost-core.service vigiahost-executor.service >/dev/null 2>&1 || true
	fi
	;;
esac
exit 0

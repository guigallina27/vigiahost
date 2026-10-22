#!/bin/sh
# Depois de remover. Os dados (/var/lib/vigiahost) são preservados; só o "purge" do DEB os apaga.
# O usuário de sistema também é preservado, como recomenda a política do Debian.
# DEB: $1 = "remove", "purge", "upgrade" etc. RPM: $1 = 0 na remoção, 1 na atualização.
set -e

case "$1" in
purge)
	rm -rf /var/lib/vigiahost
	;;
esac

case "$1" in
remove | purge | 0)
	if [ -d /run/systemd/system ]; then
		systemctl daemon-reload >/dev/null 2>&1 || true
	fi
	;;
esac
exit 0

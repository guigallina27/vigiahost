#!/usr/bin/env bash
# Roda test-container.sh em contêineres das distribuições suportadas (níveis 1 e 2 do escopo, seção 5.1).
# Uso (como root, na máquina de laboratório com podman): test-distros.sh <dir-pacotes> <versão-antiga> <versão-nova>
set -uo pipefail

dir="$1" old="$2" new="$3"
here="$(cd "$(dirname "$0")" && pwd)"
logs="$(mktemp -d)"

images=(
	docker.io/library/ubuntu:24.04
	docker.io/library/ubuntu:26.04
	docker.io/library/debian:12
	docker.io/library/debian:13
	docker.io/library/almalinux:9
	docker.io/library/almalinux:10
	docker.io/rockylinux/rockylinux:9
	docker.io/rockylinux/rockylinux:10
	# Nível 2
	docker.io/library/ubuntu:22.04
	docker.io/library/almalinux:8
)

failed=0
for img in "${images[@]}"; do
	log="$logs/$(tr '/:' '__' <<<"$img").log"
	if podman run --rm --pull=missing -v "$dir:/pkgs:ro" -v "$here:/lab:ro" "$img" \
		bash /lab/test-container.sh /pkgs "$old" "$new" >"$log" 2>&1; then
		echo "APROVADO  $img  $(tail -1 "$log")"
	else
		echo "FALHOU    $img"
		tail -n 15 "$log" | sed 's/^/          /'
		failed=$((failed + 1))
	fi
done

echo "logs em $logs"
exit "$failed"

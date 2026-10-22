#!/usr/bin/env bash
# Instala no laboratório os motores usados nos testes de detecção: ClamAV 1.4 LTS (pacote oficial da Cisco Talos)
# e YARA-X (binário oficial da VirusTotal), conferidos pelo SHA-256 fixado abaixo, e baixa as assinaturas do ClamAV.
# As versões seguem a mesma espera de 7 dias das dependências. Uso: install-engines.sh (como root, dnf ou apt).
set -euo pipefail

CLAMAV_VERSION=1.4.6
YARAX_VERSION=1.21.0
declare -A CLAMAV_SHA256=(
	[x86_64.rpm]=746feb3d9f1c2273c38fd9ac3129b2eafa358078870fef3d76afebf9a4bdd4ae
	[aarch64.rpm]=a88c446e29f06da4dadc2f409a71484df0ec093f455bf83687ef2bcc7842821a
	[x86_64.deb]=d3ee9e401974855a1edc1761b1425417d126de618d5f0c91cd51209f69f6fcc2
	[aarch64.deb]=a29cc95aeb225f0dc1b99024b49f1cc109502cb17aaf168637d0901aa9674fe8
)
# Resumos publicados pelo GitHub para cada arquivo dos releases (campo digest da API), consultados em 22/10/2026.
declare -A YARAX_SHA256=(
	[x86_64]=01585181e8979e36ac10ab123fcf8921cf8ba879bf942916413e091e18d64852
	[aarch64]=8d56947d82c7959a65fd4a7327d339d326649f6208c01c9f7fe7fd249e61c66a
)

log() { printf '[motores] %s\n' "$*"; }
arch="$(uname -m)"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

fetch() { # url destino sha256
	curl -fsSL -o "$2" "$1"
	echo "$3  $2" | sha256sum -c --quiet -
}

if command -v rpm >/dev/null 2>&1 && command -v dnf >/dev/null 2>&1; then
	fmt=rpm
else
	fmt=deb
fi

if [[ "$(clamscan --version 2>/dev/null)" == "ClamAV ${CLAMAV_VERSION}/"* || "$(clamscan --version 2>/dev/null)" == "ClamAV ${CLAMAV_VERSION}" ]]; then
	log "ClamAV ${CLAMAV_VERSION} já instalado"
else
	sum="${CLAMAV_SHA256[${arch}.${fmt}]:-}"
	[[ -n "$sum" ]] || { log "sem SHA-256 fixado para clamav ${arch}.${fmt}; preencha CLAMAV_SHA256" >&2; exit 1; }
	pkg="clamav-${CLAMAV_VERSION}.linux.${arch}.${fmt}"
	log "baixando $pkg"
	fetch "https://github.com/Cisco-Talos/clamav/releases/download/clamav-${CLAMAV_VERSION}/${pkg}" "$tmp/$pkg" "$sum"
	if [[ $fmt == rpm ]]; then rpm -Uvh --quiet "$tmp/$pkg"; else dpkg -i "$tmp/$pkg" >/dev/null; fi
fi

if [[ "$(yr --version 2>/dev/null)" == *"${YARAX_VERSION}"* ]]; then
	log "YARA-X ${YARAX_VERSION} já instalado"
else
	tarball="yara-x-v${YARAX_VERSION}-${arch}-unknown-linux-gnu.tar.gz"
	log "baixando $tarball"
	fetch "https://github.com/VirusTotal/yara-x/releases/download/v${YARAX_VERSION}/${tarball}" "$tmp/$tarball" "${YARAX_SHA256[$arch]}"
	tar -C "$tmp" -xzf "$tmp/$tarball"
	install -m 0755 "$(find "$tmp" -type f -name yr | head -1)" /usr/local/bin/yr
fi

# Assinaturas do ClamAV: o pacote oficial instala em /usr/local; o banco fica em /var/lib/clamav.
conf=/usr/local/etc/freshclam.conf
if [[ ! -f $conf ]]; then
	cat >"$conf" <<-EOF
		DatabaseDirectory /var/lib/clamav
		DatabaseOwner root
		DatabaseMirror database.clamav.net
		LogTime yes
	EOF
fi
mkdir -p /var/lib/clamav
log "atualizando assinaturas (freshclam)"
freshclam --quiet --config-file="$conf" || freshclam --config-file="$conf"
log "pronto: $(clamscan --version), $(yr --version)"

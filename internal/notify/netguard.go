package notify

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"syscall"
)

// Endereços sempre recusados, mesmo com rede privada liberada: link-local (169.254.0.0/16 e fe80::/10, onde ficam
// os serviços de metadados das nuvens) e os metadados fora dessas faixas (Alibaba, AWS em IPv6).
var alwaysDenied = []netip.Prefix{
	netip.MustParsePrefix("169.254.0.0/16"),
	netip.MustParsePrefix("fe80::/10"),
	netip.MustParsePrefix("100.100.100.200/32"),
	netip.MustParsePrefix("fd00:ec2::254/128"),
	netip.MustParsePrefix("0.0.0.0/8"),
}

// Faixas que só passam com a opção de rede privada: loopback, RFC 1918, CGNAT, ULA e documentação de rede local.
var privateRanges = []netip.Prefix{
	netip.MustParsePrefix("127.0.0.0/8"),
	netip.MustParsePrefix("10.0.0.0/8"),
	netip.MustParsePrefix("172.16.0.0/12"),
	netip.MustParsePrefix("192.168.0.0/16"),
	netip.MustParsePrefix("100.64.0.0/10"),
	netip.MustParsePrefix("198.18.0.0/15"),
	netip.MustParsePrefix("::1/128"),
	netip.MustParsePrefix("fc00::/7"),
}

// errDenied é a recusa de destino pela política de rede (falha definitiva: nova tentativa não muda nada).
var errDenied = errors.New("destino recusado pela política de rede")

// checkAddr aplica a política a um IP.
func checkAddr(ip netip.Addr, allowPrivate bool) error {
	ip = ip.Unmap()
	for _, p := range alwaysDenied {
		if p.Contains(ip) {
			return fmt.Errorf("%w: %s é link-local ou de metadados de nuvem e nunca é aceito", errDenied, ip)
		}
	}
	if ip.IsUnspecified() || ip.IsMulticast() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
		return fmt.Errorf("%w: %s não é um destino válido", errDenied, ip)
	}
	if allowPrivate {
		return nil
	}
	for _, p := range privateRanges {
		if p.Contains(ip) {
			return fmt.Errorf("%w: %s é de rede privada ou local; permita rede privada no canal se for intencional",
				errDenied, ip)
		}
	}
	if ip.IsPrivate() || ip.IsLoopback() {
		return fmt.Errorf("%w: %s é de rede privada", errDenied, ip)
	}
	return nil
}

// guardControl confere o IP de cada conexão já resolvido, logo antes do connect: vale para todos os endereços que o
// nome devolver e impede a troca de DNS entre a validação e o envio (DNS rebinding).
func guardControl(allowPrivate bool) func(network, address string, c syscall.RawConn) error {
	return func(_, address string, _ syscall.RawConn) error {
		host, _, err := net.SplitHostPort(address)
		if err != nil {
			return permanent{fmt.Errorf("%w: endereço %q", errDenied, address)}
		}
		ip, err := netip.ParseAddr(host)
		if err != nil {
			return permanent{fmt.Errorf("%w: endereço %q", errDenied, host)}
		}
		if err := checkAddr(ip, allowPrivate); err != nil {
			return permanent{err}
		}
		return nil
	}
}

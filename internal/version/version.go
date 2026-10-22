// Package version expõe a versão do produto e a do protocolo entre o core e o executor.
package version

// Preenchidas no build com -ldflags "-X github.com/guigallina27/vigiahost/internal/version.Version=...".
var (
	Version = "0.0.0-dev"
	Commit  = "desconhecido"
	Date    = "desconhecida"
)

// Versão do protocolo core–executor. Mudança incompatível incrementa ProtocolMajor;
// campos ou operações novas e opcionais incrementam ProtocolMinor.
const (
	ProtocolMajor = 1
	ProtocolMinor = 1
)

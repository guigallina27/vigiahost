package executor

import (
	"github.com/guigallina27/vigiahost/internal/ipc"
	"github.com/guigallina27/vigiahost/internal/profile"
	"github.com/guigallina27/vigiahost/internal/report"
)

// MergeAdjust aplica os campos do ajuste ao perfil efetivo da execução e confere o resultado com as mesmas travas do
// início. Só CPU, memória, banda de leitura e peso de E/S mudam: workers, nice, tempo máximo e limiares de pressão
// continuam os do pedido original, gravado pelo próprio executor (o core não tem como trocá-los aqui).
func MergeAdjust(current report.Profile, in ipc.RunAdjust, hw profile.Hardware, allowNoReserve bool) (report.Profile, error) {
	if in.Empty() {
		return report.Profile{}, &ipc.Error{Code: ipc.CodeBadRequest, Message: "informe ao menos um limite para ajustar"}
	}
	next := current
	if in.CPUQuotaPercent != nil {
		next.CPUQuotaPercent = *in.CPUQuotaPercent
	}
	if in.MemoryMaxBytes != nil {
		next.MemoryMaxBytes = *in.MemoryMaxBytes
	}
	if in.IOReadBytesPerSec != nil {
		next.IOReadBytesPerSec = *in.IOReadBytesPerSec
	}
	if in.IOWeight != nil {
		if *in.IOWeight == 0 {
			// Zero no perfil quer dizer "padrão"; num ajuste explícito é pedido inválido.
			return report.Profile{}, &ipc.Error{Code: ipc.CodeLimitRefused, Message: "limite recusado: peso de E/S deve ficar entre 1 e 10000"}
		}
		next.IOWeight = *in.IOWeight
	}
	p, err := profile.Enforce(next, hw, in.NoReserve, allowNoReserve)
	if err != nil {
		return report.Profile{}, &ipc.Error{Code: ipc.CodeLimitRefused, Message: err.Error()}
	}
	return p, nil
}

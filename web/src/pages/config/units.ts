// Unidades usadas nas telas de configuração e de inventário (memória, banda, duração).
// Unidades binárias (KiB, MiB, GiB): é assim que o kernel e o systemd contam memória e limites de cgroup.

export const MIB = 1 << 20;

const BYTE_UNITS = ["B", "KiB", "MiB", "GiB", "TiB"] as const;

/** "512 MiB", "1,5 GiB": no máximo uma casa decimal, no idioma ativo. */
export function formatBytes(bytes: number, locale: string): string {
  if (!Number.isFinite(bytes) || bytes < 0) return "—";
  let value = bytes;
  let unit = 0;
  while (value >= 1024 && unit < BYTE_UNITS.length - 1) {
    value /= 1024;
    unit++;
  }
  const fmt = new Intl.NumberFormat(locale, { maximumFractionDigits: unit === 0 ? 0 : 1 });
  return `${fmt.format(value)} ${BYTE_UNITS[unit]}`;
}

/** Bytes para MiB inteiros (formulários), arredondando. */
export function bytesToMiB(bytes: number): number {
  return Math.round(bytes / MIB);
}

/** MiB (texto do formulário) para bytes; NaN quando não é número. */
export function mibToBytes(mib: number): number {
  return Math.round(mib * MIB);
}

/** Separa segundos em horas e minutos (para "12 h 30 min"). */
export function splitDuration(seconds: number): { hours: number; minutes: number } {
  const total = Math.max(0, Math.round(seconds / 60));
  return { hours: Math.floor(total / 60), minutes: total % 60 };
}

/** Número com até `digits` casas decimais no idioma ativo ("1,25"). */
export function formatDecimal(value: number, locale: string, digits = 1): string {
  return new Intl.NumberFormat(locale, { maximumFractionDigits: digits }).format(value);
}

/** Valor que já está em porcentagem (pressão PSI: 12.5 → "12,5%"). */
export function formatPercentValue(value: number, locale: string): string {
  return `${formatDecimal(value, locale, 1)}%`;
}

// Datas e números sempre por Intl, no idioma ativo (escopo, seção 14).

const UNITS: [Intl.RelativeTimeFormatUnit, number][] = [
  ["year", 365 * 24 * 3600],
  ["month", 30 * 24 * 3600],
  ["week", 7 * 24 * 3600],
  ["day", 24 * 3600],
  ["hour", 3600],
  ["minute", 60],
  ["second", 1],
];

/** "há 6 horas", "em 2 minutos"; abaixo de 45 s, "agora". */
export function formatRelative(date: Date, locale: string, now: Date = new Date()): string {
  const diff = (date.getTime() - now.getTime()) / 1000;
  const rtf = new Intl.RelativeTimeFormat(locale, { numeric: "auto", style: "long" });
  if (Math.abs(diff) < 45) return rtf.format(0, "second");
  for (const [unit, seconds] of UNITS) {
    if (Math.abs(diff) >= seconds || unit === "second") {
      return rtf.format(Math.round(diff / seconds), unit);
    }
  }
  return rtf.format(0, "second");
}

/** Data e hora absolutas no fuso informado (o do servidor, quando a API o fornece). */
export function formatAbsolute(date: Date, locale: string, timeZone?: string): string {
  return new Intl.DateTimeFormat(locale, {
    dateStyle: "short",
    timeStyle: "medium",
    ...(timeZone ? { timeZone } : {}),
  }).format(date);
}

/** Nome curto do fuso, ex.: "BRT" ou "GMT-3". */
export function formatZoneName(date: Date, locale: string, timeZone?: string): string {
  const part = new Intl.DateTimeFormat(locale, {
    timeZoneName: "short",
    ...(timeZone ? { timeZone } : {}),
  })
    .formatToParts(date)
    .find((p) => p.type === "timeZoneName");
  return part?.value ?? timeZone ?? "";
}

export function formatNumber(value: number, locale: string): string {
  return new Intl.NumberFormat(locale).format(value);
}

/**
 * Percentual com uma casa decimal. Nunca arredonda para 100% quando falta algo,
 * nem para 0% quando há algum: "99,99%" vira "99,9%", não "100,0%".
 */
export function formatPercent(part: number, whole: number, locale: string): string {
  const fmt = new Intl.NumberFormat(locale, { style: "percent", minimumFractionDigits: 1, maximumFractionDigits: 1 });
  if (whole <= 0) return fmt.format(0);
  let ratio = part / whole;
  if (part < whole) ratio = Math.min(ratio, 0.999);
  if (part > 0) ratio = Math.max(ratio, 0.001);
  return fmt.format(Math.floor(ratio * 1000) / 1000);
}

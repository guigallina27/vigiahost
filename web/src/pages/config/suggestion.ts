import type { TFunction } from "i18next";
import type { Schemas } from "../../api/client";
import { formatBytes, formatDecimal } from "./units";

// Explicação da sugestão de perfil: cada motivo vem do servidor como código + valores numéricos; aqui eles viram
// texto no idioma ativo, com cada valor na unidade certa.

export type SuggestionReason = Schemas["SuggestionReason"];

const KNOWN = [
  "cpu_busy",
  "cpu_idle",
  "cpu_normal",
  "memory_normal",
  "memory_small",
  "memory_pressure",
  "disk_hdd",
  "disk_ssd",
  "disk_nvme",
  "workers_cpu",
  "io_busy",
  "history_limited",
  "nice",
  "pressure_thresholds",
  "pressure_unavailable",
] as const satisfies readonly SuggestionReason["code"][];

const BYTES = new Set(["total", "max", "io_read"]);
const TWO_DECIMALS = new Set(["load_per_core"]);

/** Valores formatados para a interpolação: bytes em MiB/GiB, carga com duas casas, o resto com até uma. */
export function formatReasonValues(values: Record<string, number>, locale: string): Record<string, string> {
  const out: Record<string, string> = {};
  for (const [key, value] of Object.entries(values)) {
    if (BYTES.has(key)) out[key] = formatBytes(value, locale);
    else if (TWO_DECIMALS.has(key)) out[key] = formatDecimal(value, locale, 2);
    else out[key] = formatDecimal(value, locale, 1);
  }
  return out;
}

/** Texto de um motivo; código desconhecido (servidor mais novo) vira uma linha genérica com o código. */
export function reasonText(reason: SuggestionReason, t: TFunction, locale: string): string {
  const values = formatReasonValues(reason.values, locale);
  if ((KNOWN as readonly string[]).includes(reason.code)) {
    return t(`config.resources.suggestion.reasons.${reason.code}`, { ...values, defaultValue: reason.code });
  }
  return t("config.resources.suggestion.reasons.unknown", { code: reason.code });
}

/** Perfil a gravar ao aplicar a sugestão: o sugerido, com o nome do perfil próprio. */
export function suggestedProfileBody(s: Schemas["ProfileSuggestion"]): Schemas["ResourceProfile"] {
  return { ...s.profile, name: "sugerido" };
}

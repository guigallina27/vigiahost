import type { Schemas } from "../../api/client";
import type { Tone } from "../../components/Badge";
import { severities } from "../../components/SeverityBadge";
import type { SeverityCountsValue } from "../../components/SeverityCounts";

// Regras puras das telas Integridade e Atualizações (testáveis sem React).

export type IntegrityReport = Schemas["IntegrityReport"];
export type IntegrityFile = Schemas["IntegrityFile"];
export type UpdatesReport = Schemas["UpdatesReport"];
export type PackageUpdate = Schemas["PackageUpdate"];
export type PackageRef = Schemas["PackageRef"];
export type SystemKind = "integrity" | "updates";

/** Rota de cada tela e a categoria dos achados que ela explica. */
export const systemScreens: Record<SystemKind, { path: string; category: string }> = {
  integrity: { path: "/integridade", category: "integrity" },
  updates: { path: "/atualizacoes", category: "update" },
};

/** Lista de achados abertos da categoria (correções pendentes, arquivos diferentes do pacote). */
export function systemFindingsHref(kind: SystemKind): string {
  return `/achados?category=${systemScreens[kind].category}`;
}

/** Endereço da tela para um relatório específico (o mais recente sem execução). */
export function reportHref(kind: SystemKind, runId?: string): string {
  return runId ? `${systemScreens[kind].path}?execucao=${encodeURIComponent(runId)}` : systemScreens[kind].path;
}

/** Contagem por gravidade no formato do componente de contagens (gravidades desconhecidas são ignoradas). */
export function severityCounts(by: Record<string, number>): SeverityCountsValue {
  const out = { critical: 0, high: 0, medium: 0, low: 0, info: 0, total: 0 };
  for (const s of severities) {
    const v = by[s] ?? 0;
    out[s] = v;
    out.total += v;
  }
  return out;
}

/** "nome-versão.arquitetura", como o gerenciador mostra. */
export function packageText(p: PackageRef): string {
  return p.arch ? `${p.name}-${p.version}.${p.arch}` : `${p.name}-${p.version}`;
}

// --- Atualizações ---

export type UpdateSeverity = "critical" | "important" | "moderate" | "low" | "unknown";
const updateSeverities: UpdateSeverity[] = ["critical", "important", "moderate", "low", "unknown"];

export function updateSeverity(value: string | undefined): UpdateSeverity {
  return updateSeverities.find((s) => s === value) ?? "unknown";
}

/** Tom do selo da gravidade do aviso do fornecedor (mesma escala dos achados: importante é alto). */
export function updateTone(value: string | undefined): Tone {
  switch (updateSeverity(value)) {
    case "critical":
      return "critical";
    case "important":
      return "high";
    case "moderate":
      return "medium";
    case "low":
      return "low";
    default:
      return "neutral";
  }
}

/** Correções de segurança da mais grave para a menos grave; empate pelo nome. */
export function sortUpdates(list: readonly PackageUpdate[]): PackageUpdate[] {
  const rank = (u: PackageUpdate) => updateSeverities.indexOf(updateSeverity(u.severity));
  return [...list].sort((a, b) => rank(a) - rank(b) || a.name.localeCompare(b.name));
}

/** Contagem dos avisos por gravidade, na ordem da escala. */
export function updateSeverityEntries(by: Record<string, number>): [UpdateSeverity, number][] {
  return updateSeverities.filter((s) => (by[s] ?? 0) > 0).map((s) => [s, by[s] ?? 0]);
}

export const STALE_CACHE_DAYS = 7;

/** Situação da lista de pacotes: ausente, antiga (mais de 7 dias) ou em dia. */
export function cacheState(report: Pick<UpdatesReport, "cache_updated_at">, now: Date = new Date()): "never" | "stale" | "fresh" {
  if (!report.cache_updated_at) return "never";
  const age = now.getTime() - new Date(report.cache_updated_at).getTime();
  return age > STALE_CACHE_DAYS * 24 * 3600 * 1000 ? "stale" : "fresh";
}

/** Ferramentas que a verificação usa em cada família (as de reinício são opcionais e só ganham dica). */
export function expectedTools(manager: string): { name: string; optional: boolean }[] {
  if (manager === "rpm") return [{ name: "dnf", optional: false }, { name: "needs-restarting", optional: true }];
  if (manager === "dpkg") return [{ name: "apt", optional: false }, { name: "needrestart", optional: true }];
  return [];
}

export const toolHints = ["needs-restarting", "needrestart"] as const;
export type ToolHint = (typeof toolHints)[number];

export function isToolHint(name: string): name is ToolHint {
  return (toolHints as readonly string[]).includes(name);
}

// --- Integridade ---

const changes = ["size", "mode", "digest", "device", "link", "user", "group", "mtime", "capabilities", "missing"] as const;
export type Change = (typeof changes)[number];

export function isChange(v: string): v is Change {
  return (changes as readonly string[]).includes(v);
}

const ignoreReasons = ["doc", "ghost", "mtime_only", "directory", "unchecked"] as const;
export type IgnoreReason = (typeof ignoreReasons)[number];

/** Diferenças ignoradas com quantidade, na ordem fixa dos motivos (motivo desconhecido fica de fora). */
export function ignoredEntries(ignored: Record<string, number>): [IgnoreReason, number][] {
  return ignoreReasons.filter((r) => (ignored[r] ?? 0) > 0).map((r) => [r, ignored[r] ?? 0]);
}

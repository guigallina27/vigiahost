import type { Schemas } from "../../api/client";
import { choiceToSelection, parseUid, type AccountChoice } from "../accounts/accounts";

// Regras puras das telas de execução (filtros, corpo do pedido, ações por estado, formatação), testáveis sem React.

export type Run = Schemas["Run"];
export type RunKind = Schemas["RunKind"];
export type RunStatus = Schemas["RunStatus"];
export type RunCreate = Schemas["RunCreate"];

export const ACTIVE_STATUSES: RunStatus[] = ["queued", "reserved", "running"];

export function isActive(status: RunStatus): boolean {
  return ACTIVE_STATUSES.includes(status);
}

// --- Filtros da lista (guardados no endereço para poder compartilhar e voltar) ---

/** Grupos de estado em linguagem do operador; cada um vira a lista de estados aceita pela API. */
export const STATUS_GROUPS = {
  active: ["queued", "reserved", "running"],
  completed: ["completed"],
  partial: ["partial"],
  failed: ["failed", "engine_failure", "interrupted"],
  canceled: ["canceled"],
} as const satisfies Record<string, readonly RunStatus[]>;

export type StatusGroup = keyof typeof STATUS_GROUPS;
export const STATUS_GROUP_KEYS = Object.keys(STATUS_GROUPS) as StatusGroup[];
export const RUN_KINDS: RunKind[] = ["files", "processes"];

export type RunFilters = { status?: StatusGroup; kind?: RunKind; /** Só execuções que cobriram a conta (UID). */ account?: number };

/** Lê os filtros do endereço, ignorando valores desconhecidos (endereço editado à mão ou antigo). */
export function filtersFromSearch(params: URLSearchParams): RunFilters {
  const out: RunFilters = {};
  const status = params.get("status");
  if (status && (STATUS_GROUP_KEYS as string[]).includes(status)) out.status = status as StatusGroup;
  const kind = params.get("kind");
  if (kind && (RUN_KINDS as string[]).includes(kind)) out.kind = kind as RunKind;
  const account = parseUid(params.get("account"));
  if (account !== undefined) out.account = account;
  return out;
}

/** Parâmetros de consulta da API para os filtros (sem chaves vazias, para a chave de cache ficar estável). */
export function filtersToQuery(f: RunFilters): { status?: RunStatus[]; kind?: RunKind; account?: number } {
  const q: { status?: RunStatus[]; kind?: RunKind; account?: number } = {};
  if (f.status) q.status = [...STATUS_GROUPS[f.status]];
  if (f.kind) q.kind = f.kind;
  if (f.account !== undefined) q.account = f.account;
  return q;
}

// --- Pedido de nova verificação ---

export const MAX_PATHS = 64;
export const MAX_EXCLUDE = 256;

/** Uma entrada por linha: apara espaços, descarta linhas vazias e repetições, preservando a ordem. */
export function parseLines(text: string): string[] {
  const seen = new Set<string>();
  const out: string[] = [];
  for (const raw of text.split(/\r?\n/)) {
    const line = raw.trim();
    if (!line || seen.has(line)) continue;
    seen.add(line);
    out.push(line);
  }
  return out;
}

export type RunDraft = {
  kind: RunKind;
  paths: string;
  exclude: string;
  incremental: boolean;
  /** Vazio: o servidor usa o perfil padrão. */
  profile: string;
  /** Contas do servidor; com elas, os caminhos ficam opcionais (o servidor monta o escopo de cada conta). */
  accounts?: AccountChoice;
};

export type DraftError =
  | { field: "paths"; code: "pathsRequired" }
  | { field: "accounts"; code: "accountsRequired" }
  | { field: "paths" | "exclude"; code: "notAbsolute"; path: string }
  | { field: "paths"; code: "pathsTooMany"; max: number }
  | { field: "exclude"; code: "excludeTooMany"; max: number };

/**
 * Monta o corpo de POST /api/v1/runs. Confere antes do envio só o que o servidor recusaria com certeza
 * (lista vazia, caminho relativo, quantidade); a política de caminhos permitidos continua no servidor.
 */
export function buildRunCreate(draft: RunDraft): { ok: true; body: RunCreate } | { ok: false; error: DraftError } {
  // O executor só usa "incremental" em arquivos; em processos a verificação é sempre completa.
  const body: RunCreate = { kind: draft.kind, incremental: draft.kind === "files" && draft.incremental };
  if (draft.profile) body.profile = draft.profile;
  if (draft.kind === "processes") return { ok: true, body };

  const accounts = draft.accounts ? choiceToSelection(draft.accounts) : undefined;
  if (draft.accounts?.mode === "selected" && !accounts) {
    return { ok: false, error: { field: "accounts", code: "accountsRequired" } };
  }
  const paths = parseLines(draft.paths);
  if (paths.length === 0 && !accounts) return { ok: false, error: { field: "paths", code: "pathsRequired" } };
  if (paths.length > MAX_PATHS) return { ok: false, error: { field: "paths", code: "pathsTooMany", max: MAX_PATHS } };
  const badPath = paths.find((p) => !p.startsWith("/"));
  if (badPath) return { ok: false, error: { field: "paths", code: "notAbsolute", path: badPath } };

  const exclude = parseLines(draft.exclude);
  if (exclude.length > MAX_EXCLUDE) {
    return { ok: false, error: { field: "exclude", code: "excludeTooMany", max: MAX_EXCLUDE } };
  }
  const badExclude = exclude.find((p) => !p.startsWith("/"));
  if (badExclude) return { ok: false, error: { field: "exclude", code: "notAbsolute", path: badExclude } };

  if (paths.length > 0) body.paths = paths;
  if (accounts) body.accounts = accounts;
  if (exclude.length > 0) body.exclude = exclude;
  return { ok: true, body };
}

// --- Ações conforme o estado (o servidor responde 409 se o estado mudou nesse meio-tempo) ---

export type RunAction = "pause" | "resume" | "limits" | "cancel";

export function runActions(run: Pick<Run, "status" | "paused">): RunAction[] {
  switch (run.status) {
    case "queued":
    case "reserved":
      return ["cancel"];
    case "running":
      return [run.paused ? "resume" : "pause", "limits", "cancel"];
    default:
      return [];
  }
}

// --- Motivos de arquivos fora da análise (internal/report/report.go, SkipReason) ---

export const SKIP_REASONS = [
  "excluded",
  "too_large",
  "permission",
  "not_regular",
  "changed_during_read",
  "timeout",
  "engine_error",
  "other_filesystem",
  "cached",
] as const;

export type SkipReason = (typeof SKIP_REASONS)[number];

export function isKnownSkipReason(reason: string): reason is SkipReason {
  return (SKIP_REASONS as readonly string[]).includes(reason);
}

export type SkipEntry = { reason: string; count: number };

/**
 * Motivos com contagem positiva, na ordem do glossário (desconhecidos no fim, em ordem alfabética).
 * "cached" fica de fora: o arquivo já analisado com as mesmas versões conta como analisado.
 */
export function skipEntries(map: Record<string, number> | undefined | null): SkipEntry[] {
  if (!map) return [];
  const rank = (r: string) => {
    const i = (SKIP_REASONS as readonly string[]).indexOf(r);
    return i < 0 ? SKIP_REASONS.length : i;
  };
  return Object.entries(map)
    .filter(([reason, count]) => reason !== "cached" && count > 0)
    .map(([reason, count]) => ({ reason, count }))
    .sort((a, b) => rank(a.reason) - rank(b.reason) || a.reason.localeCompare(b.reason));
}

export function skippedTotal(map: Record<string, number> | undefined | null): number {
  return skipEntries(map).reduce((sum, e) => sum + e.count, 0);
}

// --- Formatação ---

/** Segundos entre início e fim (ou agora, se ainda roda); null se não começou. */
export function durationSeconds(run: Pick<Run, "started_at" | "finished_at">, now: Date = new Date()): number | null {
  if (!run.started_at) return null;
  const start = new Date(run.started_at).getTime();
  const end = run.finished_at ? new Date(run.finished_at).getTime() : now.getTime();
  if (Number.isNaN(start) || Number.isNaN(end)) return null;
  return Math.max(0, Math.round((end - start) / 1000));
}

function unit(locale: string, u: "hour" | "minute" | "second", value: number): string {
  return new Intl.NumberFormat(locale, { style: "unit", unit: u, unitDisplay: "short" }).format(value);
}

/** "42 s", "5 min 3 s", "2 h 15 min" (no idioma ativo; segundos somem a partir de uma hora). */
export function formatDuration(seconds: number, locale: string): string {
  const total = Math.max(0, Math.round(seconds));
  const h = Math.floor(total / 3600);
  const m = Math.floor((total % 3600) / 60);
  const s = total % 60;
  if (h > 0) return m > 0 ? `${unit(locale, "hour", h)} ${unit(locale, "minute", m)}` : unit(locale, "hour", h);
  if (m > 0) return s > 0 ? `${unit(locale, "minute", m)} ${unit(locale, "second", s)}` : unit(locale, "minute", m);
  return unit(locale, "second", s);
}

const BYTE_UNITS = ["byte", "kilobyte", "megabyte", "gigabyte", "terabyte", "petabyte"] as const;

/** Volume em unidades decimais (1 MB = 1.000.000 bytes), com uma casa a partir de kB. */
export function formatBytes(bytes: number, locale: string): string {
  let value = Math.max(0, bytes);
  let i = 0;
  while (value >= 1000 && i < BYTE_UNITS.length - 1) {
    value /= 1000;
    i++;
  }
  return new Intl.NumberFormat(locale, {
    style: "unit",
    unit: BYTE_UNITS[i] ?? "byte",
    unitDisplay: "short",
    maximumFractionDigits: i === 0 ? 0 : 1,
  }).format(value);
}

/** Converte data opcional da API em Date (ou undefined). */
export function toDate(value: string | undefined | null): Date | undefined {
  if (!value) return undefined;
  const d = new Date(value);
  return Number.isNaN(d.getTime()) ? undefined : d;
}

/** Chave de idempotência do pedido (clique duplo ou nova tentativa devolvem a mesma execução). */
export function newIdempotencyKey(): string | undefined {
  const c = globalThis.crypto;
  if (c && typeof c.randomUUID === "function") return c.randomUUID();
  if (c && typeof c.getRandomValues === "function") {
    const b = c.getRandomValues(new Uint8Array(16));
    return Array.from(b, (x) => x.toString(16).padStart(2, "0")).join("");
  }
  return undefined;
}

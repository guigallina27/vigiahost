import type { Schemas } from "../../api/client";

// Lógica pura do inventário de processos e de persistência (filtros, ordenação, agrupamento), testável sem tela.

export type ProcessInfo = Schemas["ProcessInfo"];
export type PersistenceEntry = Schemas["PersistenceEntry"];
export type PersistenceInventory = Schemas["PersistenceInventory"];

export type ProcessSortKey = "pid" | "cpu" | "memory";
export type SortDirection = "asc" | "desc";

export type ProcessFilter = {
  query: string;
  onlyFlagged: boolean;
  onlyNetwork: boolean;
};

export const emptyFilter: ProcessFilter = { query: "", onlyFlagged: false, onlyNetwork: false };

export function hasNetwork(p: ProcessInfo): boolean {
  return (p.listening?.length ?? 0) > 0 || (p.connected?.length ?? 0) > 0;
}

export function isFlagged(p: ProcessInfo): boolean {
  return (p.flags?.length ?? 0) > 0;
}

/**
 * Situação do pacote dono do executável: o executor grava "-" quando nenhum pacote o reconhece
 * (o que merece atenção) e omite o campo quando a consulta não foi feita.
 */
export function packageState(pkg: string | undefined): "none" | "unknown" | "known" {
  if (pkg === undefined || pkg.trim() === "") return "unknown";
  if (pkg.trim() === "-") return "none";
  return "known";
}

/** Busca por nome, executável, usuário, unidade do systemd ou PID exato, sem diferenciar maiúsculas. */
export function filterProcesses(list: readonly ProcessInfo[], filter: ProcessFilter): ProcessInfo[] {
  const q = filter.query.trim().toLowerCase();
  return list.filter((p) => {
    if (filter.onlyFlagged && !isFlagged(p)) return false;
    if (filter.onlyNetwork && !hasNetwork(p)) return false;
    if (!q) return true;
    if (String(p.pid) === q) return true;
    return [p.comm, p.exe, p.user ?? "", p.unit ?? ""].some((v) => v.toLowerCase().includes(q));
  });
}

const sortValue: Record<ProcessSortKey, (p: ProcessInfo) => number> = {
  pid: (p) => p.pid,
  cpu: (p) => p.cpu_percent,
  memory: (p) => p.rss_bytes,
};

/** Ordena sem alterar a lista original; empate desempata pelo PID, para a ordem não "pular" entre atualizações. */
export function sortProcesses(list: readonly ProcessInfo[], key: ProcessSortKey, dir: SortDirection): ProcessInfo[] {
  const get = sortValue[key];
  const sign = dir === "asc" ? 1 : -1;
  return [...list].sort((a, b) => {
    const diff = get(a) - get(b);
    if (diff !== 0) return diff * sign;
    return a.pid - b.pid;
  });
}

/** CPU com uma casa decimal ("12,5%"). O valor já vem em pontos percentuais de um núcleo. */
export function formatCpu(value: number, locale: string): string {
  return `${new Intl.NumberFormat(locale, { maximumFractionDigits: 1 }).format(value)}%`;
}

// Tipos de persistência gravados pelo executor (internal/inspect), dos mais sensíveis para os mais comuns.
export const persistenceKinds = [
  "ld-so-preload",
  "authorized-keys",
  "sudoers",
  "pam",
  "sshd-config",
  "kernel-module",
  "kernel",
  "cron",
  "at-job",
  "systemd-unit",
  "systemd-user-unit",
  "systemd-generator",
  "rc-local",
  "init-d",
  "shell-init",
  "ld-so-conf",
  "udev-rule",
] as const;

export type PersistenceKind = (typeof persistenceKinds)[number];

export function isKnownKind(kind: string): kind is PersistenceKind {
  return (persistenceKinds as readonly string[]).includes(kind);
}

export type PersistenceGroup = { kind: string; items: PersistenceEntry[] };

/** Agrupa por tipo na ordem acima (tipos desconhecidos vão ao fim, em ordem alfabética); itens por caminho. */
export function groupPersistence(items: readonly PersistenceEntry[], onlyChanged = false): PersistenceGroup[] {
  const map = new Map<string, PersistenceEntry[]>();
  for (const it of items) {
    if (onlyChanged && !it.change) continue;
    const list = map.get(it.kind);
    if (list) list.push(it);
    else map.set(it.kind, [it]);
  }
  const rank = (k: string) => {
    const i = (persistenceKinds as readonly string[]).indexOf(k);
    return i === -1 ? persistenceKinds.length : i;
  };
  return [...map.entries()]
    .sort(([a], [b]) => rank(a) - rank(b) || a.localeCompare(b))
    .map(([kind, list]) => ({ kind, items: [...list].sort((x, y) => x.path.localeCompare(y.path)) }));
}

export function summarizeChanges(inv: Pick<PersistenceInventory, "items" | "removed">) {
  let added = 0;
  let changed = 0;
  for (const it of inv.items) {
    if (it.change === "added") added++;
    else if (it.change === "changed") changed++;
  }
  return { total: inv.items.length, added, changed, removed: inv.removed?.length ?? 0 };
}

/** Link para os achados de uma assinatura (marca de processo). */
export function findingsLink(signature: string): string {
  return `/achados?q=${encodeURIComponent(signature)}`;
}

const RUN_ID = /^[a-z0-9][a-z0-9-]{0,39}$/;

/** Identificador de execução vindo da URL; ignora valores fora do padrão do contrato. */
export function parseRunId(value: string | null): string | undefined {
  return value && RUN_ID.test(value) ? value : undefined;
}

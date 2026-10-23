import { ApiError, type Schemas } from "../../api/client";

// Regras puras da tela Contas (filtros na URL, ordenação por risco, corpo do pedido de verificação e atribuição do
// inventário à conta), testáveis sem React. A atribuição repete a do servidor (internal/core/handlers_accounts.go).

export type Account = Schemas["Account"];
export type AccountList = Schemas["AccountList"];
export type AccountSelection = Schemas["AccountSelection"];
export type RunCreate = Schemas["RunCreate"];
export type ProcessInfo = Schemas["ProcessInfo"];
export type PersistenceEntry = Schemas["PersistenceEntry"];

// --- Filtros da lista (guardados no endereço) ---

export const ACCOUNT_SORTS = ["risk", "name", "uid", "lastRun"] as const;
export type AccountSort = (typeof ACCOUNT_SORTS)[number];

export type AccountFilters = {
  /** Trecho do nome, do UID ou do diretório pessoal. */
  q: string;
  /** Inclui as contas de sistema (root, serviços): vira system=true na API. */
  system: boolean;
  /** Só contas com achados abertos. */
  withFindings: boolean;
  sort: AccountSort;
};

export const defaultAccountFilters: AccountFilters = { q: "", system: false, withFindings: false, sort: "risk" };

/** Lê os filtros do endereço; valores desconhecidos voltam ao padrão. */
export function parseAccountFilters(params: URLSearchParams): AccountFilters {
  const sort = params.get("sort");
  return {
    q: (params.get("q") ?? "").trim().slice(0, 256),
    system: params.get("system") === "1",
    withFindings: params.get("findings") === "1",
    sort: sort && (ACCOUNT_SORTS as readonly string[]).includes(sort) ? (sort as AccountSort) : "risk",
  };
}

/** Escreve os filtros no endereço omitindo o padrão, para os links ficarem curtos. */
export function accountFiltersToParams(f: AccountFilters): URLSearchParams {
  const p = new URLSearchParams();
  if (f.q) p.set("q", f.q);
  if (f.system) p.set("system", "1");
  if (f.withFindings) p.set("findings", "1");
  if (f.sort !== "risk") p.set("sort", f.sort);
  return p;
}

/** Algo além da ordenação reduz a lista (para oferecer "Limpar filtros" no estado vazio). */
export function narrowsList(f: AccountFilters): boolean {
  return f.q !== "" || f.withFindings;
}

/** Busca sem diferenciar maiúsculas por nome, UID ou diretório pessoal. */
export function matchesAccount(a: Pick<Account, "name" | "uid" | "home">, query: string): boolean {
  const q = query.trim().toLowerCase();
  if (!q) return true;
  return a.name.toLowerCase().includes(q) || String(a.uid).includes(q) || a.home.toLowerCase().includes(q);
}

export function filterAccounts(list: readonly Account[], f: Pick<AccountFilters, "q" | "withFindings">): Account[] {
  return list.filter((a) => (!f.withFindings || a.open_findings.total > 0) && matchesAccount(a, f.q));
}

const byName = (a: Account, b: Account) => a.name.localeCompare(b.name) || a.uid - b.uid;

/**
 * Ordem de risco: mais críticos primeiro, depois altos, médios, baixos e informativos; empate pelo total de achados
 * abertos e, por fim, pelo nome (a ordem não "pula" entre atualizações).
 */
export function compareRisk(a: Account, b: Account): number {
  const x = a.open_findings;
  const y = b.open_findings;
  return (
    y.critical - x.critical ||
    y.high - x.high ||
    y.medium - x.medium ||
    y.low - x.low ||
    y.info - x.info ||
    y.total - x.total ||
    byName(a, b)
  );
}

function lastRunTime(a: Account): number {
  const v = a.last_run?.finished_at ?? a.last_run?.created_at;
  const time = v ? new Date(v).getTime() : Number.NaN;
  return Number.isNaN(time) ? -Infinity : time;
}

const comparators: Record<AccountSort, (a: Account, b: Account) => number> = {
  risk: compareRisk,
  name: byName,
  uid: (a, b) => a.uid - b.uid,
  // Mais recente primeiro; contas nunca verificadas no fim, por nome.
  lastRun: (a, b) => {
    const x = lastRunTime(a);
    const y = lastRunTime(b);
    if (x === y) return byName(a, b);
    return y > x ? 1 : -1;
  },
};

/** Ordena sem alterar a lista original. */
export function sortAccounts(list: readonly Account[], sort: AccountSort): Account[] {
  return [...list].sort(comparators[sort]);
}

/** Lista exibida: filtra e ordena (5.000 contas ficam bem abaixo de 50 ms). */
export function visibleAccounts(list: readonly Account[], f: AccountFilters): Account[] {
  return sortAccounts(filterAccounts(list, f), f.sort);
}

// --- Pedido de verificação ---

export type ScanTarget = { kind: "all" } | { kind: "uids"; uids: number[] };

/** UIDs sem repetição, em ordem crescente, só inteiros não negativos. */
export function cleanUids(uids: Iterable<number>): number[] {
  return [...new Set(uids)].filter((u) => Number.isInteger(u) && u >= 0).sort((a, b) => a - b);
}

/** Corpo de POST /api/v1/runs para verificar contas (o servidor monta os caminhos de cada uma). */
export function buildAccountsRun(target: ScanTarget): RunCreate {
  if (target.kind === "all") return { kind: "files", incremental: true, accounts: { all: true } };
  return { kind: "files", incremental: true, accounts: { uids: cleanUids(target.uids) } };
}

// --- Escolha de contas nos formulários (nova verificação e agendamento) ---

export type AccountChoice = { mode: "none" | "all" | "selected"; uids: number[] };

export const noAccounts: AccountChoice = { mode: "none", uids: [] };

/** Seleção para o contrato; undefined quando nenhuma conta foi escolhida (o campo nem vai no corpo). */
export function choiceToSelection(choice: AccountChoice): AccountSelection | undefined {
  if (choice.mode === "all") return { all: true };
  if (choice.mode === "selected") {
    const uids = cleanUids(choice.uids);
    return uids.length > 0 ? { uids } : undefined;
  }
  return undefined;
}

export function selectionToChoice(sel: AccountSelection | undefined): AccountChoice {
  if (sel?.all) return { mode: "all", uids: [] };
  const uids = cleanUids(sel?.uids ?? []);
  return uids.length > 0 ? { mode: "selected", uids } : noAccounts;
}

/** Alterna um UID na seleção. */
export function toggleUid(uids: readonly number[], uid: number): number[] {
  return uids.includes(uid) ? uids.filter((u) => u !== uid) : cleanUids([...uids, uid]);
}

// --- Endereços ---

/** UID válido vindo do endereço (/contas/:uid, ?account=); undefined para qualquer outra coisa. */
export function parseUid(value: string | null | undefined): number | undefined {
  if (!value || !/^\d{1,10}$/.test(value.trim())) return undefined;
  const n = Number(value.trim());
  return n <= 4_294_967_295 ? n : undefined;
}

export function accountHref(uid: number): string {
  return `/contas/${uid}`;
}

export function accountFindingsHref(uid: number, severity?: string): string {
  const p = new URLSearchParams({ account: String(uid) });
  if (severity) p.append("severity", severity);
  return `/achados?${p.toString()}`;
}

export function accountRunsHref(uid: number): string {
  return `/execucoes?${new URLSearchParams({ account: String(uid) }).toString()}`;
}

// --- Atribuição do inventário à conta ---

/** Diretório pessoal que identifica a conta: existe e não é a raiz (mesma regra do servidor). */
function ownHome(a: Pick<Account, "home" | "home_ok">): string | undefined {
  if (!a.home_ok || !a.home.startsWith("/")) return undefined;
  const home = a.home.replace(/\/+$/, "");
  return home === "" ? undefined : home;
}

export function processesOf(a: Pick<Account, "uid">, list: readonly ProcessInfo[]): ProcessInfo[] {
  return list.filter((p) => p.uid === a.uid);
}

/** Item de persistência da conta: dono igual ao nome (ou ao UID) ou caminho dentro do diretório pessoal. */
export function ownsPersistence(a: Pick<Account, "uid" | "name" | "home" | "home_ok">, e: PersistenceEntry): boolean {
  if (e.owner !== undefined && e.owner !== "" && (e.owner === a.name || e.owner === String(a.uid))) return true;
  const home = ownHome(a);
  return home !== undefined && e.path.startsWith(`${home}/`);
}

export function persistenceOf(a: Pick<Account, "uid" | "name" | "home" | "home_ok">, list: readonly PersistenceEntry[]): PersistenceEntry[] {
  return list.filter((e) => e.change !== "removed" && ownsPersistence(a, e));
}

// --- Erros ---

/** O executor fora do ar responde 503: a lista de contas depende dele (getent passwd roda como root). */
export function isExecutorUnavailable(err: unknown): boolean {
  return err instanceof ApiError && err.status === 503;
}

/** Nome para exibição: "loja (1001)". */
export function accountLabel(a: Pick<Account, "name" | "uid">): string {
  return a.name ? `${a.name} (${a.uid})` : String(a.uid);
}

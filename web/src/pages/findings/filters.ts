import type { Schemas } from "../../api/client";
import type { operations } from "../../api/schema";
import { parseUid } from "../accounts/accounts";

// Filtros da lista de achados: a URL é a fonte de verdade, para que links da visão geral
// (/achados?severity=critical, /achados?run_id=...) e o botão Voltar do navegador funcionem.

export type FindingState = Schemas["FindingState"];
export type Severity = Schemas["Severity"];
export type FindingKind = Schemas["FindingKind"];

export const findingStateList: FindingState[] = ["new", "in_review", "confirmed", "resolved", "false_positive", "excepted"];
export const severityList: Severity[] = ["critical", "high", "medium", "low", "info"];
export const kindList: FindingKind[] = ["file", "process", "persistence", "system"];

export type SubjectLabel =
  | { key: "securityUpdates" | "reboot" | "services" | "packageCache" | "unsigned" | "unknownKey" | "aptConf" }
  | { key: "repo"; id: string }
  | { key: "pid"; pid: string }
  | { key: "port"; proto: string; port: string }
  | { key: "raw"; text: string };

const fixedSubjects: Record<string, SubjectLabel> = {
  "security-updates": { key: "securityUpdates" },
  reboot: { key: "reboot" },
  services: { key: "services" },
  "package-cache": { key: "packageCache" },
  "pacotes-sem-assinatura": { key: "unsigned" },
  "pacotes-chave-desconhecida": { key: "unknownKey" },
  "apt-conf": { key: "aptConf" },
};

/** Assunto do achado do sistema ("security-updates", "repo:epel", "tcp/31337") em forma de rótulo. */
export function subjectLabel(subject: string): SubjectLabel {
  const fixed = fixedSubjects[subject];
  if (fixed) return fixed;
  if (subject.startsWith("repo:")) return { key: "repo", id: subject.slice(5) };
  const pid = /^pid:(\d+)$/.exec(subject);
  if (pid?.[1]) return { key: "pid", pid: pid[1] };
  const port = /^(tcp|udp)\/(\d+)$/.exec(subject);
  if (port?.[1] && port[2]) return { key: "port", proto: port[1].toUpperCase(), port: port[2] };
  return { key: "raw", text: subject };
}

/** Estados abertos (mesma lista de store.OpenStates no servidor): o padrão da lista. */
export const openStates: FindingState[] = ["new", "in_review", "confirmed"];

/** Valor de `state` na URL que significa "todos os estados" (sem filtro). */
export const ALL_STATES = "all";

/** Itens por página pedidos ao servidor. */
export const PAGE_SIZE = 50;

export type FindingFilters = {
  /** Lista vazia = todos os estados. */
  states: FindingState[];
  severities: Severity[];
  kinds: FindingKind[];
  categories: string[];
  runId: string;
  q: string;
  /** Só achados da conta (UID), vindo da tela Contas (?account=). */
  account?: number;
};

export type FindingsQuery = NonNullable<operations["listFindings"]["parameters"]["query"]>;

function pick<T extends string>(values: string[], allowed: readonly T[]): T[] {
  const set = new Set(values);
  // Mantém a ordem canônica e descarta valores desconhecidos (URL editada à mão).
  return allowed.filter((v) => set.has(v));
}

function clean(values: string[]): string[] {
  const out: string[] = [];
  for (const v of values) {
    const s = v.trim();
    if (s && !out.includes(s)) out.push(s);
  }
  return out;
}

/** Lê os filtros da URL. Sem `state`, mostra os abertos; `state=all` mostra todos. */
export function parseFilters(params: URLSearchParams): FindingFilters {
  const rawStates = params.getAll("state");
  let states: FindingState[];
  if (rawStates.length === 0) states = [...openStates];
  else if (rawStates.includes(ALL_STATES)) states = [];
  else {
    states = pick(rawStates, findingStateList);
    // Só valores inválidos: volta ao padrão em vez de mostrar tudo sem querer.
    if (states.length === 0) states = [...openStates];
  }
  const account = parseUid(params.get("account"));
  return {
    ...(account !== undefined ? { account } : {}),
    states,
    severities: pick(params.getAll("severity"), severityList),
    kinds: pick(params.getAll("kind"), kindList),
    categories: clean(params.getAll("category")),
    // run_id é o nome usado nos links do painel; run (nome do contrato) também é aceito.
    runId: (params.get("run_id") ?? params.get("run") ?? "").trim(),
    q: (params.get("q") ?? "").trim(),
  };
}

function sameSet<T>(a: T[], b: T[]): boolean {
  return a.length === b.length && a.every((v) => b.includes(v));
}

/** Escreve os filtros na URL omitindo o padrão (abertos), para os endereços ficarem curtos. */
export function filtersToParams(f: FindingFilters): URLSearchParams {
  const p = new URLSearchParams();
  if (f.states.length === 0) p.append("state", ALL_STATES);
  else if (!sameSet(f.states, openStates)) for (const s of f.states) p.append("state", s);
  for (const s of f.severities) p.append("severity", s);
  for (const k of f.kinds) p.append("kind", k);
  for (const c of f.categories) p.append("category", c);
  if (f.runId) p.set("run_id", f.runId);
  if (f.q) p.set("q", f.q);
  if (f.account !== undefined) p.set("account", String(f.account));
  return p;
}

/** Monta a consulta de GET /api/v1/findings (nomes do contrato: run, before, limit). */
export function filtersToQuery(f: FindingFilters, before?: number): FindingsQuery {
  const q: FindingsQuery = { limit: PAGE_SIZE };
  if (f.states.length > 0) q.state = f.states;
  if (f.severities.length > 0) q.severity = f.severities;
  if (f.kinds.length > 0) q.kind = f.kinds;
  if (f.categories.length > 0) q.category = f.categories;
  if (f.runId) q.run = f.runId;
  if (f.q) q.q = f.q.slice(0, 512);
  if (f.account !== undefined) q.account = f.account;
  if (before !== undefined) q.before = before;
  return q;
}

/** Os mesmos filtros sem a conta (remover o "chip" de conta). */
export function withoutAccount(f: FindingFilters): FindingFilters {
  const out: FindingFilters = { ...f };
  delete out.account;
  return out;
}

/** Indica se algo difere do padrão (para oferecer "Limpar filtros"). */
export function hasActiveFilters(f: FindingFilters): boolean {
  return filtersToParams(f).size > 0;
}

/** Alterna um valor numa lista mantendo a ordem canônica. */
export function toggleValue<T extends string>(list: T[], value: T, order: readonly T[]): T[] {
  const set = new Set(list);
  if (set.has(value)) set.delete(value);
  else set.add(value);
  return order.filter((v) => set.has(v));
}

/** Separa a categoria digitada (vírgulas) em valores. */
export function splitCategories(text: string): string[] {
  return clean(text.split(","));
}

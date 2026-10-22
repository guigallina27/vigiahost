import type { Schemas } from "../../api/client";

// Regras de formulário e de exibição da tela Notificações (E1.12). Funções puras, cobertas pelos testes.

export type Channel = Schemas["NotificationChannel"];
export type ChannelInput = Schemas["NotificationChannelInput"];
export type ChannelKind = Schemas["NotificationChannelKind"];
export type SmtpSecurity = Schemas["SmtpSecurity"];
export type Rule = Schemas["NotificationRule"];
export type RuleInput = Schemas["NotificationRuleInput"];
export type NotificationEvent = Schemas["NotificationEvent"];
export type OutboxEntry = Schemas["OutboxEntry"];
export type OutboxState = Schemas["OutboxState"];
export type Severity = Schemas["Severity"];

/** Eventos na ordem em que a tela mostra (mesma do servidor). */
export const notificationEvents: NotificationEvent[] = [
  "finding_new",
  "run_failed",
  "run_partial",
  "engine_selftest_failed",
  "executor_unavailable",
  "backup_failed",
];

export const smtpSecurities: SmtpSecurity[] = ["starttls", "tls", "none"];
export const outboxStates: OutboxState[] = ["pending", "sent", "failed"];

/** Porta usual de cada modo de segurança do SMTP. */
export function defaultPort(security: SmtpSecurity): number {
  return security === "tls" ? 465 : security === "none" ? 25 : 587;
}

/** Janela de deduplicação sugerida por evento (a mesma do servidor quando o campo fica vazio). */
export function defaultDedupMinutes(event: NotificationEvent): number {
  if (event === "finding_new") return 1440;
  if (event === "engine_selftest_failed" || event === "backup_failed") return 360;
  return 60;
}

export type ChannelFormValues = {
  name: string;
  kind: ChannelKind;
  enabled: boolean;
  includeDetails: boolean;
  host: string;
  port: string;
  security: SmtpSecurity;
  username: string;
  from: string;
  to: string;
  url: string;
  allowPrivate: boolean;
  /** Senha SMTP ou segredo do webhook; vazio mantém o que está guardado. */
  secret: string;
};

export function emptyChannelValues(kind: ChannelKind = "email"): ChannelFormValues {
  return {
    name: "",
    kind,
    enabled: true,
    includeDetails: true,
    host: "",
    port: "",
    security: "starttls",
    username: "",
    from: "",
    to: "",
    url: "",
    allowPrivate: false,
    secret: "",
  };
}

export function valuesFromChannel(c: Channel): ChannelFormValues {
  const v = emptyChannelValues(c.kind);
  v.name = c.name;
  v.enabled = c.enabled;
  v.includeDetails = c.include_details;
  if (c.email) {
    v.host = c.email.host;
    v.port = String(c.email.port);
    v.security = c.email.security;
    v.username = c.email.username ?? "";
    v.from = c.email.from;
    v.to = c.email.to.join("\n");
  }
  if (c.webhook) {
    v.url = c.webhook.url;
    v.allowPrivate = c.webhook.allow_private_network;
  }
  return v;
}

/** Destinatários: um por linha, ou separados por vírgula ou ponto e vírgula. */
export function splitRecipients(text: string): string[] {
  return text
    .split(/[\n,;]+/)
    .map((s) => s.trim())
    .filter((s) => s !== "");
}

export type ChannelField = "name" | "host" | "port" | "from" | "to" | "url" | "secret";
export type ChannelError =
  | "nameRequired"
  | "hostInvalid"
  | "portInvalid"
  | "fromInvalid"
  | "toRequired"
  | "toTooMany"
  | "toInvalid"
  | "urlInvalid"
  | "passwordRequired"
  | "secretRequired"
  | "secretShort"
  | "plainRemote";

type Built = { ok: true; body: ChannelInput } | { ok: false; field: ChannelField; error: ChannelError };

const looksLikeEmail = (s: string) => /^[^\s@<>]+@[^\s@<>]+$/.test(s.replace(/^.*<([^>]*)>\s*$/, "$1").trim());

/** Tamanho em bytes da chave do webhook: "whsec_<base64>" conta os bytes decodificados. */
export function webhookKeyBytes(secret: string): number {
  const s = secret.trim();
  if (s.startsWith("whsec_")) {
    try {
      return atob(s.slice(6)).length;
    } catch {
      return 0;
    }
  }
  return new TextEncoder().encode(s).length;
}

/** Valida como o servidor e monta o corpo. Segredo vazio fica de fora (mantém o atual). */
export function buildChannelBody(v: ChannelFormValues, editing?: Channel): Built {
  const name = v.name.trim();
  if (name === "" || [...name].length > 64) return { ok: false, field: "name", error: "nameRequired" };
  const body: ChannelInput = { name, kind: v.kind, enabled: v.enabled, include_details: v.includeDetails };
  const hasStoredSecret = !!editing?.secret_configured;
  if (v.kind === "email") {
    const host = v.host.trim();
    if (host === "" || /[\s/@?#]/.test(host) || host.includes("://")) return { ok: false, field: "host", error: "hostInvalid" };
    const port = v.port.trim() === "" ? defaultPort(v.security) : Number(v.port);
    if (!Number.isInteger(port) || port < 1 || port > 65535) return { ok: false, field: "port", error: "portInvalid" };
    const local = host === "localhost" || host === "::1" || host.startsWith("127.");
    if (v.security === "none" && !local) return { ok: false, field: "host", error: "plainRemote" };
    const from = v.from.trim();
    if (!looksLikeEmail(from)) return { ok: false, field: "from", error: "fromInvalid" };
    const to = splitRecipients(v.to);
    if (to.length === 0) return { ok: false, field: "to", error: "toRequired" };
    if (to.length > 20) return { ok: false, field: "to", error: "toTooMany" };
    if (!to.every(looksLikeEmail)) return { ok: false, field: "to", error: "toInvalid" };
    const username = v.username.trim();
    if (username !== "" && v.secret === "" && !hasStoredSecret) return { ok: false, field: "secret", error: "passwordRequired" };
    body.email = { host, port, security: v.security, from, to, ...(username ? { username } : {}) };
    if (username !== "" && v.secret !== "") body.secret = v.secret;
  } else {
    const url = v.url.trim();
    let parsed: URL | null;
    try {
      parsed = new URL(url);
    } catch {
      parsed = null;
    }
    if (!parsed || (parsed.protocol !== "http:" && parsed.protocol !== "https:") || parsed.username || parsed.password) {
      return { ok: false, field: "url", error: "urlInvalid" };
    }
    if (v.secret.trim() === "" && !hasStoredSecret) return { ok: false, field: "secret", error: "secretRequired" };
    if (v.secret.trim() !== "" && webhookKeyBytes(v.secret) < 24) return { ok: false, field: "secret", error: "secretShort" };
    body.webhook = { url, allow_private_network: v.allowPrivate };
    if (v.secret.trim() !== "") body.secret = v.secret.trim();
  }
  return { ok: true, body };
}

/** Segredo novo no formato do Standard Webhooks, gerado no navegador (o servidor nunca o devolve). */
export function generateWebhookSecret(): string {
  const bytes = new Uint8Array(32);
  crypto.getRandomValues(bytes);
  return "whsec_" + btoa(String.fromCharCode(...bytes));
}

/** Resumo do destino para os cartões e a confirmação. */
export function channelDestination(c: Pick<Channel, "kind" | "email" | "webhook">): string {
  if (c.kind === "email" && c.email) {
    return `${c.email.host}:${c.email.port} → ${c.email.to.join(", ")}`;
  }
  return c.webhook?.url ?? "";
}

export type RuleFormValues = {
  channelId: string;
  event: NotificationEvent;
  minSeverity: Severity;
  dedupMinutes: string;
  enabled: boolean;
};

export function emptyRuleValues(channelId?: number): RuleFormValues {
  return {
    channelId: channelId !== undefined ? String(channelId) : "",
    event: "finding_new",
    minSeverity: "high",
    dedupMinutes: "",
    enabled: true,
  };
}

export function valuesFromRule(r: Rule): RuleFormValues {
  return {
    channelId: String(r.channel_id),
    event: r.event,
    minSeverity: r.min_severity,
    dedupMinutes: String(r.dedup_minutes),
    enabled: r.enabled,
  };
}

export type RuleError = "channelRequired" | "dedupInvalid";

export function buildRuleBody(v: RuleFormValues): { ok: true; body: RuleInput } | { ok: false; error: RuleError } {
  const channel = Number(v.channelId);
  if (!Number.isInteger(channel) || channel <= 0) return { ok: false, error: "channelRequired" };
  const body: RuleInput = { channel_id: channel, event: v.event, min_severity: v.minSeverity, enabled: v.enabled };
  if (v.dedupMinutes.trim() !== "") {
    const n = Number(v.dedupMinutes);
    if (!Number.isInteger(n) || n < 0 || n > 10080) return { ok: false, error: "dedupInvalid" };
    body.dedup_minutes = n;
  }
  return { ok: true, body };
}

/** Eventos ainda sem regra no canal (cada canal tem no máximo uma regra por evento). */
export function freeEvents(rules: readonly Rule[], channelId: number, keep?: NotificationEvent): NotificationEvent[] {
  const used = new Set(rules.filter((r) => r.channel_id === channelId).map((r) => r.event));
  return notificationEvents.filter((e) => !used.has(e) || e === keep);
}

const severityOrder: Severity[] = ["critical", "high", "medium", "low", "info"];

/** Maior severidade presente na contagem da mensagem. */
export function highestSeverity(counts: Record<string, number>): Severity {
  return severityOrder.find((s) => (counts[s] ?? 0) > 0) ?? "info";
}

/**
 * Partes do resumo da mensagem no idioma da tela (o campo summary da API vem no idioma do servidor): achados viram
 * "N achados novos" com a maior severidade; os outros eventos usam o nome do evento.
 */
export function outboxSummaryParts(
  e: Pick<OutboxEntry, "event" | "item_count" | "severity_counts" | "items">,
):
  | { key: "test" }
  | { key: "findingOne"; severity: Severity }
  | { key: "findingMany"; count: number; severity: Severity }
  | { key: "event"; event: NotificationEvent; count: number } {
  if (e.event === "test") return { key: "test" };
  if (e.event === "finding_new") {
    if (e.item_count <= 1) return { key: "findingOne", severity: e.items[0]?.severity ?? highestSeverity(e.severity_counts) };
    return { key: "findingMany", count: e.item_count, severity: highestSeverity(e.severity_counts) };
  }
  return { key: "event", event: e.event, count: e.item_count };
}

/** Minutos em texto curto: "45 min", "6 h", "1 dia". */
export function minutesParts(min: number): { unit: "minutes" | "hours" | "days"; count: number } {
  if (min > 0 && min % 1440 === 0) return { unit: "days", count: min / 1440 };
  if (min > 0 && min % 60 === 0) return { unit: "hours", count: min / 60 };
  return { unit: "minutes", count: min };
}

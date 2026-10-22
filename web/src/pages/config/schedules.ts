import type { Schemas } from "../../api/client";

// Lógica pura dos agendamentos: expressão cron em linguagem simples e montagem do corpo da requisição.

export type Schedule = Schemas["Schedule"];
export type ScheduleInput = Schemas["ScheduleInput"];
export type RunKind = Schemas["RunKind"];
export type MissedPolicy = Schemas["MissedPolicy"];

export type ScheduleFormValues = {
  name: string;
  kind: RunKind;
  cron: string;
  timezone: string;
  profile: string;
  missedPolicy: MissedPolicy;
  enabled: boolean;
  incremental: boolean;
  /** Um caminho por linha. */
  paths: string;
  exclude: string;
};

/** Fuso do navegador, ponto de partida razoável para quem cria o agendamento. */
export function browserTimeZone(): string {
  try {
    return Intl.DateTimeFormat().resolvedOptions().timeZone || "UTC";
  } catch {
    return "UTC";
  }
}

export function emptyScheduleValues(timezone = browserTimeZone()): ScheduleFormValues {
  return {
    name: "",
    kind: "files",
    cron: "0 3 * * *",
    timezone,
    profile: "padrao",
    missedPolicy: "run_once",
    enabled: true,
    incremental: true,
    paths: "",
    exclude: "",
  };
}

export function valuesFromSchedule(s: Schedule): ScheduleFormValues {
  return {
    name: s.name,
    kind: s.kind,
    cron: s.cron,
    timezone: s.timezone,
    profile: s.profile,
    missedPolicy: s.missed_policy,
    enabled: s.enabled,
    incremental: s.incremental,
    paths: s.paths.join("\n"),
    exclude: s.exclude.join("\n"),
  };
}

/** Uma entrada por linha, sem linhas vazias nem espaços nas pontas. */
export function splitLines(text: string): string[] {
  return text
    .split(/\r?\n/)
    .map((l) => l.trim())
    .filter(Boolean);
}

/**
 * Corpo de POST/PUT /api/v1/schedules. A inspeção de processos não usa caminhos (o servidor os descarta),
 * então eles nem são enviados.
 */
export function buildScheduleInput(v: ScheduleFormValues): ScheduleInput {
  const base: ScheduleInput = {
    name: v.name.trim(),
    kind: v.kind,
    cron: v.cron.trim(),
    timezone: v.timezone.trim() || "UTC",
    profile: v.profile.trim() || "padrao",
    missed_policy: v.missedPolicy,
    enabled: v.enabled,
    // O tipo gerado exige o campo (tem padrão no contrato); na inspeção de processos ele não tem efeito.
    incremental: v.kind === "files" ? v.incremental : true,
  };
  if (v.kind === "processes") return base;
  return { ...base, paths: splitLines(v.paths), exclude: splitLines(v.exclude) };
}

// ---- Expressão cron em linguagem simples ----

export type CronDescription =
  | { key: "everyMinutes"; n: number }
  | { key: "hourlyAt"; minute: number }
  | { key: "everyHours"; n: number; minute: number }
  | { key: "dailyAt"; hour: number; minute: number }
  | { key: "weeklyAt"; days: number[]; hour: number; minute: number }
  | { key: "monthlyAt"; day: number; hour: number; minute: number }
  | { key: "yearlyAt"; month: number; day: number; hour: number; minute: number }
  | { key: "every"; duration: string };

const DESCRIPTORS: Record<string, string> = {
  "@hourly": "0 * * * *",
  "@daily": "0 0 * * *",
  "@midnight": "0 0 * * *",
  "@weekly": "0 0 * * 0",
  "@monthly": "0 0 1 * *",
  "@yearly": "0 0 1 1 *",
  "@annually": "0 0 1 1 *",
};

const DOW_NAMES = ["sun", "mon", "tue", "wed", "thu", "fri", "sat"];

function int(field: string, min: number, max: number): number | null {
  if (!/^\d+$/.test(field)) return null;
  const n = Number(field);
  return n >= min && n <= max ? n : null;
}

function step(field: string, min: number, max: number): number | null {
  const m = /^\*\/(\d+)$/.exec(field);
  return m ? int(m[1] ?? "", min, max) : null;
}

function dowValue(token: string): number | null {
  const name = DOW_NAMES.indexOf(token.toLowerCase());
  if (name !== -1) return name;
  const n = int(token, 0, 7);
  return n === null ? null : n % 7;
}

/** Dias da semana: lista e intervalos ("1-5", "MON,WED,FRI"); devolve null para formas mais complexas. */
function parseDow(field: string): number[] | null {
  const days = new Set<number>();
  for (const part of field.split(",")) {
    const [a, b, ...rest] = part.split("-");
    if (rest.length > 0 || a === undefined) return null;
    const start = dowValue(a);
    if (start === null) return null;
    if (b === undefined) {
      days.add(start);
      continue;
    }
    const end = dowValue(b);
    if (end === null) return null;
    // "5-7" (sexta a domingo): 7 vale 0, mas o intervalo vai até o fim da semana.
    const last = b === "7" ? 7 : end;
    if (last < start) return null;
    for (let d = start; d <= last; d++) days.add(d % 7);
  }
  return [...days].sort((x, y) => x - y);
}

/**
 * Traduz as formas comuns da expressão (5 campos ou @daily, @weekly…) para uma descrição estruturada.
 * Devolve null quando a forma não é coberta: a tela mostra então só as próximas execuções calculadas pelo servidor.
 */
export function describeCron(expr: string): CronDescription | null {
  let text = expr.trim().replace(/\s+/g, " ");
  if (!text) return null;
  const every = /^@every (.+)$/i.exec(text);
  if (every) return { key: "every", duration: every[1] ?? "" };
  if (text.startsWith("@")) {
    const mapped = DESCRIPTORS[text.toLowerCase()];
    if (!mapped) return null;
    text = mapped;
  }
  const fields = text.split(" ");
  if (fields.length !== 5) return null;
  const [min = "", hour = "", dom = "", month = "", dow = ""] = fields;

  const minuteStep = step(min, 1, 59);
  if (minuteStep !== null && hour === "*" && dom === "*" && month === "*" && dow === "*") {
    return { key: "everyMinutes", n: minuteStep };
  }
  const minute = int(min, 0, 59);
  if (minute === null) return null;

  if (dom === "*" && month === "*" && dow === "*") {
    if (hour === "*") return { key: "hourlyAt", minute };
    const hourStep = step(hour, 1, 23);
    if (hourStep !== null) return { key: "everyHours", n: hourStep, minute };
  }
  const h = int(hour, 0, 23);
  if (h === null) return null;

  if (dom === "*" && month === "*") {
    if (dow === "*") return { key: "dailyAt", hour: h, minute };
    const days = parseDow(dow);
    if (!days || days.length === 0) return null;
    if (days.length === 7) return { key: "dailyAt", hour: h, minute };
    return { key: "weeklyAt", days, hour: h, minute };
  }
  const day = int(dom, 1, 31);
  if (day === null || dow !== "*") return null;
  if (month === "*") return { key: "monthlyAt", day, hour: h, minute };
  const m = int(month, 1, 12);
  if (m === null) return null;
  return { key: "yearlyAt", month: m, day, hour: h, minute };
}

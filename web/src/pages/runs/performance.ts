import type { Schemas } from "../../api/client";

// Regras puras do ajuste em tempo real e das métricas de desempenho (testáveis sem React).

export type RunAdjustRequest = Schemas["RunAdjustRequest"];
export type RunMetrics = Schemas["RunMetrics"];

const MIB = 1 << 20;

export type AdjustValues = { cpuPercent: string; memoryMiB: string; ioReadMiBps: string; ioWeight: string };
export type AdjustField = keyof AdjustValues;

/** Valores do formulário a partir do perfil efetivo da execução (memória e banda em MiB). */
export function adjustValuesFrom(p: Schemas["ResourceProfile"]): AdjustValues {
  return {
    cpuPercent: String(p.cpu_quota_percent),
    memoryMiB: String(Math.round(p.memory_max_bytes / MIB)),
    ioReadMiBps: String(Math.round(p.io_read_bytes_per_sec / MIB)),
    ioWeight: String(p.io_weight),
  };
}

function whole(text: string): number | null {
  const t = text.trim();
  if (!/^\d+$/.test(t)) return null;
  return Number(t);
}

export type AdjustBuild =
  | { ok: true; body: RunAdjustRequest; changes: AdjustField[] }
  | { ok: false; field: AdjustField; code: "notNumber" }
  | { ok: false; code: "nothing" };

/**
 * Corpo de POST /runs/{id}/adjust só com o que mudou em relação ao perfil efetivo. As travas (reserva de CPU e
 * memória, faixas) são do executor, que recusa com a mensagem explicando o motivo.
 */
export function buildAdjustBody(values: AdjustValues, current: Schemas["ResourceProfile"], noReserve = false): AdjustBuild {
  const fields: AdjustField[] = ["cpuPercent", "memoryMiB", "ioReadMiBps", "ioWeight"];
  const n = {} as Record<AdjustField, number>;
  for (const f of fields) {
    const v = whole(values[f]);
    if (v === null) return { ok: false, field: f, code: "notNumber" };
    n[f] = v;
  }
  const body: RunAdjustRequest = {};
  const changes: AdjustField[] = [];
  if (n.cpuPercent !== current.cpu_quota_percent) {
    body.cpu_quota_percent = n.cpuPercent;
    changes.push("cpuPercent");
  }
  if (n.memoryMiB !== Math.round(current.memory_max_bytes / MIB)) {
    body.memory_max_bytes = n.memoryMiB * MIB;
    changes.push("memoryMiB");
  }
  if (n.ioReadMiBps !== Math.round(current.io_read_bytes_per_sec / MIB)) {
    body.io_read_bytes_per_sec = n.ioReadMiBps * MIB;
    changes.push("ioReadMiBps");
  }
  if (n.ioWeight !== current.io_weight) {
    body.io_weight = n.ioWeight;
    changes.push("ioWeight");
  }
  if (changes.length === 0) return { ok: false, code: "nothing" };
  if (noReserve) body.no_reserve = true;
  return { ok: true, body, changes };
}

/** Parcela de cada etapa no total (0 a 1), para a tabela de duração por etapa. */
export function phaseShares(phases: Schemas["PhaseTiming"][]): { phase: string; seconds: number; share: number }[] {
  const total = phases.reduce((sum, p) => sum + Math.max(0, p.seconds), 0);
  return phases.map((p) => ({ phase: p.phase, seconds: p.seconds, share: total > 0 ? Math.max(0, p.seconds) / total : 0 }));
}

/** Situação da limitação por pressão no resumo, para escolher a mensagem quando não houve eventos. */
export function throttleOutcome(m: RunMetrics): "off" | "unavailable" | "none" | "limited" {
  if (!m.throttle.enabled) return "off";
  if (!m.throttle.available) return "unavailable";
  return m.throttle.events.length > 0 || m.throttle.limited_seconds > 0 ? "limited" : "none";
}

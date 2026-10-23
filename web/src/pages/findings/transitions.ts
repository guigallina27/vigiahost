import type { Schemas } from "../../api/client";

type FindingState = Schemas["FindingState"];

/** Estados que pedem nota ao operador: decisões de encerramento precisam de justificativa no histórico. */
export const noteRequiredStates: readonly FindingState[] = ["false_positive", "resolved"];

export function noteRequired(to: FindingState | null): boolean {
  return to !== null && noteRequiredStates.includes(to);
}

/**
 * Destinos manuais oferecidos. O servidor já devolve allowed_transitions conforme o estado e o perfil;
 * "excepted" sai porque o servidor só aceita cobrir por exceção criando a exceção (com motivo e validade).
 */
export function manualTargets(allowed: FindingState[]): FindingState[] {
  return allowed.filter((s) => s !== "excepted");
}

export type TransitionCheck = { ok: true; body: Schemas["FindingTransition"] } | { ok: false; error: "chooseState" | "noteMissing" };

/** Valida e monta o corpo de POST /findings/{id}/transition. */
export function buildTransition(to: FindingState | null, note: string): TransitionCheck {
  if (!to) return { ok: false, error: "chooseState" };
  const text = note.trim().slice(0, 2000);
  if (noteRequired(to) && !text) return { ok: false, error: "noteMissing" };
  return { ok: true, body: text ? { to, note: text } : { to } };
}

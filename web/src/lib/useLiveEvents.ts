import { useQueryClient } from "@tanstack/react-query";
import { useEffect, useState } from "react";

export type LiveState = "connecting" | "live" | "offline";

// Cada evento traz só tipo e identificador: a interface invalida as consultas e busca o estado pela API.
const invalidates: Record<string, (id: string) => unknown[][]> = {
  // Contas: a última verificação, os achados e o inventário de cada conta vêm das execuções.
  run: (id) => [["runs"], ["run", id], ["overview"], ["findings"], ["inventory"], ["accounts"], ["account"]],
  // Exceções criadas ou removidas também chegam como "finding" (mudam o estado dos achados que cobrem).
  finding: (id) => [["findings"], ["finding", id], ["overview"], ["exceptions"], ["accounts"], ["account"]],
  schedule: () => [["schedules"]],
};

/** Assina /api/v1/events (SSE) enquanto o painel está aberto; o navegador reconecta sozinho se cair. */
export function useLiveEvents(): LiveState {
  const qc = useQueryClient();
  const [state, setState] = useState<LiveState>("connecting");
  useEffect(() => {
    if (typeof EventSource === "undefined") return;
    const es = new EventSource("/api/v1/events");
    const handlers = Object.entries(invalidates).map(([type, keys]) => {
      const fn = (e: MessageEvent<string>) => {
        let id = "";
        try {
          id = (JSON.parse(e.data) as { id?: string }).id ?? "";
        } catch {
          /* corpo inesperado: invalida tudo do tipo */
        }
        for (const queryKey of keys(id)) void qc.invalidateQueries({ queryKey: queryKey.filter((k) => k !== "") });
      };
      es.addEventListener(type, fn);
      return [type, fn] as const;
    });
    es.onopen = () => setState("live");
    es.onerror = () => {
      setState(es.readyState === EventSource.CLOSED ? "offline" : "connecting");
      // Sessão vencida derruba o fluxo: confere a sessão para voltar ao login se for o caso.
      void qc.invalidateQueries({ queryKey: ["session"] });
    };
    return () => {
      for (const [type, fn] of handlers) es.removeEventListener(type, fn);
      es.close();
    };
  }, [qc]);
  return state;
}

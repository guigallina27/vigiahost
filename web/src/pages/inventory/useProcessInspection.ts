import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useEffect, useRef } from "react";
import { api, unwrap, type Schemas } from "../../api/client";

type RunStatus = Schemas["RunStatus"];

const ACTIVE: readonly RunStatus[] = ["queued", "reserved", "running"];

export function isActiveRun(status: RunStatus | undefined): boolean {
  return status !== undefined && ACTIVE.includes(status);
}

/** Corpo do pedido de inspeção de processos: tipo "processes" com o perfil de recursos padrão. */
export function inspectionRequest(): Schemas["RunCreate"] {
  return { kind: "processes", profile: "padrao", incremental: true };
}

/**
 * Acompanha a inspeção de processos mais recente (a chave ["runs", …] é invalidada pelos eventos ao vivo) e
 * recarrega o inventário quando ela termina; também enfileira uma nova inspeção sob demanda.
 */
export function useProcessInspection() {
  const qc = useQueryClient();
  const filter = { kind: "processes" as const, limit: 1 };

  const latest = useQuery({
    queryKey: ["runs", filter],
    queryFn: ({ signal }) => unwrap(api.GET("/api/v1/runs", { params: { query: filter }, signal })),
    // Sem os eventos ao vivo, ainda assim percebe o fim de uma inspeção em andamento.
    refetchInterval: (q) => (isActiveRun(q.state.data?.runs[0]?.status) ? 10_000 : false),
  });
  const run = latest.data?.runs[0];

  // Quando a inspeção mais recente muda de estado e não está mais ativa, o instantâneo novo já existe.
  const seen = useRef<string | null>(null);
  const key = run ? `${run.id}:${run.status}` : "";
  useEffect(() => {
    if (!key) return;
    const first = seen.current === null;
    const changed = seen.current !== key;
    seen.current = key;
    if (!first && changed && !isActiveRun(run?.status)) {
      void qc.invalidateQueries({ queryKey: ["inventory"] });
    }
  }, [key, run?.status, qc]);

  // A chave de idempotência evita duas inspeções por clique duplo; muda a cada pedido concluído.
  const idempotency = useRef<string>(newKey());
  const inspect = useMutation({
    mutationFn: () =>
      unwrap(
        api.POST("/api/v1/runs", {
          params: { header: { "Idempotency-Key": idempotency.current } },
          body: inspectionRequest(),
        }),
      ),
    onSuccess: () => {
      idempotency.current = newKey();
      void qc.invalidateQueries({ queryKey: ["runs"] });
      void qc.invalidateQueries({ queryKey: ["overview"] });
    },
  });

  return { run, active: isActiveRun(run?.status), inspect };
}

function newKey(): string {
  return globalThis.crypto?.randomUUID?.() ?? `${Date.now()}-${Math.random().toString(36).slice(2)}`;
}

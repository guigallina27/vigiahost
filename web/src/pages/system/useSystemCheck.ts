import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useEffect, useRef } from "react";
import { api, ApiError, unwrap } from "../../api/client";
import { isActiveRun } from "../inventory/useProcessInspection";
import type { SystemKind } from "./systemFormat";

// Erro 4xx (sem relatório, sem permissão) não melhora com nova tentativa.
const retry = (count: number, err: Error) => !(err instanceof ApiError && err.status !== undefined && err.status < 500) && count < 2;

/** Relatório guardado da verificação de integridade (o mais recente sem execução informada). */
export function useIntegrityReport(runId: string | undefined) {
  return useQuery({
    queryKey: ["system", "integrity", runId ?? "latest"],
    queryFn: ({ signal }) => unwrap(api.GET("/api/v1/integrity", { params: { query: runId ? { run_id: runId } : {} }, signal })),
    retry,
  });
}

/** Relatório guardado da verificação de atualizações. */
export function useUpdatesReport(runId: string | undefined) {
  return useQuery({
    queryKey: ["system", "updates", runId ?? "latest"],
    queryFn: ({ signal }) => unwrap(api.GET("/api/v1/updates", { params: { query: runId ? { run_id: runId } : {} }, signal })),
    retry,
  });
}

/**
 * Acompanha a verificação mais recente do tipo (a chave ["runs", …] é invalidada pelos eventos ao vivo), recarrega
 * o relatório quando ela termina e enfileira uma nova sob demanda.
 */
export function useSystemCheck(kind: SystemKind) {
  const qc = useQueryClient();
  const filter = { kind, limit: 1 };
  const latest = useQuery({
    queryKey: ["runs", filter],
    queryFn: ({ signal }) => unwrap(api.GET("/api/v1/runs", { params: { query: filter }, signal })),
    refetchInterval: (q) => (isActiveRun(q.state.data?.runs[0]?.status) ? 10_000 : false),
  });
  const run = latest.data?.runs[0];

  const seen = useRef<string | null>(null);
  const key = run ? `${run.id}:${run.status}` : "";
  useEffect(() => {
    if (!key) return;
    const first = seen.current === null;
    const changed = seen.current !== key;
    seen.current = key;
    if (!first && changed && !isActiveRun(run?.status)) {
      void qc.invalidateQueries({ queryKey: ["system", kind] });
    }
  }, [key, run?.status, qc, kind]);

  // A chave de idempotência evita duas verificações por clique duplo; muda a cada pedido concluído.
  const idempotency = useRef<string>(newKey());
  const check = useMutation({
    mutationFn: () =>
      unwrap(
        api.POST("/api/v1/runs", {
          params: { header: { "Idempotency-Key": idempotency.current } },
          body: { kind, profile: "padrao", incremental: false },
        }),
      ),
    onSuccess: () => {
      idempotency.current = newKey();
      void qc.invalidateQueries({ queryKey: ["runs"] });
      void qc.invalidateQueries({ queryKey: ["overview"] });
    },
  });

  return { run, active: isActiveRun(run?.status), check };
}

function newKey(): string {
  return globalThis.crypto?.randomUUID?.() ?? `${Date.now()}-${Math.random().toString(36).slice(2)}`;
}

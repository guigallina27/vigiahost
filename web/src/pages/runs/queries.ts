import { queryOptions } from "@tanstack/react-query";
import { api, unwrap } from "../../api/client";
import { isActive } from "./runFormat";

// Chaves iguais às que os eventos ao vivo (SSE) invalidam: ["run", id] e ["overview"].

export function runQuery(runId: string) {
  return queryOptions({
    queryKey: ["run", runId],
    queryFn: ({ signal }) => unwrap(api.GET("/api/v1/runs/{runId}", { params: { path: { runId } }, signal })),
    // Rede de segurança caso o fluxo ao vivo caia: enquanto a execução anda, confere a cada 15 s.
    refetchInterval: (q) => (q.state.data && isActive(q.state.data.run.status) ? 15_000 : false),
  });
}

/**
 * Comparativo com as últimas execuções do mesmo tipo. Fora da chave ["run", id] de propósito: o progresso ao vivo
 * não precisa refazer o comparativo; o estado na chave faz a consulta voltar quando a execução termina.
 */
export function comparisonQuery(runId: string, status: string) {
  return queryOptions({
    queryKey: ["run-comparison", runId, status],
    queryFn: ({ signal }) =>
      unwrap(api.GET("/api/v1/runs/{runId}/comparison", { params: { path: { runId }, query: { limit: 10 } }, signal })),
    staleTime: 60_000,
  });
}

export const overviewQuery = queryOptions({
  queryKey: ["overview"],
  queryFn: ({ signal }) => unwrap(api.GET("/api/v1/overview", { signal })),
  refetchInterval: 60_000,
});

export const resourcesQuery = queryOptions({
  queryKey: ["resources"],
  queryFn: ({ signal }) => unwrap(api.GET("/api/v1/resources", { signal })),
  staleTime: 60_000,
});

export const enginesQuery = queryOptions({
  queryKey: ["engines"],
  queryFn: ({ signal }) => unwrap(api.GET("/api/v1/engines", { signal })),
  refetchInterval: 60_000,
});

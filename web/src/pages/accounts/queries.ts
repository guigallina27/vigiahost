import { queryOptions, useMutation, useQueryClient } from "@tanstack/react-query";
import { useNavigate } from "react-router";
import { api, ApiError, unwrap } from "../../api/client";
import { newIdempotencyKey } from "../runs/runFormat";
import { buildAccountsRun, type ScanTarget } from "./accounts";

// Chaves iguais às que os eventos ao vivo (SSE) invalidam: ["accounts"] e ["account"].

/** Não insiste em respostas do pedido (4xx) nem no executor fora do ar (503): a tela orienta a pessoa. */
function retry(count: number, err: Error): boolean {
  if (err instanceof ApiError && err.status !== undefined && (err.status < 500 || err.status === 503)) return false;
  return count < 2;
}

export function accountsQuery(system: boolean) {
  return queryOptions({
    queryKey: ["accounts", { system }],
    queryFn: ({ signal }) => unwrap(api.GET("/api/v1/accounts", { params: { query: system ? { system: true } : {} }, signal })),
    retry,
    staleTime: 30_000,
  });
}

export function accountQuery(uid: number) {
  return queryOptions({
    queryKey: ["account", uid],
    queryFn: ({ signal }) => unwrap(api.GET("/api/v1/accounts/{uid}", { params: { path: { uid } }, signal })),
    retry,
  });
}

/**
 * Pedido de verificação de contas: mesma chave de idempotência enquanto o diálogo está aberto (clique duplo ou nova
 * tentativa devolvem a mesma execução) e, ao criar, abre o detalhe da execução.
 */
export function useAccountScan() {
  const qc = useQueryClient();
  const navigate = useNavigate();
  const mutation = useMutation({
    mutationFn: ({ target, key }: { target: ScanTarget; key: string | undefined }) =>
      unwrap(
        api.POST("/api/v1/runs", {
          body: buildAccountsRun(target),
          ...(key ? { params: { header: { "Idempotency-Key": key } } } : {}),
        }),
      ),
    onSuccess: (run) => {
      void qc.invalidateQueries({ queryKey: ["runs"] });
      void qc.invalidateQueries({ queryKey: ["overview"] });
      void qc.invalidateQueries({ queryKey: ["accounts"] });
      void qc.invalidateQueries({ queryKey: ["account"] });
      void navigate(`/execucoes/${encodeURIComponent(run.id)}`);
    },
  });
  return { mutation, newKey: newIdempotencyKey };
}

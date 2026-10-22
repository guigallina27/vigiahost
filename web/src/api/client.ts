import { queryOptions } from "@tanstack/react-query";
import createClient from "openapi-fetch";
import type { components, paths } from "./schema";

// Cliente tipado a partir do mesmo contrato do servidor (api/openapi.yaml): se o contrato muda, o TypeScript acusa.
// A origem explícita resolve os caminhos relativos também fora do navegador (testes), e o fetch é lido
// a cada chamada para poder ser substituído nos testes.
export const api = createClient<paths>({
  baseUrl: globalThis.location?.origin ?? "",
  fetch: (request) => globalThis.fetch(request),
});

export type Health = components["schemas"]["Health"];

/** Falha de transporte (sem resposta ou resposta fora do contrato), com a causa para a tela de erro. */
export class ApiError extends Error {
  readonly status: number | undefined;
  constructor(message: string, status?: number) {
    super(message);
    this.name = "ApiError";
    this.status = status;
  }
}

/** A saúde responde 503 com o mesmo corpo quando o executor está fora: isso é um estado, não um erro. */
export async function fetchHealth(signal?: AbortSignal): Promise<Health> {
  let result;
  try {
    result = await api.GET("/api/v1/health", signal ? { signal } : {});
  } catch (err) {
    if (err instanceof DOMException && err.name === "AbortError") throw err;
    throw new ApiError(err instanceof Error ? err.message : String(err));
  }
  const { data, error, response } = result;
  if (data) return data;
  if (response.status === 503 && error) return error;
  throw new ApiError(`HTTP ${response.status}`, response.status);
}

export const healthQuery = queryOptions({
  queryKey: ["health"],
  queryFn: ({ signal }) => fetchHealth(signal),
  refetchInterval: 30_000,
});

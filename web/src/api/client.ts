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

export type Schemas = components["schemas"];
export type Health = Schemas["Health"];
export type Session = Schemas["Session"];

/** Falha da API: mensagem do servidor (já em linguagem do operador) e código estável para decidir o que fazer. */
export class ApiError extends Error {
  readonly status: number | undefined;
  readonly code: string | undefined;
  constructor(message: string, status?: number, code?: string) {
    super(message);
    this.name = "ApiError";
    this.status = status;
    this.code = code;
  }
}

type FetchResult<T> = { data?: T; error?: unknown; response: Response };

/**
 * Converte o resultado do openapi-fetch em dado ou ApiError. Respostas sem corpo (204) devolvem undefined.
 * Falha de rede vira ApiError sem status, com a causa.
 */
export async function unwrap<T>(call: Promise<FetchResult<T>>): Promise<T> {
  let result: FetchResult<T>;
  try {
    result = await call;
  } catch (err) {
    if (err instanceof DOMException && err.name === "AbortError") throw err;
    throw new ApiError(err instanceof Error ? err.message : String(err));
  }
  const { data, error, response } = result;
  if (response.ok) return data as T;
  const body = (error ?? {}) as { error?: string; code?: string };
  throw new ApiError(body.error ?? `HTTP ${response.status}`, response.status, body.code);
}

export const sessionQuery = queryOptions({
  queryKey: ["session"],
  queryFn: ({ signal }) => unwrap(api.GET("/api/v1/auth/session", { signal })),
  staleTime: 60_000,
});

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

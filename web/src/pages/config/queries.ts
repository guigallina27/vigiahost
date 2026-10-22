import { queryOptions } from "@tanstack/react-query";
import type { TFunction } from "i18next";
import { useEffect, useState } from "react";
import { api, ApiError, unwrap } from "../../api/client";

// Consultas das telas de configuração. ["schedules"] é invalidada pelos eventos ao vivo.

export const schedulesQuery = queryOptions({
  queryKey: ["schedules"],
  queryFn: ({ signal }) => unwrap(api.GET("/api/v1/schedules", { signal })),
});

export const resourcesQuery = queryOptions({
  queryKey: ["resources"],
  queryFn: ({ signal }) => unwrap(api.GET("/api/v1/resources", { signal })),
});

// Calculada na hora pelo servidor (pressão do momento e histórico); não fica velha por muito tempo.
export const suggestionQuery = queryOptions({
  queryKey: ["resources", "suggestion"],
  queryFn: ({ signal }) => unwrap(api.GET("/api/v1/resources/suggestion", { signal })),
  staleTime: 30_000,
});

export const enginesQuery = queryOptions({
  queryKey: ["engines"],
  queryFn: ({ signal }) => unwrap(api.GET("/api/v1/engines", { signal })),
  // O servidor guarda a consulta aos motores por 60 s; atualizar mais que isso não traz nada novo.
  refetchInterval: 60_000,
});

/** Não insiste em erros do pedido (4xx): só em falhas de rede ou do servidor. */
export function retryTransient(count: number, err: unknown): boolean {
  if (err instanceof ApiError && err.status !== undefined && err.status < 500) return false;
  return count < 2;
}

/** Valor que só muda depois de um intervalo sem alterações (pré-visualização enquanto a pessoa digita). */
export function useDebounced<T>(value: T, delay = 400): T {
  const [debounced, setDebounced] = useState(value);
  useEffect(() => {
    const timer = setTimeout(() => setDebounced(value), delay);
    return () => clearTimeout(timer);
  }, [value, delay]);
  return debounced;
}

/** Nome do perfil de recursos para exibição: pré-definidos traduzidos, personalizados como foram nomeados. */
export function profileLabel(name: string, t: TFunction): string {
  switch (name) {
    case "leve":
      return t("config.profiles.leve");
    case "padrao":
      return t("config.profiles.padrao");
    case "intensivo":
      return t("config.profiles.intensivo");
    case "sugerido":
      return t("config.profiles.sugerido");
    default:
      return name;
  }
}

/** Fuso para o Timestamp só quando o navegador o reconhece (um fuso inválido derrubaria a formatação). */
export function zoneProp(timeZone: string | undefined): { timeZone?: string } {
  if (!timeZone) return {};
  try {
    new Intl.DateTimeFormat(undefined, { timeZone });
    return { timeZone };
  } catch {
    return {};
  }
}

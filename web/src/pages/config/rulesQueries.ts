import { queryOptions } from "@tanstack/react-query";
import { api, unwrap } from "../../api/client";

// Consulta e ações da tela "Regras e fontes".

export const rulesQuery = queryOptions({
  queryKey: ["rules"],
  queryFn: ({ signal }) => unwrap(api.GET("/api/v1/rules", { signal })),
  // Enquanto a compilação roda numa unidade isolada, acompanha a cada 3 s; depois, só sob pedido.
  refetchInterval: (query) => (query.state.data?.yara.compiling ? 3_000 : false),
});

export const compileRules = () => unwrap(api.POST("/api/v1/rules/compile", {}));

export const setRuleSource = (name: string, enabled: boolean) =>
  unwrap(api.PUT("/api/v1/rules/sources/{name}", { params: { path: { name } }, body: { enabled } }));

export const setLmd = (enabled: boolean) => unwrap(api.PUT("/api/v1/rules/lmd", { body: { enabled } }));

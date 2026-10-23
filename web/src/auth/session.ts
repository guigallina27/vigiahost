import { useQuery, useQueryClient } from "@tanstack/react-query";
import { api, sessionQuery, unwrap, type Schemas } from "../api/client";

export type Role = Schemas["Role"];

// Mesma escala do servidor (internal/core/authz.go): leitura e auditor veem; operador age; administrador configura.
const rank: Record<Role, number> = { reader: 1, auditor: 1, operator: 2, admin: 3 };

/** Usuário da sessão e o que ele pode fazer (só para esconder botões: quem decide é o servidor). */
export function useCurrentUser() {
  const { data } = useQuery(sessionQuery);
  const user = data?.user;
  const role = user?.role ?? "reader";
  return {
    user,
    session: data,
    canOperate: rank[role] >= 2,
    isAdmin: role === "admin",
    canAudit: role === "admin" || role === "auditor",
  };
}

/**
 * Reautenticação das ações sensíveis: confere senha (e código, com segundo fator) e só então executa a ação.
 * Usar com o ConfirmDialog em requireReauth.
 */
export function useReauth() {
  const qc = useQueryClient();
  const { user } = useCurrentUser();
  return {
    requireCode: !!user?.mfa_enabled,
    async confirm(input: { password?: string; code?: string }, action: () => Promise<unknown>) {
      const body = { password: input.password ?? "", ...(input.code ? { code: input.code } : {}) };
      const session = await unwrap(api.POST("/api/v1/auth/reauth", { body }));
      qc.setQueryData(sessionQuery.queryKey, session);
      await action();
    },
  };
}

import { useMutation, useQueryClient } from "@tanstack/react-query";
import { api, sessionQuery, unwrap } from "../api/client";

/** Encerra a sessão e limpa o cache (nada da sessão anterior fica visível para a próxima pessoa). */
export function useLogout() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: () => unwrap(api.POST("/api/v1/auth/logout")),
    onSettled: async () => {
      qc.clear();
      await qc.invalidateQueries({ queryKey: sessionQuery.queryKey });
    },
  });
}

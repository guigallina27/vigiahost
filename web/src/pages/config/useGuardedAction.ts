import { useState } from "react";
import { useTranslation } from "react-i18next";
import { ApiError } from "../../api/client";
import { useReauth } from "../../auth/session";

/**
 * Executa uma ação confirmada pelo ConfirmDialog. Com alwaysReauth, a senha é pedida desde o início (rotas com
 * reautenticação no servidor); sem ele, só se o servidor responder reauth_required, quando o diálogo passa a pedir
 * a senha e a pessoa confirma de novo.
 */
export function useGuardedAction(alwaysReauth: boolean) {
  const { t } = useTranslation();
  const reauth = useReauth();
  const [asked, setAsked] = useState(false);
  const requireReauth = alwaysReauth || asked;

  async function run(input: { password?: string; code?: string }, action: () => Promise<unknown>) {
    try {
      if (requireReauth) await reauth.confirm(input, action);
      else await action();
    } catch (err) {
      if (err instanceof ApiError && err.code === "reauth_required" && !requireReauth) {
        setAsked(true);
        throw new ApiError(t("config.reauthNeeded"), err.status, err.code);
      }
      throw err;
    }
  }

  return { requireReauth, requireCode: reauth.requireCode, run, reset: () => setAsked(false) };
}

import { useMutation, useQueryClient } from "@tanstack/react-query";
import { ShieldCheck } from "lucide-react";
import type { FormEvent } from "react";
import { useTranslation } from "react-i18next";
import { api, sessionQuery, unwrap } from "../api/client";
import { Button } from "../components/Button";
import { Field, FormError } from "../components/Field";
import { AuthLayout } from "./AuthLayout";
import { useLogout } from "./useLogout";

/** Segundo fator do login: código do aplicativo autenticador ou um código de recuperação. */
export function MfaVerifyPage() {
  const { t } = useTranslation();
  const qc = useQueryClient();
  const logout = useLogout();
  const verify = useMutation({
    mutationFn: (code: string) => unwrap(api.POST("/api/v1/auth/mfa/verify", { body: { code } })),
    onSuccess: (s) => qc.setQueryData(sessionQuery.queryKey, s),
  });
  function submit(e: FormEvent<HTMLFormElement>) {
    e.preventDefault();
    verify.mutate(String(new FormData(e.currentTarget).get("code") ?? "").trim());
  }
  return (
    <AuthLayout title={t("auth.mfaTitle")} subtitle={t("auth.mfaSubtitle")}>
      <form onSubmit={submit} className="flex flex-col gap-4">
        <Field
          label={t("auth.mfaCode")}
          hint={t("auth.mfaCodeHint")}
          name="code"
          autoComplete="one-time-code"
          inputMode="text"
          required
          mono
          maxLength={32}
        />
        <FormError message={verify.error?.message} />
        <Button type="submit" variant="primary" disabled={verify.isPending}>
          <ShieldCheck aria-hidden="true" className="size-4" />
          {t("auth.mfaAction")}
        </Button>
        <Button variant="ghost" onClick={() => logout.mutate()}>
          {t("auth.backToLogin")}
        </Button>
      </form>
    </AuthLayout>
  );
}

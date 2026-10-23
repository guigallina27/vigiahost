import { useMutation, useQueryClient } from "@tanstack/react-query";
import { UserPlus } from "lucide-react";
import { useCallback, useRef, useState, type FormEvent } from "react";
import { useTranslation } from "react-i18next";
import { api, sessionQuery, unwrap, type Session } from "../api/client";
import { Button } from "../components/Button";
import { CaptchaField, type CaptchaHandle } from "../components/CaptchaField";
import { Field, FormError } from "../components/Field";
import { AuthLayout } from "./AuthLayout";
import { InsecureWarning } from "./LoginPage";

/** Primeiro acesso: o token impresso no terminal do servidor cria o primeiro administrador. */
export function SetupPage({ session }: { session: Session }) {
  const { t } = useTranslation();
  const qc = useQueryClient();
  const captcha = useRef<CaptchaHandle>(null);
  const [payload, setPayload] = useState<string | null>(null);
  const [localError, setLocalError] = useState<string | null>(null);
  const onCaptcha = useCallback((p: string | null) => setPayload(p), []);
  const setup = useMutation({
    mutationFn: (body: { token: string; username: string; display_name: string; password: string; altcha: string }) =>
      unwrap(api.POST("/api/v1/auth/setup", { body })),
    onSuccess: (s) => qc.setQueryData(sessionQuery.queryKey, s),
    onSettled: () => {
      captcha.current?.reset();
      setPayload(null);
    },
  });

  function submit(e: FormEvent<HTMLFormElement>) {
    e.preventDefault();
    const data = new FormData(e.currentTarget);
    const password = String(data.get("password") ?? "");
    if (password !== String(data.get("confirm") ?? "")) {
      setLocalError(t("auth.passwordMismatch"));
      return;
    }
    if (!payload) {
      setLocalError(t("captcha.required"));
      return;
    }
    setLocalError(null);
    setup.mutate({
      token: String(data.get("token") ?? "").trim(),
      username: String(data.get("username") ?? "").trim(),
      display_name: String(data.get("display_name") ?? "").trim(),
      password,
      altcha: payload,
    });
  }

  return (
    <AuthLayout title={t("auth.setupTitle")} subtitle={t("auth.setupSubtitle")}>
      <InsecureWarning session={session} />
      <form onSubmit={submit} className="flex flex-col gap-4" noValidate>
        <Field
          label={t("auth.setupToken")}
          hint={
            <>
              {t("auth.setupTokenHint")} <code className="font-mono">sudo vigiahost first-access</code>
            </>
          }
          name="token"
          autoComplete="off"
          required
          mono
          spellCheck={false}
        />
        <Field
          label={t("auth.username")}
          hint={t("auth.usernameHint")}
          name="username"
          autoComplete="username"
          required
          autoCapitalize="none"
          spellCheck={false}
        />
        <Field label={t("auth.displayName")} name="display_name" autoComplete="name" />
        <Field
          label={t("auth.newPassword")}
          hint={t("auth.passwordHint")}
          name="password"
          type="password"
          autoComplete="new-password"
          required
          minLength={12}
        />
        <Field label={t("auth.confirmPassword")} name="confirm" type="password" autoComplete="new-password" required />
        <CaptchaField ref={captcha} onChange={onCaptcha} />
        <FormError message={localError ?? setup.error?.message} />
        <Button type="submit" variant="primary" disabled={setup.isPending}>
          <UserPlus aria-hidden="true" className="size-4" />
          {t("auth.setupAction")}
        </Button>
      </form>
    </AuthLayout>
  );
}

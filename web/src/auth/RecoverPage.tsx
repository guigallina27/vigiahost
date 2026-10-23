import { useMutation } from "@tanstack/react-query";
import { KeyRound } from "lucide-react";
import { useCallback, useRef, useState, type FormEvent } from "react";
import { useTranslation } from "react-i18next";
import { Link } from "react-router";
import { api, unwrap } from "../api/client";
import { Button } from "../components/Button";
import { CaptchaField, type CaptchaHandle } from "../components/CaptchaField";
import { Field, FormError } from "../components/Field";
import { AuthLayout } from "./AuthLayout";

/** Nova senha com o token de recuperação gerado pelo root no servidor ("vigiahost user reset"). */
export function RecoverPage() {
  const { t } = useTranslation();
  const captcha = useRef<CaptchaHandle>(null);
  const [payload, setPayload] = useState<string | null>(null);
  const [localError, setLocalError] = useState<string | null>(null);
  const onCaptcha = useCallback((p: string | null) => setPayload(p), []);
  const reset = useMutation({
    mutationFn: (body: { token: string; password: string; altcha: string }) =>
      unwrap(api.POST("/api/v1/auth/reset", { body })),
    onSettled: () => {
      captcha.current?.reset();
      setPayload(null);
    },
  });

  if (reset.isSuccess) {
    return (
      <AuthLayout title={t("auth.recoverDoneTitle")} subtitle={t("auth.recoverDoneSubtitle")}>
        <Link to="/" className="font-semibold">
          {t("auth.backToLogin")}
        </Link>
      </AuthLayout>
    );
  }

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
    reset.mutate({ token: String(data.get("token") ?? "").trim(), password, altcha: payload });
  }

  return (
    <AuthLayout title={t("auth.recoverTitle")} subtitle={t("auth.recoverSubtitle")}>
      <form onSubmit={submit} className="flex flex-col gap-4" noValidate>
        <Field
          label={t("auth.recoverToken")}
          hint={
            <>
              {t("auth.recoverTokenHint")} <code className="font-mono">sudo vigiahost user reset {t("auth.usernamePlaceholder")}</code>
            </>
          }
          name="token"
          autoComplete="off"
          required
          mono
          spellCheck={false}
        />
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
        <FormError message={localError ?? reset.error?.message} />
        <Button type="submit" variant="primary" disabled={reset.isPending}>
          <KeyRound aria-hidden="true" className="size-4" />
          {t("auth.recoverAction")}
        </Button>
      </form>
      <Link to="/" className="text-sm">
        {t("auth.backToLogin")}
      </Link>
    </AuthLayout>
  );
}

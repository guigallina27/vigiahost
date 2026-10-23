import { useMutation, useQueryClient } from "@tanstack/react-query";
import { LogIn, TriangleAlert } from "lucide-react";
import { useCallback, useRef, useState, type FormEvent } from "react";
import { useTranslation } from "react-i18next";
import { Link } from "react-router";
import { api, sessionQuery, unwrap, type Session } from "../api/client";
import { Button } from "../components/Button";
import { CaptchaField, type CaptchaHandle } from "../components/CaptchaField";
import { Field, FormError } from "../components/Field";
import { AuthLayout } from "./AuthLayout";

/** Aviso quando o painel foi aberto sem HTTPS nem túnel: o servidor recusaria o login. */
export function InsecureWarning({ session }: { session: Session }) {
  const { t } = useTranslation();
  if (session.secure_transport) return null;
  return (
    <p role="alert" className="m-0 flex gap-2 rounded-control border border-(--vh-high-fg) bg-(--vh-high-bg) p-3 text-sm text-(--vh-high-fg)">
      <TriangleAlert aria-hidden="true" className="mt-0.5 size-4 shrink-0" />
      {t("auth.insecure")}
    </p>
  );
}

/** Usuário, senha e a caixa "Não sou um robô". */
export function LoginPage({ session }: { session: Session }) {
  const { t } = useTranslation();
  const qc = useQueryClient();
  const captcha = useRef<CaptchaHandle>(null);
  const [payload, setPayload] = useState<string | null>(null);
  const [missing, setMissing] = useState(false);
  const onCaptcha = useCallback((p: string | null) => {
    setPayload(p);
    if (p) setMissing(false);
  }, []);
  const login = useMutation({
    mutationFn: (body: { username: string; password: string; altcha: string }) =>
      unwrap(api.POST("/api/v1/auth/login", { body })),
    onSuccess: (s) => qc.setQueryData(sessionQuery.queryKey, s),
    // A solução vale uma vez só: depois de cada tentativa, a caixa volta ao início.
    onSettled: () => {
      captcha.current?.reset();
      setPayload(null);
    },
  });

  function submit(e: FormEvent<HTMLFormElement>) {
    e.preventDefault();
    if (!payload) {
      setMissing(true);
      return;
    }
    const data = new FormData(e.currentTarget);
    login.mutate({ username: String(data.get("username") ?? ""), password: String(data.get("password") ?? ""), altcha: payload });
  }

  return (
    <AuthLayout title={t("auth.loginTitle")} subtitle={t("auth.loginSubtitle")}>
      <InsecureWarning session={session} />
      <form onSubmit={submit} className="flex flex-col gap-4" noValidate>
        <Field label={t("auth.username")} name="username" autoComplete="username" required autoCapitalize="none" spellCheck={false} />
        <Field label={t("auth.password")} name="password" type="password" autoComplete="current-password" required />
        <div className="grid gap-1">
          <CaptchaField ref={captcha} onChange={onCaptcha} />
          {missing && <span className="text-sm text-(--vh-critical-fg)">{t("captcha.required")}</span>}
        </div>
        <FormError message={login.error?.message} />
        <Button type="submit" variant="primary" disabled={login.isPending}>
          <LogIn aria-hidden="true" className="size-4" />
          {t("auth.loginAction")}
        </Button>
      </form>
      <p className="m-0 text-sm text-ink-muted">
        {t("auth.forgot")} <Link to="/recuperar">{t("auth.forgotLink")}</Link>
      </p>
    </AuthLayout>
  );
}

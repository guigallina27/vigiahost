import { useMutation } from "@tanstack/react-query";
import { CircleCheck, KeyRound, ShieldAlert, ShieldCheck, TriangleAlert } from "lucide-react";
import { useState, type FormEvent, type ReactNode } from "react";
import { useTranslation } from "react-i18next";
import { Link } from "react-router";
import { api, unwrap } from "../../api/client";
import { useCurrentUser } from "../../auth/session";
import { Badge } from "../../components/Badge";
import { Button } from "../../components/Button";
import { Field, FormError } from "../../components/Field";
import { Panel } from "../../components/Panel";
import { formatNumber } from "../../lib/format";
import { checkPassword } from "./adminLogic";
import { SafeText } from "./SecretOnce";

/** Abaixo disso, avisa que os códigos de recuperação estão acabando. */
const LOW_RECOVERY_CODES = 3;

export type PasswordForm = { current: string; next: string; repeat: string };
export type PasswordFormErrors = { current?: string; next?: string; repeat?: string };

type PasswordMessageKey =
  | "admin.common.passwordShort"
  | "admin.common.passwordLong"
  | "admin.account.currentRequired"
  | "admin.account.mismatch"
  | "admin.account.sameAsCurrent";

/** Validação local da troca de senha (o servidor confere a senha atual e repete a regra de tamanho). */
export function validatePasswordForm(
  form: PasswordForm,
  t: (key: PasswordMessageKey) => string,
): PasswordFormErrors {
  const errors: PasswordFormErrors = {};
  if (!form.current) errors.current = t("admin.account.currentRequired");
  const problem = checkPassword(form.next);
  if (problem) errors.next = problem === "short" ? t("admin.common.passwordShort") : t("admin.common.passwordLong");
  else if (form.next === form.current) errors.next = t("admin.account.sameAsCurrent");
  if (form.repeat !== form.next) errors.repeat = t("admin.account.mismatch");
  return errors;
}

/** Painel "Sua conta" da página de configurações: dados da sessão, troca de senha e acesso aos tokens de API. */
export function AccountPanel() {
  const { t, i18n } = useTranslation();
  const { user, session } = useCurrentUser();
  if (!user) return null;
  const lng = i18n.language;
  const left = user.recovery_codes_left;
  const idleMinutes = session?.idle_timeout_seconds ? Math.round(session.idle_timeout_seconds / 60) : undefined;

  return (
    <>
      <Panel title={t("admin.account.title")}>
        <dl className="m-0 grid gap-4 sm:grid-cols-2">
          <Item label={t("admin.account.name")}>
            <SafeText value={user.display_name || "—"} />
          </Item>
          <Item label={t("admin.account.username")}>
            <SafeText value={user.username} mono />
          </Item>
          <Item label={t("admin.account.role")}>{t(`roles.${user.role}`)}</Item>
          <Item label={t("admin.account.mfa")}>
            {user.mfa_enabled ? (
              <Badge tone="ok" variant="outline" icon={ShieldCheck}>
                {t("admin.account.mfaOn")}
              </Badge>
            ) : (
              <Badge tone="medium" variant="outline" icon={ShieldAlert}>
                {t("admin.account.mfaOff")}
              </Badge>
            )}
          </Item>
          {user.mfa_enabled && left !== undefined && (
            <Item label={t("admin.account.recoveryLeft")}>
              <span className="tabular-nums">{formatNumber(left, lng)}</span>
            </Item>
          )}
          {idleMinutes !== undefined && idleMinutes > 0 && (
            <Item label={t("admin.account.idle")}>{t("admin.account.idleMinutes", { count: idleMinutes })}</Item>
          )}
        </dl>
        {user.mfa_enabled && left !== undefined && left < LOW_RECOVERY_CODES && (
          <p className="m-0 flex items-start gap-2 rounded-control bg-(--vh-medium-bg) p-3 text-(--vh-medium-fg)">
            <TriangleAlert aria-hidden="true" className="mt-0.5 size-4 shrink-0" />
            <span className="min-w-0">{t("admin.account.recoveryLow")}</span>
          </p>
        )}
      </Panel>

      <ChangePassword />

      <Panel title={t("admin.account.tokensTitle")}>
        <p className="m-0">{t("admin.account.tokensIntro")}</p>
        <p className="m-0">
          <Link
            to="/tokens"
            className="inline-flex min-h-11 items-center gap-2 font-semibold text-accent underline underline-offset-4"
          >
            <KeyRound aria-hidden="true" className="size-4" />
            {t("admin.tokens.manageLink")}
          </Link>
        </p>
      </Panel>
    </>
  );
}

function Item({ label, children }: { label: string; children: ReactNode }) {
  return (
    <div className="grid min-w-0 gap-0.5">
      <dt className="text-sm text-ink-muted">{label}</dt>
      <dd className="m-0 min-w-0 font-semibold break-words">{children}</dd>
    </div>
  );
}

function ChangePassword() {
  const { t } = useTranslation();
  const [form, setForm] = useState<PasswordForm>({ current: "", next: "", repeat: "" });
  const [errors, setErrors] = useState<PasswordFormErrors>({});
  const [done, setDone] = useState(false);
  const change = useMutation({
    mutationFn: (body: { current: string; new: string }) => unwrap(api.POST("/api/v1/auth/password", { body })),
    onSuccess: () => {
      setForm({ current: "", next: "", repeat: "" });
      setDone(true);
    },
  });

  function submit(e: FormEvent<HTMLFormElement>) {
    e.preventDefault();
    setDone(false);
    const next = validatePasswordForm(form, (key) => t(key));
    setErrors(next);
    if (next.current || next.next || next.repeat) return;
    change.mutate({ current: form.current, new: form.next });
  }

  return (
    <Panel title={t("admin.account.passwordTitle")}>
      <p className="m-0 text-ink-muted">{t("admin.account.passwordIntro")}</p>
      <form onSubmit={submit} noValidate className="flex flex-col gap-4">
        <Field
          label={t("admin.account.current")}
          error={errors.current ?? null}
          type="password"
          autoComplete="current-password"
          value={form.current}
          onChange={(e) => setForm({ ...form, current: e.target.value })}
          required
        />
        <Field
          label={t("admin.account.new")}
          hint={t("admin.account.newHint")}
          error={errors.next ?? null}
          type="password"
          autoComplete="new-password"
          value={form.next}
          onChange={(e) => setForm({ ...form, next: e.target.value })}
          required
        />
        <Field
          label={t("admin.account.repeat")}
          error={errors.repeat ?? null}
          type="password"
          autoComplete="new-password"
          value={form.repeat}
          onChange={(e) => setForm({ ...form, repeat: e.target.value })}
          required
        />
        <FormError message={change.error?.message} />
        <p role="status" className={done ? "m-0 flex items-center gap-2 font-semibold" : "visually-hidden"}>
          {done && (
            <>
              <CircleCheck aria-hidden="true" className="size-4 shrink-0 text-(--vh-ok-fg)" />
              {t("admin.account.changed")}
            </>
          )}
        </p>
        <div>
          <Button type="submit" variant="primary" disabled={change.isPending}>
            <KeyRound aria-hidden="true" className="size-4" />
            {t("admin.account.submit")}
          </Button>
        </div>
      </form>
    </Panel>
  );
}

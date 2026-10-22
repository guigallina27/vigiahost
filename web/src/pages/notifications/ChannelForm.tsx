import { useMutation, useQueryClient } from "@tanstack/react-query";
import { Check, Copy, KeyRound, Save } from "lucide-react";
import { useEffect, useId, useRef, useState, type FormEvent, type ReactNode } from "react";
import { useTranslation } from "react-i18next";
import { api, ApiError, unwrap } from "../../api/client";
import { Button } from "../../components/Button";
import { ConfirmDialog } from "../../components/ConfirmDialog";
import { Field, FormError, TextAreaField } from "../../components/Field";
import { useGuardedAction } from "../config/useGuardedAction";
import {
  buildChannelBody,
  defaultPort,
  generateWebhookSecret,
  smtpSecurities,
  type Channel,
  type ChannelError,
  type ChannelField,
  type ChannelFormValues,
  type ChannelInput,
  type ChannelKind,
} from "./notifications";
import { notificationsKey } from "./queries";

const radioLabel =
  "grid min-h-11 cursor-pointer grid-cols-[auto_minmax(0,1fr)] items-start gap-x-3 gap-y-0.5 rounded-control border border-line-strong bg-surface px-3 py-2 has-checked:border-accent has-checked:bg-accent-soft has-focus-visible:outline-3 has-focus-visible:outline-offset-2 has-focus-visible:outline-(--vh-focus)";

type Props = {
  /** Canal em edição; ausente para criar. */
  editing?: Channel;
  initial: ChannelFormValues;
  onDone: (saved: Channel) => void;
  onCancel: () => void;
};

/** Criação e edição de canal de e-mail ou webhook. Segredo já guardado nunca aparece: o campo vazio o mantém. */
export function ChannelForm({ editing, initial, onDone, onCancel }: Props) {
  const { t } = useTranslation();
  const qc = useQueryClient();
  const [values, setValues] = useState(initial);
  const [fieldError, setFieldError] = useState<{ field: ChannelField; error: ChannelError } | null>(null);
  const [formError, setFormError] = useState<string | null>(null);
  const [pendingBody, setPendingBody] = useState<ChannelInput | null>(null);
  const [copied, setCopied] = useState<"idle" | "copied" | "failed">("idle");
  const guarded = useGuardedAction(false);
  const headingRef = useRef<HTMLHeadingElement>(null);
  const headingId = useId();
  const toErrorId = useId();

  useEffect(() => headingRef.current?.focus(), []);

  const save = useMutation({
    mutationFn: (body: ChannelInput) =>
      editing
        ? unwrap(api.PUT("/api/v1/notifications/channels/{id}", { params: { path: { id: editing.id } }, body }))
        : unwrap(api.POST("/api/v1/notifications/channels", { body })),
  });

  function set<K extends keyof ChannelFormValues>(key: K, value: ChannelFormValues[K]) {
    setValues((v) => ({ ...v, [key]: value }));
    setFieldError(null);
  }

  function err(field: ChannelField) {
    return fieldError?.field === field ? t(`notifications.form.errors.${fieldError.error}`) : null;
  }

  function submit(e: FormEvent<HTMLFormElement>) {
    e.preventDefault();
    setFormError(null);
    const built = buildChannelBody(values, editing);
    if (!built.ok) {
      setFieldError({ field: built.field, error: built.error });
      return;
    }
    setPendingBody(built.body);
  }

  async function confirm(input: { password?: string; code?: string }) {
    if (!pendingBody) return;
    let saved: Channel | undefined;
    try {
      await guarded.run(input, async () => {
        saved = await save.mutateAsync(pendingBody);
      });
    } catch (e) {
      // Recusa do servidor (destino bloqueado, nome repetido...): a mensagem vai para o formulário.
      if (e instanceof ApiError && (e.status === 400 || e.status === 409)) {
        setFormError(e.message);
        return;
      }
      throw e;
    }
    await qc.invalidateQueries({ queryKey: notificationsKey });
    if (saved) onDone(saved);
  }

  async function copySecret() {
    try {
      await navigator.clipboard.writeText(values.secret);
      setCopied("copied");
    } catch {
      setCopied("failed");
    }
  }

  const kind = values.kind;
  const secretStored = !!editing?.secret_configured;
  const secretLabel = kind === "email" ? t("notifications.form.password") : t("notifications.form.webhookSecret");
  const secretHint =
    kind === "email"
      ? secretStored
        ? t("notifications.form.passwordStored")
        : t("notifications.form.passwordHint")
      : secretStored
        ? t("notifications.form.secretStored")
        : t("notifications.form.secretHint");

  return (
    <section
      aria-labelledby={headingId}
      className="flex min-w-0 flex-col gap-4 rounded-panel border border-line-strong bg-surface p-5 shadow-panel"
    >
      <h2 id={headingId} ref={headingRef} tabIndex={-1} className="m-0 text-xl font-bold [overflow-wrap:anywhere]">
        {editing ? t("notifications.form.editTitle", { name: editing.name }) : t("notifications.form.newTitle")}
      </h2>
      <form onSubmit={submit} className="flex min-w-0 flex-col gap-5" noValidate>
        <FormError message={formError} />
        <Field
          className="max-w-md"
          label={t("notifications.form.name")}
          hint={t("notifications.form.nameHint")}
          value={values.name}
          onChange={(e) => set("name", e.target.value)}
          maxLength={64}
          required
          autoComplete="off"
          error={err("name")}
        />

        {editing ? (
          <p className="m-0">
            <span className="font-semibold">{t("notifications.form.kind")}: </span>
            {t(`notifications.kinds.${kind}`)}
          </p>
        ) : (
          <fieldset className="m-0 min-w-0 border-0 p-0">
            <legend className="mb-2 p-0 font-semibold">{t("notifications.form.kind")}</legend>
            <div className="grid gap-2 md:grid-cols-2">
              {(["email", "webhook"] as ChannelKind[]).map((k) => (
                <RadioOption
                  key={k}
                  name="kind"
                  value={k}
                  checked={kind === k}
                  onChange={() => set("kind", k)}
                  title={t(`notifications.kinds.${k}`)}
                  help={t(`notifications.kindHelp.${k}`)}
                />
              ))}
            </div>
          </fieldset>
        )}

        {kind === "email" ? (
          <>
            <Group legend={t("notifications.form.smtpLegend")}>
              <div className="grid gap-4 md:grid-cols-[minmax(0,2fr)_minmax(0,1fr)]">
                <Field
                  label={t("notifications.form.host")}
                  hint={t("notifications.form.hostHint")}
                  value={values.host}
                  onChange={(e) => set("host", e.target.value)}
                  maxLength={253}
                  required
                  mono
                  autoComplete="off"
                  autoCapitalize="off"
                  spellCheck={false}
                  error={err("host")}
                />
                <Field
                  label={t("notifications.form.port")}
                  hint={t("notifications.form.portHint", { port: defaultPort(values.security) })}
                  value={values.port}
                  onChange={(e) => set("port", e.target.value)}
                  inputMode="numeric"
                  maxLength={5}
                  autoComplete="off"
                  error={err("port")}
                />
              </div>
              <fieldset className="m-0 min-w-0 border-0 p-0">
                <legend className="mb-2 p-0 font-semibold">{t("notifications.form.security")}</legend>
                <div className="grid gap-2 lg:grid-cols-3">
                  {smtpSecurities.map((s) => (
                    <RadioOption
                      key={s}
                      name="security"
                      value={s}
                      checked={values.security === s}
                      onChange={() => set("security", s)}
                      title={t(`notifications.security.${s}`)}
                      help={t(`notifications.securityHelp.${s}`)}
                    />
                  ))}
                </div>
              </fieldset>
              <div className="grid gap-4 md:grid-cols-2">
                <Field
                  label={t("notifications.form.username")}
                  hint={t("notifications.form.usernameHint")}
                  value={values.username}
                  onChange={(e) => set("username", e.target.value)}
                  maxLength={256}
                  autoComplete="off"
                  autoCapitalize="off"
                  spellCheck={false}
                />
                <Field
                  label={secretLabel}
                  hint={secretHint}
                  type="password"
                  value={values.secret}
                  onChange={(e) => set("secret", e.target.value)}
                  maxLength={512}
                  autoComplete="new-password"
                  error={err("secret")}
                />
              </div>
            </Group>
            <Group legend={t("notifications.form.messageLegend")}>
              <Field
                className="max-w-xl"
                label={t("notifications.form.from")}
                hint={t("notifications.form.fromHint")}
                value={values.from}
                onChange={(e) => set("from", e.target.value)}
                maxLength={320}
                required
                autoComplete="off"
                autoCapitalize="off"
                spellCheck={false}
                error={err("from")}
              />
              <TextAreaField
                label={t("notifications.form.to")}
                hint={t("notifications.form.toHint")}
                value={values.to}
                onChange={(e) => set("to", e.target.value)}
                aria-invalid={err("to") ? true : undefined}
                {...(err("to") ? { "aria-describedby": toErrorId } : {})}
                autoCapitalize="off"
                spellCheck={false}
                mono
              />
              {err("to") && (
                <p id={toErrorId} role="alert" className="m-0 text-sm text-(--vh-critical-fg)">
                  {err("to")}
                </p>
              )}
            </Group>
          </>
        ) : (
          <Group legend={t("notifications.form.webhookLegend")}>
            <Field
              label={t("notifications.form.url")}
              hint={t("notifications.form.urlHint")}
              type="url"
              value={values.url}
              onChange={(e) => set("url", e.target.value)}
              maxLength={2048}
              required
              mono
              autoComplete="off"
              autoCapitalize="off"
              spellCheck={false}
              error={err("url")}
            />
            <Checkbox
              label={t("notifications.form.allowPrivate")}
              hint={t("notifications.form.allowPrivateHint")}
              checked={values.allowPrivate}
              onChange={(v) => set("allowPrivate", v)}
            />
            <div className="flex min-w-0 flex-col gap-2">
              <Field
                label={secretLabel}
                hint={secretHint}
                value={values.secret}
                onChange={(e) => {
                  set("secret", e.target.value);
                  setCopied("idle");
                }}
                maxLength={512}
                mono
                autoComplete="off"
                autoCapitalize="off"
                spellCheck={false}
                error={err("secret")}
              />
              <div className="flex flex-wrap gap-2">
                <Button
                  onClick={() => {
                    set("secret", generateWebhookSecret());
                    setCopied("idle");
                  }}
                >
                  <KeyRound aria-hidden="true" className="size-4" />
                  {t("notifications.form.generateSecret")}
                </Button>
                {values.secret !== "" && (
                  <Button onClick={() => void copySecret()}>
                    {copied === "copied" ? (
                      <Check aria-hidden="true" className="size-4" />
                    ) : (
                      <Copy aria-hidden="true" className="size-4" />
                    )}
                    {t("notifications.form.copySecret")}
                  </Button>
                )}
              </div>
              <p role="status" className="m-0 text-sm text-ink-muted">
                {copied === "copied"
                  ? t("notifications.form.secretCopied")
                  : copied === "failed"
                    ? t("notifications.form.secretCopyFailed")
                    : ""}
              </p>
            </div>
          </Group>
        )}

        <Group legend={t("notifications.form.optionsLegend")}>
          <Checkbox
            label={t("notifications.form.enabled")}
            hint={t("notifications.form.enabledHint")}
            checked={values.enabled}
            onChange={(v) => set("enabled", v)}
          />
          <Checkbox
            label={t("notifications.form.includeDetails")}
            hint={t("notifications.form.includeDetailsHint")}
            checked={values.includeDetails}
            onChange={(v) => set("includeDetails", v)}
          />
        </Group>

        <div className="flex flex-wrap justify-end gap-2">
          <Button variant="secondary" onClick={onCancel}>
            {t("notifications.form.cancel")}
          </Button>
          <Button type="submit" variant="primary" disabled={save.isPending}>
            <Save aria-hidden="true" className="size-4" />
            {t("notifications.form.save")}
          </Button>
        </div>
      </form>

      <ConfirmDialog
        open={pendingBody !== null}
        onClose={() => {
          guarded.reset();
          setPendingBody(null);
        }}
        onConfirm={confirm}
        title={editing ? t("notifications.form.confirmEditTitle") : t("notifications.form.confirmNewTitle")}
        object={<strong className="[overflow-wrap:anywhere]">{values.name.trim()}</strong>}
        impact={t(kind === "email" ? "notifications.form.confirmImpactEmail" : "notifications.form.confirmImpactWebhook")}
        reversible
        destructive={false}
        requireReauth={guarded.requireReauth}
        requireCode={guarded.requireCode}
        confirmLabel={t("notifications.form.save")}
      />
    </section>
  );
}

/** Opção de rádio com nome e explicação; o texto fica direto no rótulo (nome acessível sem aninhamento). */
function RadioOption(props: {
  name: string;
  value: string;
  checked: boolean;
  onChange: () => void;
  title: string;
  help: string;
}) {
  return (
    <label className={radioLabel}>
      <input
        type="radio"
        name={props.name}
        value={props.value}
        checked={props.checked}
        onChange={props.onChange}
        className="row-span-2 mt-1 size-4 shrink-0 focus-visible:outline-none"
      />
      <span className="min-w-0 font-semibold">{props.title}</span>
      <span className="min-w-0 text-sm text-ink-muted">{props.help}</span>
    </label>
  );
}

function Group({ legend, children }: { legend: string; children: ReactNode }) {
  return (
    <fieldset className="m-0 flex min-w-0 flex-col gap-4 rounded-control border border-line p-4">
      <legend className="px-1 font-semibold">{legend}</legend>
      {children}
    </fieldset>
  );
}

export function Checkbox({
  label,
  hint,
  checked,
  onChange,
}: {
  label: string;
  hint?: string;
  checked: boolean;
  onChange: (v: boolean) => void;
}) {
  const id = useId();
  return (
    <div className="flex min-w-0 flex-col">
      <label htmlFor={id} className="inline-flex min-h-11 cursor-pointer items-center gap-2 font-semibold">
        <input
          id={id}
          type="checkbox"
          className="size-5 shrink-0 accent-(--vh-accent)"
          checked={checked}
          onChange={(e) => onChange(e.target.checked)}
          aria-describedby={hint ? `${id}-dica` : undefined}
        />
        {label}
      </label>
      {hint && (
        <span id={`${id}-dica`} className="text-sm text-ink-muted">
          {hint}
        </span>
      )}
    </div>
  );
}

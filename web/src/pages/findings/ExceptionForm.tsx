import { useQueryClient } from "@tanstack/react-query";
import { Info } from "lucide-react";
import { useEffect, useId, useRef, useState, type FormEvent } from "react";
import { useTranslation } from "react-i18next";
import { api, unwrap, type Schemas } from "../../api/client";
import { useCurrentUser, useReauth } from "../../auth/session";
import { Button } from "../../components/Button";
import { ConfirmDialog } from "../../components/ConfirmDialog";
import { Field, FormError, SelectField } from "../../components/Field";
import { HashText } from "../../components/HashText";
import { PathText } from "../../components/PathText";
import { formatAbsolute, formatZoneName } from "../../lib/format";
import {
  buildExceptionBody,
  DEFAULT_VALIDITY,
  expiryFor,
  scopeList,
  scopeNeeds,
  validateDraft,
  validityList,
  type DraftErrors,
  type ExceptionDraft,
  type ExceptionScope,
  type Validity,
} from "./exceptionRules";
import { FieldError, NoteField } from "./parts";

type Exception = Schemas["Exception"];

const radioLabel =
  "flex min-h-11 cursor-pointer items-start gap-3 rounded-control border border-line-strong bg-surface px-3 py-2 has-checked:border-accent has-checked:bg-accent-soft has-disabled:cursor-not-allowed has-disabled:opacity-60 has-focus-visible:outline-3 has-focus-visible:outline-offset-2 has-focus-visible:outline-(--vh-focus)";

/** O que a exceção cobre, em linguagem simples, com os valores exatos (hash, regra, diretório). */
export function ExceptionCoverage(props: { scope: ExceptionScope; sha256: string; signature: string; pathPrefix: string }) {
  const { t } = useTranslation();
  const need = scopeNeeds(props.scope);
  return (
    <div className="flex min-w-0 flex-col gap-1">
      <span className="font-semibold">{t(`findings.exceptions.scopeName.${props.scope}`)}</span>
      <dl className="m-0 grid gap-1 text-sm">
        {need.sha256 && props.sha256 && (
          <div className="flex min-w-0 flex-wrap items-center gap-x-2">
            <dt className="text-ink-muted">{t("findings.exceptions.content")}</dt>
            <dd className="m-0 min-w-0">
              <HashText value={props.sha256} />
            </dd>
          </div>
        )}
        {need.signature && props.signature && (
          <div className="flex min-w-0 flex-wrap gap-x-2">
            <dt className="text-ink-muted">{t("findings.exceptions.rule")}</dt>
            <dd className="m-0 min-w-0">
              <PathText path={props.signature} />
            </dd>
          </div>
        )}
        {need.pathPrefix && props.pathPrefix && (
          <div className="flex min-w-0 flex-wrap gap-x-2">
            <dt className="text-ink-muted">{t("findings.exceptions.directory")}</dt>
            <dd className="m-0 min-w-0">
              <PathText path={props.pathPrefix} />
            </dd>
          </div>
        )}
      </dl>
    </div>
  );
}

type Props = {
  initial: ExceptionDraft;
  /** Falso quando o achado de origem não tem SHA-256: os escopos por conteúdo ficam indisponíveis. */
  hashAvailable?: boolean;
  onCancel: () => void;
  onCreated: (created: Exception) => void;
};

/**
 * Formulário de exceção: escopo explicado, motivo e validade; a criação passa por ConfirmDialog com
 * reautenticação (a rota exige). O servidor aplica a exceção aos achados abertos que ela cobre.
 */
export function ExceptionForm({ initial, hashAvailable = true, onCancel, onCreated }: Props) {
  const { t, i18n } = useTranslation();
  const qc = useQueryClient();
  const { isAdmin } = useCurrentUser();
  const reauth = useReauth();
  const scopeErrorId = useId();
  const formRef = useRef<HTMLFormElement>(null);
  const [draft, setDraft] = useState<ExceptionDraft>(initial);
  const [errors, setErrors] = useState<DraftErrors>({});
  const [attempt, setAttempt] = useState(0);
  const [confirming, setConfirming] = useState(false);
  // "Agora" fixado ao abrir o formulário só para mostrar a data de vencimento; o corpo usa o instante da confirmação.
  const [openedAt] = useState(() => new Date());

  const need = scopeNeeds(draft.scope);
  const errorText = (field: keyof DraftErrors) => {
    const code = errors[field];
    return code ? t(`findings.exceptions.errors.${code}`) : null;
  };

  useEffect(() => {
    if (attempt === 0) return;
    formRef.current?.querySelector<HTMLElement>('[aria-invalid="true"], [data-invalid="true"] input:checked')?.focus();
  }, [attempt]);

  function update(patch: Partial<ExceptionDraft>) {
    const next = { ...draft, ...patch };
    // Escopo que exige validade não aceita "sem validade": volta ao prazo padrão.
    if (scopeNeeds(next.scope).expiresRequired && next.validity === "none") next.validity = DEFAULT_VALIDITY;
    setDraft(next);
    // Erros somem quando o campo é corrigido, sem acusar campos ainda não revisados.
    if (Object.keys(errors).length > 0) {
      const now = validateDraft(next, { isAdmin });
      setErrors((prev) => {
        const kept: DraftErrors = {};
        for (const k of Object.keys(prev) as (keyof DraftErrors)[]) {
          const code = now[k];
          if (code) kept[k] = code;
        }
        return kept;
      });
    }
  }

  function submit(e: FormEvent<HTMLFormElement>) {
    e.preventDefault();
    const found = validateDraft(draft, { isAdmin });
    setErrors(found);
    if (Object.keys(found).length > 0) {
      setAttempt((n) => n + 1);
      return;
    }
    setConfirming(true);
  }

  async function create(input: { password?: string; code?: string }) {
    const body = buildExceptionBody(draft, new Date());
    let created: Exception | undefined;
    await reauth.confirm(input, async () => {
      created = await unwrap(api.POST("/api/v1/exceptions", { body }));
    });
    for (const key of [["exceptions"], ["findings"], ["finding"], ["overview"]]) {
      void qc.invalidateQueries({ queryKey: key });
    }
    if (created) onCreated(created);
  }

  const expiry = expiryFor(draft.validity, openedAt);
  const lng = i18n.language;
  const validityOptions = validityList
    .filter((v) => !(need.expiresRequired && v === "none"))
    .map((v) => ({ value: v, label: t(`findings.exceptions.validityOption.${v}`) }));
  const hasErrors = Object.keys(errors).length > 0;

  return (
    <>
      <form ref={formRef} onSubmit={submit} noValidate className="flex flex-col gap-4">
        {draft.findingId !== undefined && (
          <p className="m-0 text-sm text-ink-muted">{t("findings.exceptions.fromFinding", { id: draft.findingId })}</p>
        )}

        <fieldset
          className="m-0 min-w-0 border-0 p-0"
          data-invalid={errors.scope ? "true" : undefined}
          aria-describedby={errors.scope ? scopeErrorId : undefined}
        >
          <legend className="mb-2 p-0 font-semibold">{t("findings.exceptions.scope")}</legend>
          <div className="grid gap-2 md:grid-cols-2">
            {scopeList.map((s) => {
              const sNeed = scopeNeeds(s);
              const blockedAdmin = sNeed.adminOnly && !isAdmin;
              const blockedHash = sNeed.sha256 && !hashAvailable;
              const disabled = (blockedAdmin || blockedHash) && draft.scope !== s;
              return (
                <label key={s} className={radioLabel}>
                  <input
                    type="radio"
                    name="scope"
                    value={s}
                    checked={draft.scope === s}
                    disabled={disabled}
                    onChange={() => update({ scope: s })}
                    className="mt-1 size-4 shrink-0 focus-visible:outline-none"
                  />
                  <span className="flex min-w-0 flex-col gap-0.5">
                    <span className="font-semibold">{t(`findings.exceptions.scopeName.${s}`)}</span>
                    <span className="text-sm text-ink-muted">{t(`findings.exceptions.scopeHelp.${s}`)}</span>
                    {blockedAdmin && <span className="text-sm font-semibold">{t("findings.exceptions.adminOnly")}</span>}
                    {blockedHash && <span className="text-sm font-semibold">{t("findings.exceptions.noHash")}</span>}
                  </span>
                </label>
              );
            })}
          </div>
          {errors.scope && (
            <div className="mt-2">
              <FieldError id={scopeErrorId} message={t(`findings.exceptions.errors.${errors.scope}`)} />
            </div>
          )}
        </fieldset>

        <div className="grid gap-4 md:grid-cols-2">
          {need.sha256 && (
            <Field
              className="md:col-span-2"
              label={t("findings.exceptions.sha256")}
              hint={t("findings.exceptions.sha256Hint")}
              mono
              maxLength={64}
              autoComplete="off"
              spellCheck={false}
              required
              value={draft.sha256}
              onChange={(e) => update({ sha256: e.target.value })}
              error={errorText("sha256")}
            />
          )}
          {need.signature && (
            <Field
              label={t("findings.exceptions.signature")}
              hint={t("findings.exceptions.signatureHint")}
              mono
              maxLength={256}
              autoComplete="off"
              spellCheck={false}
              required
              value={draft.signature}
              onChange={(e) => update({ signature: e.target.value })}
              error={errorText("signature")}
            />
          )}
          {need.pathPrefix && (
            <Field
              label={t("findings.exceptions.pathPrefix")}
              hint={t("findings.exceptions.pathPrefixHint")}
              mono
              maxLength={4096}
              autoComplete="off"
              spellCheck={false}
              required
              value={draft.pathPrefix}
              onChange={(e) => update({ pathPrefix: e.target.value })}
              error={errorText("pathPrefix")}
            />
          )}
        </div>

        <NoteField
          label={t("findings.exceptions.reason")}
          hint={t("findings.exceptions.reasonHint")}
          required
          maxLength={2000}
          value={draft.reason}
          onChange={(e) => update({ reason: e.target.value })}
          error={errorText("reason")}
        />

        <SelectField
          className="max-w-sm"
          label={t("findings.exceptions.validity")}
          hint={
            <>
              {t("findings.exceptions.validityHint")}{" "}
              {expiry
                ? t("findings.exceptions.expiresOn", {
                    date: `${formatAbsolute(expiry, lng)} ${formatZoneName(expiry, lng)}`,
                  })
                : t("findings.exceptions.neverExpires")}
            </>
          }
          options={validityOptions}
          value={draft.validity}
          onChange={(e) => update({ validity: e.target.value as Validity })}
          error={errorText("validity")}
        />

        <p className="m-0 flex items-start gap-2 rounded-control border border-line-strong bg-sunken p-3 text-sm">
          <Info aria-hidden="true" className="mt-0.5 size-4 shrink-0 text-accent" />
          <span className="min-w-0">{t("findings.exceptions.effect")}</span>
        </p>

        <FormError message={hasErrors && attempt > 0 ? t("findings.exceptions.fixErrors") : null} />

        <div className="flex flex-wrap gap-2">
          <Button type="submit" variant="primary">
            {t("findings.exceptions.review")}
          </Button>
          <Button onClick={onCancel}>{t("findings.exceptions.cancel")}</Button>
        </div>
      </form>

      <ConfirmDialog
        open={confirming}
        onClose={() => setConfirming(false)}
        title={t("findings.exceptions.confirmTitle")}
        object={
          <ExceptionCoverage
            scope={draft.scope}
            sha256={draft.sha256.trim().toLowerCase()}
            signature={draft.signature.trim()}
            pathPrefix={draft.pathPrefix.trim()}
          />
        }
        impact={t("findings.exceptions.confirmImpact")}
        reversible
        destructive={false}
        confirmLabel={t("findings.exceptions.confirmLabel")}
        requireReauth
        requireCode={reauth.requireCode}
        onConfirm={create}
      />
    </>
  );
}

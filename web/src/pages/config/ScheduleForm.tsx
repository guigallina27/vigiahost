import { keepPreviousData, useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { CalendarClock, LoaderCircle } from "lucide-react";
import { useEffect, useId, useMemo, useRef, useState, type FormEvent } from "react";
import { useTranslation } from "react-i18next";
import { api, ApiError, unwrap } from "../../api/client";
import { Button } from "../../components/Button";
import { ConfirmDialog } from "../../components/ConfirmDialog";
import { Field, FormError, SelectField, TextAreaField } from "../../components/Field";
import { Timestamp } from "../../components/Timestamp";
import { AccountPicker } from "../accounts/AccountPicker";
import { RUN_KINDS } from "../runs/runFormat";
import { cronToText } from "./cronText";
import { profileLabel, resourcesQuery, useDebounced, zoneProp } from "./queries";
import { fieldForServerError, type ScheduleField } from "./scheduleErrors";
import { buildScheduleInput, type Schedule, type ScheduleFormValues } from "./schedules";
import { useGuardedAction } from "./useGuardedAction";

const CRON_SHORTCUTS = ["0 3 * * *", "0 3 * * 0", "0 */6 * * *", "0 * * * *"];

function timeZones(): string[] {
  try {
    const list = Intl.supportedValuesOf("timeZone");
    return list.includes("UTC") ? list : ["UTC", ...list];
  } catch {
    return ["UTC"];
  }
}

type Props = {
  /** Agendamento em edição; ausente para criar um novo. */
  editing?: Schedule;
  initial: ScheduleFormValues;
  onDone: (saved: Schedule) => void;
  onCancel: () => void;
};

/** Formulário de agendamento com pré-visualização das próximas 5 execuções calculadas pelo servidor. */
export function ScheduleForm({ editing, initial, onDone, onCancel }: Props) {
  const { t, i18n } = useTranslation();
  const lng = i18n.language;
  const qc = useQueryClient();
  const [values, setValues] = useState<ScheduleFormValues>(initial);
  const [fieldErrors, setFieldErrors] = useState<Partial<Record<ScheduleField, string>>>({});
  const [formError, setFormError] = useState<string | null>(null);
  const [confirming, setConfirming] = useState(false);
  const guarded = useGuardedAction(false);
  const headingRef = useRef<HTMLHeadingElement>(null);
  const tzListId = useId();
  const headingId = useId();
  const zones = useMemo(timeZones, []);
  const resources = useQuery(resourcesQuery);

  // Foco no título ao abrir o formulário, para o leitor de tela anunciar o contexto novo.
  useEffect(() => headingRef.current?.focus(), []);

  function set<K extends keyof ScheduleFormValues>(key: K, value: ScheduleFormValues[K]) {
    setValues((v) => ({ ...v, [key]: value }));
    setFieldErrors((e) => {
      const field = key as ScheduleField;
      return field in e ? { ...e, [field]: undefined } : e;
    });
  }

  const pending = useDebounced({ cron: values.cron.trim(), timezone: values.timezone.trim() || "UTC" });
  const preview = useQuery({
    queryKey: ["schedule-preview", pending.cron, pending.timezone],
    queryFn: ({ signal }) =>
      unwrap(api.POST("/api/v1/schedules/preview", { body: { cron: pending.cron, timezone: pending.timezone }, signal })),
    enabled: pending.cron !== "",
    retry: false,
    staleTime: 60_000,
    placeholderData: keepPreviousData,
  });
  const previewError = preview.isError ? preview.error.message : null;
  const previewField = previewError ? (fieldForServerError(previewError) === "timezone" ? "timezone" : "cron") : null;

  const save = useMutation({
    mutationFn: async () => {
      const body = buildScheduleInput(values);
      return editing
        ? unwrap(api.PUT("/api/v1/schedules/{id}", { params: { path: { id: editing.id } }, body }))
        : unwrap(api.POST("/api/v1/schedules", { body }));
    },
    onSuccess: (saved) => {
      void qc.invalidateQueries({ queryKey: ["schedules"] });
      void qc.invalidateQueries({ queryKey: ["overview"] });
      onDone(saved);
    },
  });

  function submit(e: FormEvent<HTMLFormElement>) {
    e.preventDefault();
    setFormError(null);
    setConfirming(true);
  }

  async function confirm(input: { password?: string; code?: string }) {
    try {
      await guarded.run(input, () => save.mutateAsync());
    } catch (err) {
      // Validação do servidor volta para o campo (o diálogo fecha); reautenticação e falhas seguem no diálogo.
      if (err instanceof ApiError && err.status === 400) {
        const field = fieldForServerError(err.message);
        if (field) setFieldErrors((f) => ({ ...f, [field]: err.message }));
        else setFormError(err.message);
        return;
      }
      throw err;
    }
  }

  const description = cronToText(values.cron, t, lng);
  const profileOptions = useMemo(() => {
    const names = resources.data?.profiles.map((p) => p.profile.name) ?? [];
    if (values.profile && !names.includes(values.profile)) names.push(values.profile);
    if (names.length === 0) names.push("padrao");
    return names.map((n) => ({ value: n, label: profileLabel(n, t) }));
  }, [resources.data, values.profile, t]);

  return (
    <section
      aria-labelledby={headingId}
      className="flex min-w-0 flex-col gap-4 rounded-panel border border-line-strong bg-surface p-5 shadow-panel"
    >
      <h2 id={headingId} ref={headingRef} tabIndex={-1} className="m-0 text-xl font-bold">
        {editing ? t("config.schedules.editTitle", { name: editing.name }) : t("config.schedules.newTitle")}
      </h2>
      <form onSubmit={submit} className="flex flex-col gap-4">
        <FormError message={formError} />
        <div className="grid gap-4 md:grid-cols-2">
          <Field
            label={t("config.schedules.name")}
            value={values.name}
            onChange={(e) => set("name", e.target.value)}
            required
            maxLength={128}
            error={fieldErrors.name ?? null}
          />
          <SelectField
            label={t("config.schedules.kind")}
            value={values.kind}
            onChange={(e) => set("kind", RUN_KINDS.find((k) => k === e.target.value) ?? "files")}
            options={RUN_KINDS.map((k) => ({ value: k, label: t(`config.kinds.${k}`) }))}
          />
        </div>

        <div className="grid gap-4 md:grid-cols-2">
          <div className="flex min-w-0 flex-col gap-2">
            <Field
              label={t("config.schedules.cron")}
              hint={t("config.schedules.cronHint")}
              value={values.cron}
              onChange={(e) => set("cron", e.target.value)}
              required
              maxLength={128}
              mono
              autoComplete="off"
              spellCheck={false}
              error={fieldErrors.cron ?? (previewField === "cron" ? previewError : null)}
            />
            <div className="flex flex-wrap items-center gap-2" role="group" aria-label={t("config.schedules.shortcuts")}>
              {CRON_SHORTCUTS.map((expr) => (
                <Button key={expr} variant="ghost" className="border-line! text-sm" onClick={() => set("cron", expr)}>
                  {cronToText(expr, t, lng)}
                </Button>
              ))}
            </div>
          </div>
          <div className="flex min-w-0 flex-col gap-2">
            <Field
              label={t("config.schedules.timezone")}
              hint={t("config.schedules.timezoneHint")}
              value={values.timezone}
              onChange={(e) => set("timezone", e.target.value)}
              list={tzListId}
              autoComplete="off"
              spellCheck={false}
              error={fieldErrors.timezone ?? (previewField === "timezone" ? previewError : null)}
            />
            <datalist id={tzListId}>
              {zones.map((z) => (
                <option key={z} value={z} />
              ))}
            </datalist>
          </div>
        </div>

        <PreviewBox
          description={description}
          next={preview.data?.next}
          loading={preview.isFetching}
          invalid={!!previewError}
          timezone={pending.timezone}
        />

        <div className="grid gap-4 md:grid-cols-2">
          <SelectField
            label={t("config.schedules.profile")}
            hint={t("config.schedules.profileHint")}
            value={values.profile}
            onChange={(e) => set("profile", e.target.value)}
            options={profileOptions}
            error={fieldErrors.profile ?? null}
          />
          <SelectField
            label={t("config.schedules.missedPolicy")}
            hint={t("config.schedules.missedPolicyHint")}
            value={values.missedPolicy}
            onChange={(e) => set("missedPolicy", e.target.value === "skip" ? "skip" : "run_once")}
            options={[
              { value: "run_once", label: t("config.missed.run_once") },
              { value: "skip", label: t("config.missed.skip") },
            ]}
            error={fieldErrors.missedPolicy ?? null}
          />
        </div>

        {values.kind === "files" && (
          <AccountPicker value={values.accounts} onChange={(next) => set("accounts", next)} />
        )}

        {values.kind === "files" && (
          <div className="grid gap-4 md:grid-cols-2">
            <div className="grid min-w-0 gap-1">
              <TextAreaField
                label={t("config.schedules.paths")}
                hint={values.accounts.mode !== "none" ? t("config.schedules.pathsOptionalHint") : t("config.schedules.pathsHint")}
                value={values.paths}
                onChange={(e) => set("paths", e.target.value)}
                mono
                spellCheck={false}
                aria-invalid={fieldErrors.paths ? true : undefined}
              />
              {fieldErrors.paths && (
                <span role="alert" className="text-sm text-(--vh-critical-fg)">
                  {fieldErrors.paths}
                </span>
              )}
            </div>
            <TextAreaField
              label={t("config.schedules.exclude")}
              hint={t("config.schedules.excludeHint")}
              value={values.exclude}
              onChange={(e) => set("exclude", e.target.value)}
              mono
              spellCheck={false}
            />
          </div>
        )}

        <div className="flex flex-wrap gap-x-6 gap-y-2">
          <Check label={t("config.schedules.enabled")} checked={values.enabled} onChange={(v) => set("enabled", v)} />
          {values.kind === "files" && (
            <Check
              label={t("config.schedules.incremental")}
              hint={t("config.schedules.incrementalHint")}
              checked={values.incremental}
              onChange={(v) => set("incremental", v)}
            />
          )}
        </div>

        <div className="flex flex-wrap justify-end gap-2">
          <Button variant="secondary" onClick={onCancel}>
            {t("config.schedules.cancelEdit")}
          </Button>
          <Button type="submit" variant="primary" disabled={save.isPending}>
            <CalendarClock aria-hidden="true" className="size-4" />
            {editing ? t("config.schedules.saveChanges") : t("config.schedules.create")}
          </Button>
        </div>
      </form>

      <ConfirmDialog
        open={confirming}
        onClose={() => {
          setConfirming(false);
          guarded.reset();
        }}
        onConfirm={confirm}
        title={editing ? t("config.schedules.confirmEditTitle") : t("config.schedules.confirmCreateTitle")}
        object={
          <span className="flex flex-col gap-1">
            <strong className="[overflow-wrap:anywhere]">{values.name.trim() || "—"}</strong>
            <span>
              {description} · <code>{values.cron.trim()}</code> · {values.timezone.trim() || "UTC"}
            </span>
          </span>
        }
        impact={values.enabled ? t("config.schedules.confirmImpact") : t("config.schedules.confirmImpactDisabled")}
        reversible
        destructive={false}
        requireReauth={guarded.requireReauth}
        requireCode={guarded.requireCode}
        confirmLabel={editing ? t("config.schedules.saveChanges") : t("config.schedules.create")}
      />
    </section>
  );
}

function PreviewBox({
  description,
  next,
  loading,
  invalid,
  timezone,
}: {
  description: string;
  next: string[] | undefined;
  loading: boolean;
  invalid: boolean;
  timezone: string;
}) {
  const { t } = useTranslation();
  return (
    <div className="flex min-w-0 flex-col gap-2 rounded-control border border-line bg-sunken p-3" aria-live="polite">
      <p className="m-0 font-semibold">{description}</p>
      <h3 className="m-0 flex items-center gap-2 text-sm font-semibold text-ink-muted">
        {t("config.schedules.nextRuns")}
        {loading && <LoaderCircle aria-hidden="true" className="size-4 motion-safe:animate-spin" />}
      </h3>
      {invalid ? (
        <p className="m-0 text-sm text-ink-muted">{t("config.schedules.previewInvalid")}</p>
      ) : next && next.length > 0 ? (
        <ol className="m-0 flex flex-col gap-1 pl-5">
          {next.map((d) => (
            <li key={d}>
              <Timestamp date={new Date(d)} {...zoneProp(timezone)} compact />
            </li>
          ))}
        </ol>
      ) : (
        <p className="m-0 text-sm text-ink-muted">{loading ? t("states.loading") : t("config.schedules.previewEmpty")}</p>
      )}
    </div>
  );
}

function Check({
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
          className="size-5 accent-(--vh-accent)"
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

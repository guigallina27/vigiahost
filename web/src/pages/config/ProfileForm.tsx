import { useMutation, useQueryClient } from "@tanstack/react-query";
import { Save } from "lucide-react";
import { useEffect, useId, useRef, useState, type FormEvent } from "react";
import { useTranslation } from "react-i18next";
import { api, ApiError, unwrap, type Schemas } from "../../api/client";
import { Button } from "../../components/Button";
import { ConfirmDialog } from "../../components/ConfirmDialog";
import { Field, FormError } from "../../components/Field";
import { formatNumber } from "../../lib/format";
import { profileLabel, resourcesQuery } from "./queries";
import { buildProfileBody, PROFILE_NAME, type ProfileFormValues } from "./resources";
import { formatBytes } from "./units";
import { useGuardedAction } from "./useGuardedAction";

type Props = {
  /** Nome do perfil em edição (pré-definido ou personalizado); ausente para criar. */
  editingName?: string;
  initial: ProfileFormValues;
  hardware: Schemas["Hardware"] | undefined;
  existingNames: string[];
  onDone: (name: string) => void;
  onCancel: () => void;
};

/** Criação e edição de perfil de recursos (administrador, com reautenticação). */
export function ProfileForm({ editingName, initial, hardware, existingNames, onDone, onCancel }: Props) {
  const { t, i18n } = useTranslation();
  const lng = i18n.language;
  const qc = useQueryClient();
  const [values, setValues] = useState(initial);
  const [fieldError, setFieldError] = useState<{ field: keyof ProfileFormValues; message: string } | null>(null);
  const [formError, setFormError] = useState<string | null>(null);
  const [confirming, setConfirming] = useState(false);
  const guarded = useGuardedAction(true);
  const headingRef = useRef<HTMLHeadingElement>(null);
  const headingId = useId();

  useEffect(() => headingRef.current?.focus(), []);

  const save = useMutation({
    mutationFn: (body: Schemas["ResourceProfile"]) =>
      unwrap(api.PUT("/api/v1/resources/profiles/{name}", { params: { path: { name: body.name } }, body })),
    onSuccess: (data) => qc.setQueryData(resourcesQuery.queryKey, data),
  });

  function set(key: keyof ProfileFormValues, value: string) {
    setValues((v) => ({ ...v, [key]: value }));
    if (fieldError?.field === key) setFieldError(null);
  }

  function err(key: keyof ProfileFormValues) {
    return fieldError?.field === key ? fieldError.message : null;
  }

  function submit(e: FormEvent<HTMLFormElement>) {
    e.preventDefault();
    setFormError(null);
    const name = values.name.trim();
    if (!editingName) {
      if (!PROFILE_NAME.test(name)) {
        setFieldError({ field: "name", message: t("config.resources.form.nameInvalid") });
        return;
      }
      if (existingNames.includes(name)) {
        setFieldError({ field: "name", message: t("config.resources.form.nameTaken") });
        return;
      }
    }
    const built = buildProfileBody(values);
    if (!built.ok) {
      setFieldError({ field: built.field, message: t("config.resources.form.notNumber") });
      return;
    }
    setConfirming(true);
  }

  async function confirm(input: { password?: string; code?: string }) {
    const built = buildProfileBody(values);
    if (!built.ok) return;
    try {
      await guarded.run(input, () => save.mutateAsync(built.body));
    } catch (e) {
      // Limite recusado pelo servidor (reserva de CPU/memória, faixas): a mensagem vai para o formulário.
      if (e instanceof ApiError && e.status === 400) {
        setFormError(t("config.resources.form.refused", { reason: e.message }));
        return;
      }
      throw e;
    }
    onDone(built.body.name);
  }

  const cpus = hardware?.cpus;
  const cpuHint = cpus
    ? t("config.resources.form.cpuHintHw", { count: cpus, max: formatNumber(cpus * 100, lng) })
    : t("config.resources.form.cpuHint");
  const memHint = hardware
    ? t("config.resources.form.memoryHintHw", { total: formatBytes(hardware.memory_bytes, lng) })
    : t("config.resources.form.memoryHint");

  const numeric = { inputMode: "numeric" as const, autoComplete: "off", required: true, className: "" };

  return (
    <section aria-labelledby={headingId} className="flex min-w-0 flex-col gap-4 rounded-panel border border-line-strong bg-surface p-5 shadow-panel">
      <h2 id={headingId} ref={headingRef} tabIndex={-1} className="m-0 text-xl font-bold">
        {editingName ? t("config.resources.form.editTitle", { name: profileLabel(editingName, t) }) : t("config.resources.form.newTitle")}
      </h2>
      <p className="m-0 text-sm text-ink-muted">{t("config.resources.form.intro")}</p>
      <form onSubmit={submit} className="flex flex-col gap-4">
        <FormError message={formError} />
        {!editingName && (
          <Field
            className="max-w-md"
            label={t("config.resources.form.name")}
            hint={t("config.resources.form.nameHint")}
            value={values.name}
            onChange={(e) => set("name", e.target.value.toLowerCase())}
            required
            maxLength={32}
            mono
            autoComplete="off"
            spellCheck={false}
            error={err("name")}
          />
        )}
        <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-3">
          <Field {...numeric} label={t("config.resources.limits.cpu")} hint={cpuHint} value={values.cpuPercent} onChange={(e) => set("cpuPercent", e.target.value)} error={err("cpuPercent")} />
          <Field {...numeric} label={t("config.resources.limits.memoryMiB")} hint={memHint} value={values.memoryMiB} onChange={(e) => set("memoryMiB", e.target.value)} error={err("memoryMiB")} />
          <Field {...numeric} label={t("config.resources.limits.ioReadMiBps")} hint={t("config.resources.form.ioReadHint")} value={values.ioReadMiBps} onChange={(e) => set("ioReadMiBps", e.target.value)} error={err("ioReadMiBps")} />
          <Field {...numeric} label={t("config.resources.limits.ioWeight")} hint={t("config.resources.form.ioWeightHint")} value={values.ioWeight} onChange={(e) => set("ioWeight", e.target.value)} error={err("ioWeight")} />
          <Field {...numeric} label={t("config.resources.limits.workers")} hint={t("config.resources.form.workersHint")} value={values.workers} onChange={(e) => set("workers", e.target.value)} error={err("workers")} />
          <Field {...numeric} label={t("config.resources.limits.clamd")} hint={t("config.resources.form.clamdHint")} value={values.clamdConcurrency} onChange={(e) => set("clamdConcurrency", e.target.value)} error={err("clamdConcurrency")} />
          <Field {...numeric} label={t("config.resources.limits.nice")} hint={t("config.resources.form.niceHint")} value={values.nice} onChange={(e) => set("nice", e.target.value)} error={err("nice")} />
          <Field {...numeric} label={t("config.resources.limits.runtimeMin")} hint={t("config.resources.form.runtimeHint")} value={values.maxRuntimeMin} onChange={(e) => set("maxRuntimeMin", e.target.value)} error={err("maxRuntimeMin")} />
          <Field {...numeric} label={t("config.resources.limits.maxFileMiB")} hint={t("config.resources.form.maxFileHint")} value={values.maxFileMiB} onChange={(e) => set("maxFileMiB", e.target.value)} error={err("maxFileMiB")} />
        </div>
        <fieldset className="m-0 flex min-w-0 flex-col gap-3 border-0 p-0">
          <legend className="mb-1 p-0 text-base font-semibold">{t("config.resources.limits.pressure")}</legend>
          <p className="m-0 text-sm text-ink-muted">{t("config.resources.form.pressureIntro")}</p>
          <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-3">
            <Field {...numeric} label={t("config.resources.limits.pressureCpu")} hint={t("config.resources.form.pressureHint")} value={values.pressureCpu} onChange={(e) => set("pressureCpu", e.target.value)} error={err("pressureCpu")} />
            <Field {...numeric} label={t("config.resources.limits.pressureIo")} hint={t("config.resources.form.pressureHint")} value={values.pressureIo} onChange={(e) => set("pressureIo", e.target.value)} error={err("pressureIo")} />
            <Field {...numeric} label={t("config.resources.limits.pressureMemory")} hint={t("config.resources.form.pressureHint")} value={values.pressureMemory} onChange={(e) => set("pressureMemory", e.target.value)} error={err("pressureMemory")} />
          </div>
        </fieldset>
        <div className="flex flex-wrap justify-end gap-2">
          <Button variant="secondary" onClick={onCancel}>
            {t("config.resources.form.cancel")}
          </Button>
          <Button type="submit" variant="primary" disabled={save.isPending}>
            <Save aria-hidden="true" className="size-4" />
            {t("config.resources.form.save")}
          </Button>
        </div>
      </form>

      <ConfirmDialog
        open={confirming}
        onClose={() => setConfirming(false)}
        onConfirm={confirm}
        title={editingName ? t("config.resources.form.confirmEditTitle") : t("config.resources.form.confirmNewTitle")}
        object={<code className="[overflow-wrap:anywhere]">{values.name.trim()}</code>}
        impact={t("config.resources.form.confirmImpact")}
        reversible
        destructive={false}
        requireReauth={guarded.requireReauth}
        requireCode={guarded.requireCode}
        confirmLabel={t("config.resources.form.save")}
      />
    </section>
  );
}

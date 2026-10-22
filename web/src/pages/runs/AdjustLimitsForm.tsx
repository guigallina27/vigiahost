import { useQueryClient } from "@tanstack/react-query";
import { Gauge } from "lucide-react";
import { useId, useState, type FormEvent } from "react";
import { useTranslation } from "react-i18next";
import { api, ApiError, unwrap, type Schemas } from "../../api/client";
import { Button } from "../../components/Button";
import { ConfirmDialog } from "../../components/ConfirmDialog";
import { Field, FormError } from "../../components/Field";
import { useGuardedAction } from "../config/useGuardedAction";
import { adjustValuesFrom, buildAdjustBody, type AdjustField, type AdjustValues, type RunAdjustRequest } from "./performance";
import type { Run } from "./runFormat";

type RunDetail = Schemas["RunDetail"];

/**
 * Ajuste de CPU, memória e disco da execução em andamento, aplicado na hora pelo executor (administrador, com
 * reautenticação). Workers e prioridade continuam os do perfil: valem a partir da próxima execução.
 */
export function AdjustLimitsForm({ run, allowNoReserve, onDone }: { run: Run; allowNoReserve: boolean; onDone: (msg: string) => void }) {
  const { t } = useTranslation();
  const qc = useQueryClient();
  const headingId = useId();
  const noReserveId = useId();
  const [values, setValues] = useState<AdjustValues>(() => adjustValuesFrom(run.profile));
  const [noReserve, setNoReserve] = useState(false);
  const [fieldError, setFieldError] = useState<{ field: AdjustField; message: string } | null>(null);
  const [formError, setFormError] = useState<string | null>(null);
  const [pending, setPending] = useState<{ body: RunAdjustRequest; changes: AdjustField[] } | null>(null);
  const guarded = useGuardedAction(true);

  function set(key: AdjustField, value: string) {
    setValues((v) => ({ ...v, [key]: value }));
    if (fieldError?.field === key) setFieldError(null);
  }
  const err = (key: AdjustField) => (fieldError?.field === key ? fieldError.message : null);

  function submit(e: FormEvent<HTMLFormElement>) {
    e.preventDefault();
    setFormError(null);
    const built = buildAdjustBody(values, run.profile, noReserve);
    if (!built.ok) {
      if (built.code === "nothing") setFormError(t("runs.adjust.nothing"));
      else setFieldError({ field: built.field, message: t("runs.adjust.notNumber") });
      return;
    }
    setPending({ body: built.body, changes: built.changes });
  }

  async function confirm(input: { password?: string; code?: string }) {
    if (!pending) return;
    try {
      await guarded.run(input, async () => {
        const updated = await unwrap(
          api.POST("/api/v1/runs/{runId}/adjust", { params: { path: { runId: run.id } }, body: pending.body }),
        );
        qc.setQueryData<RunDetail>(["run", run.id], (old) => (old ? { ...old, run: updated } : old));
        setValues(adjustValuesFrom(updated.profile));
        void qc.invalidateQueries({ queryKey: ["run", run.id] });
      });
    } catch (e) {
      // Trava do executor (reserva do sistema, faixas): a mensagem explica e o diálogo fecha.
      if (e instanceof ApiError && (e.status === 400 || e.status === 409)) {
        setFormError(t("runs.adjust.refused", { reason: e.message }));
        return;
      }
      throw e;
    }
    setNoReserve(false);
    onDone(t("runs.adjust.applied"));
  }

  const numeric = { inputMode: "numeric" as const, autoComplete: "off", required: true };
  const labels: Record<AdjustField, string> = {
    cpuPercent: t("runs.adjust.cpu"),
    memoryMiB: t("runs.adjust.memory"),
    ioReadMiBps: t("runs.adjust.ioRead"),
    ioWeight: t("runs.adjust.ioWeight"),
  };

  return (
    <section aria-labelledby={headingId} className="flex min-w-0 flex-col gap-3 border-t border-line pt-4">
      <h3 id={headingId} className="m-0 text-base font-semibold">
        {t("runs.adjust.title")}
      </h3>
      <p className="m-0 text-sm text-ink-muted">{t("runs.adjust.hint")}</p>
      <form onSubmit={submit} className="flex flex-col gap-3">
        <FormError message={formError} />
        <div className="grid gap-3 sm:grid-cols-2">
          <Field {...numeric} label={labels.cpuPercent} hint={t("runs.adjust.cpuHint")} value={values.cpuPercent} onChange={(e) => set("cpuPercent", e.target.value)} error={err("cpuPercent")} />
          <Field {...numeric} label={labels.memoryMiB} hint={t("runs.adjust.memoryHint")} value={values.memoryMiB} onChange={(e) => set("memoryMiB", e.target.value)} error={err("memoryMiB")} />
          <Field {...numeric} label={labels.ioReadMiBps} hint={t("runs.adjust.ioReadHint")} value={values.ioReadMiBps} onChange={(e) => set("ioReadMiBps", e.target.value)} error={err("ioReadMiBps")} />
          <Field {...numeric} label={labels.ioWeight} hint={t("runs.adjust.ioWeightHint")} value={values.ioWeight} onChange={(e) => set("ioWeight", e.target.value)} error={err("ioWeight")} />
        </div>
        {allowNoReserve && (
          <div className="flex flex-col gap-1">
            <label htmlFor={noReserveId} className="inline-flex min-h-11 cursor-pointer items-center gap-2 font-semibold">
              <input id={noReserveId} type="checkbox" className="size-5 accent-(--vh-accent)" checked={noReserve} onChange={(e) => setNoReserve(e.target.checked)} />
              {t("runs.adjust.noReserve")}
            </label>
            <p className="m-0 text-sm text-ink-muted">{t("runs.adjust.noReserveHint")}</p>
          </div>
        )}
        <Button type="submit" className="self-start">
          <Gauge aria-hidden="true" className="size-4" />
          {t("runs.adjust.submit")}
        </Button>
      </form>

      <ConfirmDialog
        open={pending !== null}
        onClose={() => setPending(null)}
        onConfirm={confirm}
        title={t("runs.adjust.confirmTitle")}
        object={
          <ul className="m-0 flex list-none flex-col gap-1 p-0">
            {pending?.changes.map((f) => (
              <li key={f}>{t("runs.adjust.changeLine", { label: labels[f], value: values[f] })}</li>
            ))}
            {pending?.body.no_reserve && <li>{t("runs.adjust.noReserve")}</li>}
          </ul>
        }
        impact={t("runs.adjust.confirmImpact")}
        reversible
        destructive={false}
        requireReauth={guarded.requireReauth}
        requireCode={guarded.requireCode}
        confirmLabel={t("runs.adjust.submit")}
      />
    </section>
  );
}

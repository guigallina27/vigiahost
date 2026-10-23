import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Lightbulb, RefreshCw, Wand2 } from "lucide-react";
import { useState, type ReactNode } from "react";
import { useTranslation } from "react-i18next";
import { api, ApiError, unwrap, type Schemas } from "../../api/client";
import { Button } from "../../components/Button";
import { ConfirmDialog } from "../../components/ConfirmDialog";
import { FormError } from "../../components/Field";
import { Panel } from "../../components/Panel";
import { formatNumber } from "../../lib/format";
import { resourcesQuery, retryTransient, suggestionQuery } from "./queries";
import { reasonText, suggestedProfileBody } from "./suggestion";
import { formatBytes, formatDecimal, splitDuration } from "./units";
import { useGuardedAction } from "./useGuardedAction";

type Props = {
  isAdmin: boolean;
  /** Já existe o perfil próprio "sugerido" (aplicar atualiza em vez de criar). */
  hasSuggested: boolean;
  onApplied: (name: string) => void;
};

function Item({ label, children }: { label: string; children: ReactNode }) {
  return (
    <div className="grid min-w-0 gap-0.5">
      <dt className="text-sm text-ink-muted">{label}</dt>
      <dd className="m-0 min-w-0 font-semibold break-words tabular-nums">{children}</dd>
    </div>
  );
}

/**
 * Sugestão de perfil pelo hardware, pela pressão típica e pelo histórico das execuções, com a explicação de cada
 * limite. "Aplicar sugestão" grava o perfil próprio "sugerido" (administrador, com reautenticação).
 */
export function SuggestionPanel({ isAdmin, hasSuggested, onApplied }: Props) {
  const { t, i18n } = useTranslation();
  const lng = i18n.language;
  const qc = useQueryClient();
  const q = useQuery({ ...suggestionQuery, retry: retryTransient });
  const [confirming, setConfirming] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const guarded = useGuardedAction(true);
  const save = useMutation({
    mutationFn: (body: Schemas["ResourceProfile"]) =>
      unwrap(api.PUT("/api/v1/resources/profiles/{name}", { params: { path: { name: body.name } }, body })),
    onSuccess: (data) => qc.setQueryData(resourcesQuery.queryKey, data),
  });

  const refresh = (
    <Button variant="ghost" onClick={() => void q.refetch()} disabled={q.isFetching}>
      <RefreshCw aria-hidden="true" className="size-4" />
      {t("config.resources.suggestion.refresh")}
    </Button>
  );

  if (q.isPending) {
    return (
      <Panel title={t("config.resources.suggestion.title")}>
        <p role="status" className="m-0 text-ink-muted">
          {t("config.resources.suggestion.loading")}
        </p>
      </Panel>
    );
  }
  if (q.isError) {
    return (
      <Panel title={t("config.resources.suggestion.title")} actions={refresh}>
        <p role="alert" className="m-0 [overflow-wrap:anywhere]">
          {t("config.resources.suggestion.loadError", { cause: q.error.message })}
        </p>
      </Panel>
    );
  }

  const s = q.data;
  const p = s.profile;
  const b = s.basis;
  const runtime = splitDuration(p.max_runtime_sec);
  const body = suggestedProfileBody(s);

  async function apply(input: { password?: string; code?: string }) {
    setError(null);
    try {
      await guarded.run(input, () => save.mutateAsync(body));
    } catch (e) {
      // Trava do servidor (o hardware mudou desde o cálculo): explica no painel e fecha o diálogo.
      if (e instanceof ApiError && e.status === 400) {
        setError(t("config.resources.suggestion.refused", { reason: e.message }));
        return;
      }
      throw e;
    }
    onApplied(body.name);
  }

  return (
    <Panel title={t("config.resources.suggestion.title")} actions={refresh}>
      <p className="m-0 max-w-prose text-ink-muted">{t("config.resources.suggestion.intro")}</p>
      <p className="m-0 text-sm">
        {t("config.resources.suggestion.basis", {
          cpus: formatNumber(b.cpus, lng),
          memory: formatBytes(b.memory_bytes, lng),
          disk: t(`config.resources.suggestion.disk.${b.disk_type}`),
          load: formatDecimal(b.load_avg, lng, 2),
        })}{" "}
        {b.psi
          ? t("config.resources.suggestion.basisPsi", {
              cpu: formatDecimal(b.cpu_pressure, lng),
              io: formatDecimal(b.io_pressure, lng),
              memory: formatDecimal(b.memory_pressure, lng),
            })
          : t("config.resources.suggestion.basisNoPsi")}{" "}
        {b.history_runs > 0
          ? t("config.resources.suggestion.history", {
              count: b.history_runs,
              formatted: formatNumber(b.history_runs, lng),
              percent: formatDecimal(b.limited_ratio * 100, lng),
            })
          : t("config.resources.suggestion.historyNone")}
      </p>

      <div className="grid min-w-0 gap-6 lg:grid-cols-2">
        <section aria-labelledby="sugestao-limites" className="flex min-w-0 flex-col gap-3">
          <h3 id="sugestao-limites" className="m-0 text-base font-semibold">
            {t("config.resources.suggestion.limitsTitle")}
          </h3>
          <dl className="m-0 grid gap-3 sm:grid-cols-2">
            <Item label={t("config.resources.limits.cpu")}>{formatNumber(p.cpu_quota_percent, lng)}%</Item>
            <Item label={t("config.resources.limits.memory")}>{formatBytes(p.memory_max_bytes, lng)}</Item>
            <Item label={t("config.resources.limits.ioRead")}>
              {p.io_read_bytes_per_sec > 0
                ? t("config.resources.perSecond", { value: formatBytes(p.io_read_bytes_per_sec, lng) })
                : t("config.resources.noBandwidthLimit")}
            </Item>
            <Item label={t("config.resources.limits.ioWeight")}>{formatNumber(p.io_weight, lng)}</Item>
            <Item label={t("config.resources.limits.workers")}>{formatNumber(p.workers, lng)}</Item>
            <Item label={t("config.resources.limits.clamd")}>{formatNumber(p.clamd_concurrency, lng)}</Item>
            <Item label={t("config.resources.limits.nice")}>{p.nice}</Item>
            <Item label={t("config.resources.limits.runtime")}>
              {t("config.resources.duration", { hours: runtime.hours, minutes: runtime.minutes })}
            </Item>
            <Item label={t("config.resources.limits.pressure")}>
              {t("config.resources.suggestion.pressureValue", {
                cpu: p.pressure_cpu ?? 0,
                io: p.pressure_io ?? 0,
                memory: p.pressure_memory ?? 0,
              })}
            </Item>
          </dl>
        </section>
        <section aria-labelledby="sugestao-motivos" className="flex min-w-0 flex-col gap-3">
          <h3 id="sugestao-motivos" className="m-0 text-base font-semibold">
            {t("config.resources.suggestion.reasonsTitle")}
          </h3>
          <ul className="m-0 flex list-none flex-col gap-2 p-0">
            {s.reasons.map((r, i) => (
              <li key={`${r.code}-${i}`} className="flex gap-2">
                <Lightbulb aria-hidden="true" className="mt-0.5 size-4 shrink-0 text-ink-muted" />
                <span className="min-w-0 [overflow-wrap:anywhere]">{reasonText(r, t, lng)}</span>
              </li>
            ))}
          </ul>
        </section>
      </div>

      <FormError message={error} />
      {isAdmin ? (
        <div className="flex flex-wrap items-center gap-3">
          <Button variant="primary" onClick={() => setConfirming(true)} disabled={save.isPending}>
            <Wand2 aria-hidden="true" className="size-4" />
            {t("config.resources.suggestion.apply")}
          </Button>
          <span className="text-sm text-ink-muted">
            {t(hasSuggested ? "config.resources.suggestion.applyHintUpdate" : "config.resources.suggestion.applyHintNew")}
          </span>
        </div>
      ) : (
        <p className="m-0 text-sm text-ink-muted">{t("config.resources.suggestion.adminOnly")}</p>
      )}

      <ConfirmDialog
        open={confirming}
        onClose={() => setConfirming(false)}
        onConfirm={apply}
        title={t("config.resources.suggestion.applyTitle")}
        object={<code className="[overflow-wrap:anywhere]">{body.name}</code>}
        impact={t(hasSuggested ? "config.resources.suggestion.applyImpactUpdate" : "config.resources.suggestion.applyImpactNew")}
        reversible
        destructive={false}
        requireReauth={guarded.requireReauth}
        requireCode={guarded.requireCode}
        confirmLabel={t("config.resources.suggestion.apply")}
      />
    </Panel>
  );
}

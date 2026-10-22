import { CircleAlert, LoaderCircle, Play, PlugZap, RefreshCw, SearchX, ShieldOff, TriangleAlert, type LucideIcon } from "lucide-react";
import type { ReactNode } from "react";
import { useTranslation } from "react-i18next";
import { Link, useSearchParams } from "react-router";
import type { Schemas } from "../../api/client";
import { ApiError } from "../../api/client";
import { useCurrentUser } from "../../auth/session";
import { Button } from "../../components/Button";
import { EmptyState } from "../../components/EmptyState";
import { FormError, SelectField } from "../../components/Field";
import { Panel } from "../../components/Panel";
import { formatAbsolute } from "../../lib/format";
import { parseRunId } from "../inventory/processes";
import { reportHref, systemFindingsHref, type SystemKind } from "./systemFormat";
import type { useSystemCheck } from "./useSystemCheck";

type Check = ReturnType<typeof useSystemCheck>;

/** Execução escolhida pelo endereço (?execucao=<id>); inválida ou ausente vale a mais recente. */
export function useReportRun(): string | undefined {
  const [params] = useSearchParams();
  return parseRunId(params.get("execucao"));
}

/** Botão "Verificar agora" (só operador e administrador). */
export function CheckButton({ check }: { check: Check }) {
  const { t } = useTranslation();
  const { canOperate } = useCurrentUser();
  if (!canOperate) return null;
  return (
    <Button variant="primary" onClick={() => check.check.mutate()} disabled={check.check.isPending || check.active}>
      <Play aria-hidden="true" className="size-4" />
      {t("system.checkNow")}
    </Button>
  );
}

/** Aviso de verificação em andamento (região viva sempre presente) e erro ao pedir uma nova. */
export function CheckStatus({ check }: { check: Check }) {
  const { t } = useTranslation();
  const { run, active } = check;
  return (
    <>
      <p role="status" className={active && run ? "m-0 flex flex-wrap items-center gap-2 rounded-control border border-line-strong bg-accent-soft p-3" : "visually-hidden"}>
        {active && run && (
          <>
            <LoaderCircle aria-hidden="true" className="size-4 shrink-0 motion-safe:animate-spin" />
            <span>{t("system.running")}</span>
            <Link to={`/execucoes/${run.id}`} className="font-semibold text-accent underline underline-offset-4">
              {t("system.followRun", { id: run.id })}
            </Link>
          </>
        )}
      </p>
      {check.check.isError && <FormError message={check.check.error.message} />}
    </>
  );
}

/** De qual execução é o relatório, com a escolha entre os guardados. */
export function ReportInfo({ kind, report }: { kind: SystemKind; report: { run_id: string; runs: Schemas["ReportRun"][] } }) {
  const { t, i18n } = useTranslation();
  const [, setParams] = useSearchParams();
  const lng = i18n.language;
  const latest = report.runs[0]?.run_id;
  const options = report.runs.map((r, i) => {
    const date = formatAbsolute(new Date(r.taken_at), lng);
    return { value: r.run_id, label: i === 0 ? t("system.latest", { date }) : date };
  });
  if (!options.some((o) => o.value === report.run_id)) options.push({ value: report.run_id, label: report.run_id });
  return (
    <div className="flex flex-wrap items-end gap-x-6 gap-y-3">
      {options.length > 1 && (
        <SelectField
          className="w-full max-w-sm"
          label={t("system.history")}
          hint={t("system.historyHint")}
          value={report.run_id}
          onChange={(e) =>
            setParams(
              (prev) => {
                const p = new URLSearchParams(prev);
                if (e.target.value === latest) p.delete("execucao");
                else p.set("execucao", e.target.value);
                return p;
              },
              { replace: true },
            )
          }
          options={options}
        />
      )}
      <p className="m-0 flex min-h-11 flex-wrap items-center gap-x-2 text-sm text-ink-muted">
        <span>{t("system.reportOf")}</span>
        <Link to={`/execucoes/${report.run_id}`} className="font-mono font-semibold text-accent underline underline-offset-4">
          {report.run_id}
        </Link>
        <span aria-hidden="true">·</span>
        <Link to={systemFindingsHref(kind)} className="font-semibold text-accent underline underline-offset-4">
          {t("system.findingsLink")}
        </Link>
      </p>
    </div>
  );
}

/** Avisos e erro da verificação (lista com ícone; o texto vem do executor). */
export function ReportNotes({ error, warnings }: { error?: string | undefined; warnings?: string[] | undefined }) {
  const { t } = useTranslation();
  const list = warnings ?? [];
  if (!error && list.length === 0) return null;
  return (
    <>
      {error && (
        <div className="flex gap-2 rounded-control border border-(--vh-critical-fg) bg-(--vh-critical-bg) p-3 text-(--vh-critical-fg)">
          <CircleAlert aria-hidden="true" className="mt-0.5 size-4 shrink-0" />
          <div className="min-w-0">
            <h2 className="m-0 text-base font-bold">{t("system.error")}</h2>
            <p className="m-0 [overflow-wrap:anywhere]">{error}</p>
          </div>
        </div>
      )}
      {list.length > 0 && (
        <Panel title={t("system.warnings")}>
          <ul className="m-0 flex list-none flex-col gap-2 p-0">
            {list.map((w, i) => (
              <li key={i} className="flex gap-2">
                <TriangleAlert aria-hidden="true" className="mt-0.5 size-4 shrink-0 text-(--vh-high-fg)" />
                <span className="min-w-0 [overflow-wrap:anywhere]">{w}</span>
              </li>
            ))}
          </ul>
        </Panel>
      )}
    </>
  );
}

export function Loading() {
  const { t } = useTranslation();
  return (
    <p role="status" className="m-0 text-ink-muted">
      {t("states.loading")}
    </p>
  );
}

/** Sem relatório ainda (404), relatório inexistente, sem permissão ou falha de rede, cada um com o próximo passo. */
export function ReportProblem({
  kind,
  icon,
  error,
  runId,
  retry,
  checkAction,
}: {
  kind: SystemKind;
  icon: LucideIcon;
  error: Error;
  runId: string | undefined;
  retry: () => void;
  checkAction: ReactNode;
}) {
  const { t } = useTranslation();
  const apiErr = error instanceof ApiError ? error : undefined;
  if (apiErr?.status === 404 && !runId) {
    return (
      <EmptyState
        icon={icon}
        title={t(`system.${kind}.noReportTitle`)}
        description={
          <>
            <p className="m-0">{t(`system.${kind}.noReportDescription`)}</p>
            {!checkAction && <p className="m-0 mt-2">{t("system.noReportAskOperator")}</p>}
          </>
        }
        action={checkAction || undefined}
      />
    );
  }
  if (apiErr?.status === 404 && runId) {
    return (
      <EmptyState
        icon={SearchX}
        title={t("system.runNotFoundTitle")}
        description={t("system.runNotFoundDescription", { id: runId })}
        action={
          <Link to={reportHref(kind)} className="inline-flex min-h-11 items-center font-semibold text-accent underline underline-offset-4">
            {t("system.viewLatest")}
          </Link>
        }
      />
    );
  }
  if (apiErr?.status === 403) {
    return <EmptyState tone="error" icon={ShieldOff} title={t("states.forbidden")} description={error.message} />;
  }
  return (
    <EmptyState
      tone="error"
      icon={PlugZap}
      title={t("system.loadErrorTitle")}
      description={<div role="alert">{t("system.loadErrorDescription", { cause: error.message })}</div>}
      action={
        <Button variant="primary" onClick={retry}>
          <RefreshCw aria-hidden="true" className="size-4" />
          {t("states.retry")}
        </Button>
      }
    />
  );
}

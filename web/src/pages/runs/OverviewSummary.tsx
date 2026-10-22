import { useQuery } from "@tanstack/react-query";
import { CircleAlert, ListChecks, Play, RefreshCw } from "lucide-react";
import type { ReactNode } from "react";
import { useTranslation } from "react-i18next";
import { Link } from "react-router";
import type { Schemas } from "../../api/client";
import { Button } from "../../components/Button";
import { EmptyState } from "../../components/EmptyState";
import { Panel } from "../../components/Panel";
import { PathText } from "../../components/PathText";
import { SeverityBadge, severities } from "../../components/SeverityBadge";
import { Timestamp } from "../../components/Timestamp";
import { formatNumber } from "../../lib/format";
import { EngineList } from "./EngineList";
import { overviewQuery } from "./queries";
import { DurationText, KindLabel, PhaseText, RunStatus } from "./RunBits";
import { toDate, type Run } from "./runFormat";

type Overview = Schemas["Overview"];
type Finding = Schemas["Finding"];

/** Endereço da lista de achados filtrada por severidade (combinado com a frente de achados). */
export function severityHref(severity: string): string {
  return `/achados?${new URLSearchParams({ severity }).toString()}`;
}

/** Resumo de achados, execuções e motores da Visão geral (GET /api/v1/overview, chave ["overview"], atualizada ao vivo). */
export function OverviewSummary({ canOperate, onNewRun }: { canOperate: boolean; onNewRun: () => void }) {
  const { t } = useTranslation();
  const overview = useQuery(overviewQuery);
  if (overview.isPending) {
    return (
      <p className="m-0 text-ink-muted" role="status">
        {t("states.loading")}
      </p>
    );
  }
  if (overview.isError) {
    return (
      <EmptyState
        tone="error"
        icon={CircleAlert}
        title={t("runs.overview.loadError")}
        description={overview.error.message}
        action={
          <Button onClick={() => void overview.refetch()} disabled={overview.isFetching}>
            <RefreshCw aria-hidden="true" className="size-4" />
            {t("states.retry")}
          </Button>
        }
      />
    );
  }
  const data = overview.data;
  return (
    <>
      {!data.has_runs && (
        <EmptyState
          icon={ListChecks}
          title={t("runs.overview.firstTitle")}
          description={
            <>
              <p className="m-0">{canOperate ? t("runs.overview.firstDescription") : t("runs.overview.firstDescriptionReader")}</p>
              {!data.has_schedules && <p className="m-0 mt-2">{t("runs.overview.noSchedules")}</p>}
            </>
          }
          action={
            canOperate && (
              <div className="flex flex-wrap items-center gap-3">
                <Button variant="primary" onClick={onNewRun}>
                  <Play aria-hidden="true" className="size-4" />
                  {t("runs.firstRun")}
                </Button>
                {!data.has_schedules && (
                  <Link to="/agendamentos" className="inline-flex min-h-11 items-center font-semibold">
                    {t("runs.overview.configureSchedules")}
                  </Link>
                )}
              </div>
            )
          }
        />
      )}
      <div className="grid items-start gap-6 xl:grid-cols-2">
        <OpenFindingsPanel counts={data.open_findings} />
        <ActiveRunsPanel runs={data.active_runs} />
      </div>
      <div className="grid items-start gap-6 xl:grid-cols-2">
        <LastRunPanel title={t("runs.overview.lastFiles")} empty={t("runs.overview.noLastFiles")} run={data.last_files_run} />
        <LastRunPanel title={t("runs.overview.lastProcesses")} empty={t("runs.overview.noLastProcesses")} run={data.last_processes_run} />
      </div>
      <div className="grid items-start gap-6 xl:grid-cols-2">
        <RecentFindingsPanel findings={data.recent_findings} />
        <Panel
          title={t("runs.overview.engines")}
          actions={
            <Link to="/cobertura" className="inline-flex min-h-11 items-center font-semibold">
              {t("runs.overview.viewCoverage")}
            </Link>
          }
        >
          <EngineList engines={data.engines} />
        </Panel>
      </div>
    </>
  );
}

function OpenFindingsPanel({ counts }: { counts: Overview["open_findings"] }) {
  const { t, i18n } = useTranslation();
  const lng = i18n.language;
  return (
    <Panel
      title={t("runs.overview.openFindings")}
      actions={
        <Link to="/achados" className="inline-flex min-h-11 items-center font-semibold">
          {t("runs.overview.viewAllFindings")}
        </Link>
      }
    >
      <p className="m-0 text-2xl font-bold tabular-nums">
        {t("runs.overview.openTotal", { count: counts.total, formatted: formatNumber(counts.total, lng) })}
      </p>
      {counts.total === 0 ? (
        <p className="m-0 text-ink-muted">{t("runs.overview.noOpenFindings")}</p>
      ) : (
        <ul className="m-0 grid list-none grid-cols-[repeat(auto-fill,minmax(9.5rem,1fr))] gap-2 p-0">
          {severities.map((s) => (
            <li key={s} className="min-w-0">
              <Link
                to={severityHref(s)}
                className="flex min-h-11 items-center justify-between gap-2 rounded-control border border-line px-3 py-2 text-ink no-underline hover:border-line-strong hover:bg-sunken"
              >
                <SeverityBadge severity={s} />
                <span className="text-lg font-bold tabular-nums">{formatNumber(counts[s], lng)}</span>
              </Link>
            </li>
          ))}
        </ul>
      )}
    </Panel>
  );
}

function RunLink({ run }: { run: Run }) {
  return (
    <Link to={`/execucoes/${encodeURIComponent(run.id)}`} className="font-mono font-semibold [overflow-wrap:anywhere]">
      {run.id}
    </Link>
  );
}

function ActiveRunsPanel({ runs }: { runs: Run[] }) {
  const { t } = useTranslation();
  return (
    <Panel
      title={t("runs.overview.activeRuns")}
      actions={
        <Link to="/execucoes" className="inline-flex min-h-11 items-center font-semibold">
          {t("runs.overview.viewRuns")}
        </Link>
      }
    >
      {runs.length === 0 ? (
        <p className="m-0 text-ink-muted">{t("runs.overview.noActiveRuns")}</p>
      ) : (
        <ul className="m-0 flex list-none flex-col divide-y divide-line p-0">
          {runs.map((run) => (
            <li key={run.id} className="flex min-w-0 flex-col gap-1 py-2 first:pt-0 last:pb-0">
              <div className="flex min-w-0 flex-wrap items-center gap-x-3 gap-y-1">
                <RunLink run={run} />
                <RunStatus run={run} />
              </div>
              <div className="flex flex-wrap items-center gap-x-3 gap-y-1 text-sm text-ink-muted">
                <KindLabel kind={run.kind} />
                {run.phase && <PhaseText phase={run.phase} />}
                <DurationText run={run} />
              </div>
            </li>
          ))}
        </ul>
      )}
    </Panel>
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

function LastRunPanel({ title, empty, run }: { title: string; empty: string; run: Run | undefined }) {
  const { t, i18n } = useTranslation();
  const lng = i18n.language;
  if (!run) {
    return (
      <Panel title={title}>
        <p className="m-0 text-ink-muted">{empty}</p>
      </Panel>
    );
  }
  const finished = toDate(run.finished_at);
  const counts = { processed: formatNumber(run.files_processed, lng), eligible: formatNumber(run.files_eligible, lng) };
  return (
    <Panel title={title}>
      <div className="flex min-w-0 flex-wrap items-center gap-x-3 gap-y-1">
        <RunLink run={run} />
        <RunStatus run={run} />
      </div>
      <dl className="m-0 grid gap-4 sm:grid-cols-2">
        <Item label={t("runs.overview.finished")}>{finished ? <Timestamp date={finished} /> : t("runs.none")}</Item>
        <Item label={t("runs.detail.findings")}>
          <span className="tabular-nums">
            {t("runs.overview.findings", { count: run.findings_count, formatted: formatNumber(run.findings_count, lng) })}
          </span>
        </Item>
        <Item label={t("runs.detail.duration")}>
          <DurationText run={run} />
        </Item>
        <Item label={t("runs.table.processed")}>
          {run.files_eligible > 0 ? (
            <span className="tabular-nums">
              {run.kind === "files" ? t("runs.overview.processedFiles", counts) : t("runs.overview.processedTargets", counts)}
            </span>
          ) : (
            t("runs.none")
          )}
        </Item>
      </dl>
    </Panel>
  );
}

function findingSubject(f: Finding): ReactNode {
  if (f.location?.path) return <PathText path={f.location.path} />;
  if (f.process) return <PathText path={f.process.exe || f.process.comm} />;
  if (f.persistence?.path) return <PathText path={f.persistence.path} />;
  return null;
}

function RecentFindingsPanel({ findings }: { findings: Finding[] }) {
  const { t } = useTranslation();
  return (
    <Panel title={t("runs.overview.recentFindings")}>
      {findings.length === 0 ? (
        <p className="m-0 text-ink-muted">{t("runs.overview.noRecentFindings")}</p>
      ) : (
        <ul className="m-0 flex list-none flex-col divide-y divide-line p-0">
          {findings.map((f) => {
            const seen = toDate(f.last_seen);
            return (
              <li key={f.id} className="flex min-w-0 flex-col gap-1 py-2 first:pt-0 last:pb-0">
                <div className="flex min-w-0 flex-wrap items-center gap-x-3 gap-y-1">
                  <SeverityBadge severity={f.severity} />
                  <Link to={`/achados/${f.id}`} className="min-w-0 font-semibold [overflow-wrap:anywhere]">
                    {f.signature}
                  </Link>
                </div>
                {f.process && (
                  <span className="text-sm text-ink-muted">
                    {t("runs.overview.processLabel", { pid: f.process.pid, comm: f.process.comm })}
                  </span>
                )}
                <span className="min-w-0 text-sm">{findingSubject(f)}</span>
                {seen && (
                  <span className="text-sm text-ink-muted">
                    {t("runs.overview.lastSeen")} <Timestamp date={seen} compact />
                  </span>
                )}
              </li>
            );
          })}
        </ul>
      )}
    </Panel>
  );
}

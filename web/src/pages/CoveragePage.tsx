import { useQuery } from "@tanstack/react-query";
import { CircleAlert, RefreshCw } from "lucide-react";
import { useTranslation } from "react-i18next";
import { Link } from "react-router";
import { Button } from "../components/Button";
import { EmptyState } from "../components/EmptyState";
import { Panel } from "../components/Panel";
import { Timestamp } from "../components/Timestamp";
import { PageHeader } from "../layout/PageHeader";
import { EngineList } from "./runs/EngineList";
import { enginesQuery, overviewQuery, runQuery } from "./runs/queries";
import { KindLabel, RunStatus } from "./runs/RunBits";
import { EngineCoverageCard, SkipReasonGlossary, SkipReasonTable } from "./runs/RunCoverage";
import { skipEntries, toDate, type Run } from "./runs/runFormat";

/** Cobertura (rota /cobertura): saúde dos motores e o que a última verificação de cada tipo conseguiu analisar. */
export function CoveragePage() {
  const { t } = useTranslation();
  const overview = useQuery(overviewQuery);
  return (
    <>
      <PageHeader title={t("runs.coverage.title")} subtitle={t("runs.coverage.subtitle")} />
      <div className="flex flex-col gap-6">
        <EnginesPanel />
        {overview.isPending ? (
          <p className="m-0 text-ink-muted" role="status">
            {t("states.loading")}
          </p>
        ) : overview.isError ? (
          <EmptyState
            tone="error"
            icon={CircleAlert}
            title={t("runs.overview.loadError")}
            description={overview.error.message}
            action={<RetryButton onClick={() => void overview.refetch()} disabled={overview.isFetching} />}
          />
        ) : (
          <>
            <LastRunCoverage title={t("runs.coverage.lastFiles")} empty={t("runs.coverage.noLastFiles")} run={overview.data.last_files_run} />
            <LastRunCoverage
              title={t("runs.coverage.lastProcesses")}
              empty={t("runs.coverage.noLastProcesses")}
              run={overview.data.last_processes_run}
            />
          </>
        )}
        <Panel title={t("runs.coverage.glossary")}>
          <p className="m-0 max-w-prose text-ink-muted">{t("runs.coverage.glossaryIntro")}</p>
          <SkipReasonGlossary />
        </Panel>
      </div>
    </>
  );
}

function RetryButton({ onClick, disabled }: { onClick: () => void; disabled: boolean }) {
  const { t } = useTranslation();
  return (
    <Button onClick={onClick} disabled={disabled}>
      <RefreshCw aria-hidden="true" className="size-4" />
      {t("states.retry")}
    </Button>
  );
}

function EnginesPanel() {
  const { t } = useTranslation();
  const engines = useQuery(enginesQuery);
  return (
    <Panel title={t("runs.coverage.engines")}>
      {engines.isPending ? (
        <p className="m-0 text-ink-muted" role="status">
          {t("states.loading")}
        </p>
      ) : engines.isError ? (
        <EmptyState
          tone="error"
          icon={CircleAlert}
          headingLevel={3}
          title={t("runs.coverage.enginesError")}
          description={engines.error.message}
          action={<RetryButton onClick={() => void engines.refetch()} disabled={engines.isFetching} />}
        />
      ) : (
        <>
          {engines.data.executor_error && (
            <p className="m-0 rounded-control border border-(--vh-critical-fg) bg-(--vh-critical-bg) p-3 text-sm text-(--vh-critical-fg) [overflow-wrap:anywhere]">
              {t("runs.coverage.executorError", { cause: engines.data.executor_error })}
            </p>
          )}
          <EngineList engines={engines.data.engines} />
        </>
      )}
    </Panel>
  );
}

function LastRunCoverage({ title, empty, run }: { title: string; empty: string; run: Run | undefined }) {
  const { t } = useTranslation();
  if (!run) {
    return (
      <Panel title={title}>
        <p className="m-0 text-ink-muted">{empty}</p>
      </Panel>
    );
  }
  const finished = toDate(run.finished_at);
  return (
    <Panel
      title={title}
      actions={
        <Link to={`/execucoes/${encodeURIComponent(run.id)}`} className="inline-flex min-h-11 items-center font-semibold [overflow-wrap:anywhere]">
          {t("runs.coverage.viewRun", { id: run.id })}
        </Link>
      }
    >
      <div className="flex flex-wrap items-center gap-x-4 gap-y-2">
        <RunStatus run={run} />
        <KindLabel kind={run.kind} />
        {finished && (
          <span className="text-sm">
            <span className="text-ink-muted">{t("runs.coverage.finishedAt")}</span> <Timestamp date={finished} compact />
          </span>
        )}
      </div>
      <RunEngines runId={run.id} />
      {skipEntries(run.summary?.skipped).length > 0 && (
        <div className="flex flex-col gap-2">
          <h3 className="m-0 text-base font-semibold">{t("runs.detail.walkSkipped")}</h3>
          <p className="m-0 text-sm text-ink-muted">{t("runs.detail.walkSkippedHint")}</p>
          <SkipReasonTable skipped={run.summary?.skipped} />
        </div>
      )}
    </Panel>
  );
}

function RunEngines({ runId }: { runId: string }) {
  const { t } = useTranslation();
  const detail = useQuery(runQuery(runId));
  if (detail.isPending) {
    return (
      <p className="m-0 text-ink-muted" role="status">
        {t("states.loading")}
      </p>
    );
  }
  if (detail.isError) {
    return (
      <div className="flex flex-wrap items-center gap-3">
        <p role="alert" className="m-0 rounded-control bg-(--vh-critical-bg) p-3 text-sm text-(--vh-critical-fg)">
          {t("runs.coverage.runError", { cause: detail.error.message })}
        </p>
        <RetryButton onClick={() => void detail.refetch()} disabled={detail.isFetching} />
      </div>
    );
  }
  if (detail.data.engines.length === 0) return <p className="m-0 text-ink-muted">{t("runs.coverage.noEngines")}</p>;
  return (
    <div className="grid items-start gap-4 lg:grid-cols-2">
      {detail.data.engines.map((e) => (
        <EngineCoverageCard key={e.engine} engine={e} />
      ))}
    </div>
  );
}

import { useQuery } from "@tanstack/react-query";
import { Cpu, LoaderCircle, PlugZap, Play, RefreshCw, SearchX, ShieldOff } from "lucide-react";
import { useId, useRef, type KeyboardEvent, type ReactNode } from "react";
import { useTranslation } from "react-i18next";
import { Link, useSearchParams } from "react-router";
import { api, ApiError, unwrap } from "../../api/client";
import { useCurrentUser } from "../../auth/session";
import { Button } from "../../components/Button";
import { EmptyState } from "../../components/EmptyState";
import { FormError } from "../../components/Field";
import { Timestamp } from "../../components/Timestamp";
import { PageHeader } from "../../layout/PageHeader";
import { PersistenceView } from "./PersistenceView";
import { parseRunId } from "./processes";
import { ProcessTable } from "./ProcessTable";
import { useProcessInspection } from "./useProcessInspection";

type Tab = "processes" | "persistence";
const TABS: Tab[] = ["processes", "persistence"];

/**
 * Processos e persistência da última inspeção (rota sugerida: /processos). A aba vem de ?aba=persistencia e
 * um instantâneo específico de ?execucao=<id>.
 */
export function ProcessesPage() {
  const { t } = useTranslation();
  const [params, setParams] = useSearchParams();
  const tab: Tab = params.get("aba") === "persistencia" ? "persistence" : "processes";
  const runId = parseRunId(params.get("execucao"));
  const { canOperate } = useCurrentUser();
  const inspection = useProcessInspection();
  const baseId = useId();
  const tabRefs = useRef<Record<Tab, HTMLButtonElement | null>>({ processes: null, persistence: null });

  function select(next: Tab, focus = false) {
    setParams(
      (prev) => {
        const p = new URLSearchParams(prev);
        if (next === "persistence") p.set("aba", "persistencia");
        else p.delete("aba");
        return p;
      },
      { replace: true },
    );
    if (focus) tabRefs.current[next]?.focus();
  }

  // Teclado das abas (padrão WAI-ARIA): setas, Home e End movem e ativam.
  function onTabKey(e: KeyboardEvent<HTMLButtonElement>) {
    const i = TABS.indexOf(tab);
    let next: Tab | undefined;
    if (e.key === "ArrowRight") next = TABS[(i + 1) % TABS.length];
    else if (e.key === "ArrowLeft") next = TABS[(i - 1 + TABS.length) % TABS.length];
    else if (e.key === "Home") next = TABS[0];
    else if (e.key === "End") next = TABS[TABS.length - 1];
    if (next) {
      e.preventDefault();
      select(next, true);
    }
  }

  const inspectButton = canOperate && (
    <Button
      variant="primary"
      onClick={() => inspection.inspect.mutate()}
      disabled={inspection.inspect.isPending || inspection.active}
    >
      <Play aria-hidden="true" className="size-4" />
      {t("inventory.inspectNow")}
    </Button>
  );

  return (
    <>
      <PageHeader title={t("inventory.title")} subtitle={t("inventory.subtitle")} actions={inspectButton} />

      <div className="flex min-w-0 flex-col gap-4">
        <InspectionStatus inspection={inspection} />

        <div role="tablist" aria-label={t("inventory.tabsLabel")} className="flex flex-wrap gap-1 border-b border-line">
          {TABS.map((id) => {
            const selected = id === tab;
            return (
              <button
                key={id}
                ref={(el) => {
                  tabRefs.current[id] = el;
                }}
                type="button"
                role="tab"
                id={`${baseId}-aba-${id}`}
                aria-selected={selected}
                aria-controls={`${baseId}-painel`}
                tabIndex={selected ? 0 : -1}
                onClick={() => select(id)}
                onKeyDown={onTabKey}
                className={`-mb-px min-h-11 cursor-pointer border-b-[3px] px-4 font-semibold ${
                  selected ? "border-accent text-ink" : "border-transparent text-ink-muted hover:text-ink"
                }`}
              >
                {t(id === "processes" ? "inventory.tabProcesses" : "inventory.tabPersistence")}
              </button>
            );
          })}
        </div>

        <div role="tabpanel" id={`${baseId}-painel`} aria-labelledby={`${baseId}-aba-${tab}`} className="min-w-0">
          {tab === "processes" ? (
            <ProcessesTab runId={runId} inspectAction={inspectButton} />
          ) : (
            <PersistenceTab runId={runId} inspectAction={inspectButton} />
          )}
        </div>
      </div>
    </>
  );
}

export default ProcessesPage;

/** Aviso de inspeção em andamento e erro ao pedir uma nova. */
function InspectionStatus({ inspection }: { inspection: ReturnType<typeof useProcessInspection> }) {
  const { t } = useTranslation();
  const { run, active, inspect } = inspection;
  return (
    <>
      <p role="status" className={active && run ? "m-0 flex flex-wrap items-center gap-2 rounded-control border border-line-strong bg-accent-soft p-3" : "visually-hidden"}>
        {active && run && (
          <>
            <LoaderCircle aria-hidden="true" className="size-4 shrink-0 motion-safe:animate-spin" />
            <span>{t("inventory.inspectionRunning")}</span>
            <Link to={`/execucoes/${run.id}`} className="font-semibold text-accent underline underline-offset-4">
              {t("inventory.followRun", { id: run.id })}
            </Link>
          </>
        )}
      </p>
      {inspect.isError && <FormError message={inspect.error.message} />}
    </>
  );
}

/** De qual inspeção é o instantâneo. */
function SnapshotInfo({ runId, takenAt }: { runId: string; takenAt: string }) {
  const { t } = useTranslation();
  return (
    <p className="m-0 flex flex-wrap items-baseline gap-x-2 gap-y-1 text-sm text-ink-muted">
      <span>{t("inventory.snapshotOf")}</span>
      <Link to={`/execucoes/${runId}`} className="font-mono font-semibold text-accent underline underline-offset-4">
        {runId}
      </Link>
      <span aria-hidden="true">·</span>
      <span>{t("inventory.takenAt")}</span>
      <Timestamp date={new Date(takenAt)} compact />
    </p>
  );
}

function ProcessesTab({ runId, inspectAction }: { runId: string | undefined; inspectAction: ReactNode }) {
  const { t } = useTranslation();
  const q = useQuery({
    queryKey: ["inventory", "processes", runId ?? "latest"],
    queryFn: ({ signal }) =>
      unwrap(api.GET("/api/v1/inventory/processes", { params: { query: runId ? { run_id: runId } : {} }, signal })),
    retry: (count, err) => !(err instanceof ApiError && err.status !== undefined && err.status < 500) && count < 2,
  });
  if (q.isPending) return <Loading />;
  if (q.isError) return <QueryProblem error={q.error} runId={runId} retry={() => void q.refetch()} inspectAction={inspectAction} />;
  return (
    <div className="flex min-w-0 flex-col gap-4">
      <SnapshotInfo runId={q.data.run_id} takenAt={q.data.taken_at} />
      {q.data.processes.length === 0 ? (
        <EmptyState icon={Cpu} title={t("inventory.processes.emptyTitle")} description={t("inventory.processes.emptyDescription")} />
      ) : (
        <ProcessTable processes={q.data.processes} />
      )}
    </div>
  );
}

function PersistenceTab({ runId, inspectAction }: { runId: string | undefined; inspectAction: ReactNode }) {
  const q = useQuery({
    queryKey: ["inventory", "persistence", runId ?? "latest"],
    queryFn: ({ signal }) =>
      unwrap(api.GET("/api/v1/inventory/persistence", { params: { query: runId ? { run_id: runId } : {} }, signal })),
    retry: (count, err) => !(err instanceof ApiError && err.status !== undefined && err.status < 500) && count < 2,
  });
  if (q.isPending) return <Loading />;
  if (q.isError) return <QueryProblem error={q.error} runId={runId} retry={() => void q.refetch()} inspectAction={inspectAction} />;
  return (
    <div className="flex min-w-0 flex-col gap-4">
      <SnapshotInfo runId={q.data.run_id} takenAt={q.data.taken_at} />
      <PersistenceView inventory={q.data} />
    </div>
  );
}

function Loading() {
  const { t } = useTranslation();
  return (
    <p role="status" className="m-0 text-ink-muted">
      {t("states.loading")}
    </p>
  );
}

/** Sem inspeção ainda (404), instantâneo inexistente, sem permissão ou falha de rede, cada um com seu próximo passo. */
function QueryProblem({
  error,
  runId,
  retry,
  inspectAction,
}: {
  error: Error;
  runId: string | undefined;
  retry: () => void;
  inspectAction: ReactNode;
}) {
  const { t } = useTranslation();
  const [params] = useSearchParams();
  const apiErr = error instanceof ApiError ? error : undefined;
  if (apiErr?.status === 404 && !runId) {
    return (
      <EmptyState
        icon={Cpu}
        title={t("inventory.noSnapshotTitle")}
        description={
          <>
            <p className="m-0">{t("inventory.noSnapshotDescription")}</p>
            {!inspectAction && <p className="m-0 mt-2">{t("inventory.noSnapshotAskOperator")}</p>}
          </>
        }
        action={inspectAction || undefined}
      />
    );
  }
  if (apiErr?.status === 404 && runId) {
    return (
      <EmptyState
        icon={SearchX}
        title={t("inventory.runNotFoundTitle")}
        description={t("inventory.runNotFoundDescription", { id: runId })}
        action={
          <Link to={params.get("aba") === "persistencia" ? "/processos?aba=persistencia" : "/processos"} className="inline-flex min-h-11 items-center font-semibold text-accent underline underline-offset-4">
            {t("inventory.viewLatest")}
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
      title={t("inventory.loadErrorTitle")}
      description={<div role="alert">{t("inventory.loadErrorDescription", { cause: error.message })}</div>}
      action={
        <Button variant="primary" onClick={retry}>
          <RefreshCw aria-hidden="true" className="size-4" />
          {t("states.retry")}
        </Button>
      }
    />
  );
}

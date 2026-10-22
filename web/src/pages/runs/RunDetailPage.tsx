import { useQuery, useQueryClient } from "@tanstack/react-query";
import { ArrowLeft, Ban, CircleAlert, FileQuestion, Pause, Play, RefreshCw, ScanSearch, SlidersHorizontal, TriangleAlert } from "lucide-react";
import { useState, type FormEvent, type ReactNode } from "react";
import { useTranslation } from "react-i18next";
import { Link, useParams } from "react-router";
import { api, ApiError, unwrap, type Schemas } from "../../api/client";
import { useCurrentUser } from "../../auth/session";
import { Button } from "../../components/Button";
import { ConfirmDialog } from "../../components/ConfirmDialog";
import { EmptyState } from "../../components/EmptyState";
import { FormError, SelectField } from "../../components/Field";
import { Panel } from "../../components/Panel";
import { PathText } from "../../components/PathText";
import { Timestamp } from "../../components/Timestamp";
import { PageHeader } from "../../layout/PageHeader";
import { formatNumber, formatPercent } from "../../lib/format";
import { DurationText, KindLabel, OriginText, PhaseText, RunStatus, useProfileLabel, useProfileSummary } from "./RunBits";
import { EngineCoverageCard, SkipReasonTable } from "./RunCoverage";
import { resourcesQuery, runQuery } from "./queries";
import { formatBytes, isActive, runActions, skipEntries, toDate, type Run } from "./runFormat";

type RunDetail = Schemas["RunDetail"];

/** Endereço da lista de achados filtrada por esta execução (combinado com a frente de achados). */
export function runFindingsHref(runId: string): string {
  return `/achados?${new URLSearchParams({ run_id: runId }).toString()}`;
}

/** Detalhe da execução (rota /execucoes/:runId): progresso, cobertura por motor, avisos e ações. */
export function RunDetailPage() {
  const { t } = useTranslation();
  const { runId = "" } = useParams();
  const detail = useQuery(runQuery(runId));

  if (detail.isPending) {
    return (
      <>
        <PageHeader title={t("runs.detail.title", { id: runId })} actions={<BackLink />} />
        <p className="m-0 text-ink-muted" role="status">
          {t("states.loading")}
        </p>
      </>
    );
  }

  if (detail.isError) {
    const notFound = detail.error instanceof ApiError && detail.error.status === 404;
    return (
      <>
        <PageHeader title={t("runs.detail.title", { id: runId })} actions={<BackLink />} />
        {notFound ? (
          <EmptyState
            icon={FileQuestion}
            title={t("runs.detail.notFoundTitle")}
            description={t("runs.detail.notFoundDescription", { id: runId })}
            action={<BackLink />}
          />
        ) : (
          <EmptyState
            tone="error"
            icon={CircleAlert}
            title={t("runs.detail.loadError")}
            description={detail.error.message}
            action={
              <Button onClick={() => void detail.refetch()} disabled={detail.isFetching}>
                <RefreshCw aria-hidden="true" className="size-4" />
                {t("states.retry")}
              </Button>
            }
          />
        )}
      </>
    );
  }

  return <RunDetailView detail={detail.data} />;
}

function BackLink() {
  const { t } = useTranslation();
  return (
    <Link to="/execucoes" className="inline-flex min-h-11 items-center gap-2 font-semibold">
      <ArrowLeft aria-hidden="true" className="size-4" />
      {t("runs.detail.back")}
    </Link>
  );
}

function RunDetailView({ detail }: { detail: RunDetail }) {
  const { t } = useTranslation();
  const { canOperate } = useCurrentUser();
  const { run, engines } = detail;
  const active = isActive(run.status);
  const errorText = run.error || run.summary?.error;
  const warnings = run.summary?.warnings ?? [];

  return (
    <>
      <PageHeader
        title={t("runs.detail.title", { id: run.id })}
        subtitle={
          <span className="mt-1 flex flex-wrap items-center gap-x-3 gap-y-1">
            <RunStatus run={run} />
            <KindLabel kind={run.kind} />
          </span>
        }
        actions={<BackLink />}
      />
      <div className="flex flex-col gap-6">
        {run.paused && run.status === "running" && (
          <p role="status" className="m-0 flex items-center gap-2 rounded-control border border-(--vh-medium-fg) bg-(--vh-medium-bg) p-3 text-(--vh-medium-fg)">
            <Pause aria-hidden="true" className="size-4 shrink-0" />
            {t("runs.detail.pausedNote")}
          </p>
        )}
        {errorText && (
          <div className="flex gap-2 rounded-control border border-(--vh-critical-fg) bg-(--vh-critical-bg) p-3 text-(--vh-critical-fg)">
            <CircleAlert aria-hidden="true" className="mt-0.5 size-4 shrink-0" />
            <div className="min-w-0">
              <h2 className="m-0 text-base font-bold">{t("runs.detail.error")}</h2>
              <p className="m-0 [overflow-wrap:anywhere]">{errorText}</p>
            </div>
          </div>
        )}

        <div className="grid items-start gap-6 xl:grid-cols-2">
          <ProgressPanel run={run} />
          {canOperate && active ? <ActionsPanel run={run} /> : <DetailsPanel run={run} />}
        </div>
        {canOperate && active && <DetailsPanel run={run} />}

        {warnings.length > 0 && (
          <Panel title={t("runs.detail.warnings")}>
            <ul className="m-0 flex list-none flex-col gap-2 p-0">
              {warnings.map((w, i) => (
                <li key={i} className="flex gap-2">
                  <TriangleAlert aria-hidden="true" className="mt-0.5 size-4 shrink-0 text-(--vh-high-fg)" />
                  <span className="min-w-0 [overflow-wrap:anywhere]">{w}</span>
                </li>
              ))}
            </ul>
          </Panel>
        )}

        <Panel title={t("runs.detail.engines")}>
          {engines.length === 0 ? (
            <p className="m-0 text-ink-muted">{active ? t("runs.detail.enginesEmptyActive") : t("runs.detail.enginesEmpty")}</p>
          ) : (
            <div className="grid items-start gap-4 lg:grid-cols-2">
              {engines.map((e) => (
                <EngineCoverageCard key={e.engine} engine={e} />
              ))}
            </div>
          )}
        </Panel>

        {skipEntries(run.summary?.skipped).length > 0 && (
          <Panel title={t("runs.detail.walkSkipped")}>
            <p className="m-0 text-sm text-ink-muted">{t("runs.detail.walkSkippedHint")}</p>
            <SkipReasonTable skipped={run.summary?.skipped} />
          </Panel>
        )}

        {run.kind === "files" && <PathsPanel run={run} />}
      </div>
    </>
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

function ProgressPanel({ run }: { run: Run }) {
  const { t, i18n } = useTranslation();
  const lng = i18n.language;
  const files = run.kind === "files";
  const n = (v: number) => <span className="tabular-nums">{formatNumber(v, lng)}</span>;
  const ratio = run.files_eligible > 0 ? Math.min(1, run.files_processed / run.files_eligible) : 0;
  return (
    <Panel title={t("runs.detail.progress")}>
      {isActive(run.status) && run.files_eligible > 0 && (
        <div className="flex flex-col gap-1.5">
          <p className="m-0 text-lg font-bold tabular-nums">
            {t("runs.detail.percentDone", { percent: formatPercent(run.files_processed, run.files_eligible, lng) })}
          </p>
          <div aria-hidden="true" className="h-2 overflow-clip rounded-full bg-sunken outline outline-1 -outline-offset-1 outline-line">
            <div className="vh-meter-fill h-full rounded-full bg-accent" style={{ inlineSize: `${ratio * 100}%` }} />
          </div>
        </div>
      )}
      <dl className="m-0 grid gap-4 sm:grid-cols-2">
        <Item label={t("runs.detail.phase")}>
          <PhaseText phase={run.phase} />
        </Item>
        <Item label={files ? t("runs.detail.filesSeen") : t("runs.detail.processesSeen")}>{n(run.files_seen)}</Item>
        <Item label={files ? t("runs.detail.filesEligible") : t("runs.detail.targetsEligible")}>{n(run.files_eligible)}</Item>
        <Item label={files ? t("runs.detail.filesProcessed") : t("runs.detail.targetsProcessed")}>{n(run.files_processed)}</Item>
        {files && (
          <Item label={t("runs.detail.bytes")}>
            <span className="tabular-nums">
              {t("runs.detail.bytesOf", {
                processed: formatBytes(run.bytes_processed, lng),
                eligible: formatBytes(run.bytes_eligible, lng),
              })}
            </span>
          </Item>
        )}
        <Item label={t("runs.detail.findings")}>{n(run.findings_count)}</Item>
      </dl>
      <Link to={runFindingsHref(run.id)} className="inline-flex min-h-11 items-center gap-2 self-start font-semibold">
        <ScanSearch aria-hidden="true" className="size-4" />
        {t("runs.detail.viewFindings")}
      </Link>
    </Panel>
  );
}

function DetailsPanel({ run }: { run: Run }) {
  const { t } = useTranslation();
  const profileLabel = useProfileLabel();
  const profileSummary = useProfileSummary();
  const created = toDate(run.created_at);
  const started = toDate(run.started_at);
  const finished = toDate(run.finished_at);
  const scheduled = toDate(run.scheduled_for);
  const none = <span className="font-normal text-ink-muted">{t("runs.none")}</span>;
  return (
    <Panel title={t("runs.detail.details")}>
      <dl className="m-0 grid gap-4 sm:grid-cols-2">
        <Item label={t("runs.origin.label")}>
          <OriginText run={run} />
        </Item>
        {scheduled && (
          <Item label={t("runs.detail.scheduledFor")}>
            <Timestamp date={scheduled} />
          </Item>
        )}
        <Item label={t("runs.detail.created")}>{created ? <Timestamp date={created} /> : none}</Item>
        <Item label={t("runs.detail.started")}>{started ? <Timestamp date={started} /> : none}</Item>
        <Item label={t("runs.detail.finished")}>{finished ? <Timestamp date={finished} /> : none}</Item>
        <Item label={t("runs.detail.duration")}>
          <DurationText run={run} />
        </Item>
        <Item label={t("runs.detail.profile")}>
          {profileLabel(run.profile.name)}
          <span className="block text-sm font-normal text-ink-muted">{profileSummary(run.profile)}</span>
        </Item>
        {run.kind === "files" && (
          <Item label={t("runs.detail.mode")}>{run.incremental ? t("runs.detail.incrementalYes") : t("runs.detail.incrementalNo")}</Item>
        )}
        {run.attempts > 1 && <Item label={t("runs.detail.attempts")}>{run.attempts}</Item>}
      </dl>
    </Panel>
  );
}

function PathsPanel({ run }: { run: Run }) {
  const { t } = useTranslation();
  return (
    <Panel title={t("runs.detail.paths")}>
      <ul className="m-0 flex list-none flex-col gap-1 p-0">
        {run.paths.map((p) => (
          <li key={p} className="min-w-0">
            <PathText path={p} />
          </li>
        ))}
      </ul>
      <div className="flex flex-col gap-1">
        <h3 className="m-0 text-base font-semibold">{t("runs.detail.exclude")}</h3>
        {run.exclude.length === 0 ? (
          <p className="m-0 text-ink-muted">{t("runs.detail.noExclude")}</p>
        ) : (
          <ul className="m-0 flex list-none flex-col gap-1 p-0">
            {run.exclude.map((p) => (
              <li key={p} className="min-w-0">
                <PathText path={p} />
              </li>
            ))}
          </ul>
        )}
      </div>
    </Panel>
  );
}

type ActionInput = { action: "pause" | "resume" | "cancel" } | { action: "limits"; profile: string };

function callAction(runId: string, input: ActionInput) {
  const path = { params: { path: { runId } } };
  switch (input.action) {
    case "pause":
      return unwrap(api.POST("/api/v1/runs/{runId}/pause", path));
    case "resume":
      return unwrap(api.POST("/api/v1/runs/{runId}/resume", path));
    case "cancel":
      return unwrap(api.POST("/api/v1/runs/{runId}/cancel", path));
    case "limits":
      return unwrap(api.POST("/api/v1/runs/{runId}/limits", { ...path, body: { profile: input.profile } }));
  }
}

/** Pausar/retomar, trocar o perfil de limites e cancelar, conforme o estado atual da execução. */
function ActionsPanel({ run }: { run: Run }) {
  const { t } = useTranslation();
  const qc = useQueryClient();
  const profileLabel = useProfileLabel();
  const resources = useQuery(resourcesQuery);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState("");
  const [confirmCancel, setConfirmCancel] = useState(false);
  const actions = runActions(run);
  const freezer = resources.data?.hardware?.freezer;

  async function run_(input: ActionInput) {
    const updated = await callAction(run.id, input);
    qc.setQueryData<RunDetail>(["run", run.id], (old) => (old ? { ...old, run: updated } : old));
    void qc.invalidateQueries({ queryKey: ["run", run.id] });
    void qc.invalidateQueries({ queryKey: ["runs"] });
    void qc.invalidateQueries({ queryKey: ["overview"] });
    return updated;
  }

  async function act(input: ActionInput) {
    setBusy(true);
    setError(null);
    setNotice("");
    try {
      const updated = await run_(input);
      if (input.action === "limits") setNotice(t("runs.detail.limitsApplied", { name: profileLabel(updated.profile.name) }));
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setBusy(false);
    }
  }

  function submitLimits(e: FormEvent<HTMLFormElement>) {
    e.preventDefault();
    const profile = String(new FormData(e.currentTarget).get("profile") ?? "");
    if (profile) void act({ action: "limits", profile });
  }

  const profileNames = resources.data?.profiles.map((p) => p.profile.name) ?? [];
  if (!profileNames.includes(run.profile.name)) profileNames.unshift(run.profile.name);

  return (
    <Panel title={t("runs.detail.actions")}>
      <div className="flex flex-wrap gap-2">
        {actions.includes("pause") && (
          <Button onClick={() => void act({ action: "pause" })} disabled={busy || freezer === false}>
            <Pause aria-hidden="true" className="size-4" />
            {t("runs.detail.pause")}
          </Button>
        )}
        {actions.includes("resume") && (
          <Button variant="primary" onClick={() => void act({ action: "resume" })} disabled={busy}>
            <Play aria-hidden="true" className="size-4" />
            {t("runs.detail.resume")}
          </Button>
        )}
        {actions.includes("cancel") && (
          <Button variant="danger" onClick={() => setConfirmCancel(true)} disabled={busy}>
            <Ban aria-hidden="true" className="size-4" />
            {t("runs.detail.cancel")}
          </Button>
        )}
      </div>
      {actions.includes("pause") && freezer === false && <p className="m-0 text-sm text-ink-muted">{t("runs.detail.pauseUnavailable")}</p>}

      {actions.includes("limits") && (
        <form onSubmit={submitLimits} className="flex flex-wrap items-end gap-2">
          <SelectField
            key={run.profile.name}
            label={t("runs.detail.limits")}
            hint={t("runs.detail.limitsHint")}
            name="profile"
            className="min-w-0 flex-1 basis-56"
            defaultValue={run.profile.name}
            options={profileNames.map((name) => ({ value: name, label: profileLabel(name) }))}
          />
          <Button type="submit" disabled={busy}>
            <SlidersHorizontal aria-hidden="true" className="size-4" />
            {t("runs.detail.applyLimits")}
          </Button>
        </form>
      )}

      <FormError message={error} />
      <p role="status" className={notice ? "m-0 text-sm text-(--vh-ok-fg)" : "visually-hidden"}>
        {notice}
      </p>

      <ConfirmDialog
        open={confirmCancel}
        onClose={() => setConfirmCancel(false)}
        onConfirm={async () => {
          await run_({ action: "cancel" });
        }}
        title={t("runs.detail.cancelTitle")}
        object={<span className="font-mono [overflow-wrap:anywhere]">{run.id}</span>}
        impact={run.status === "running" ? t("runs.detail.cancelImpact") : t("runs.detail.cancelQueuedImpact")}
        reversible={false}
        destructive={false}
        confirmLabel={t("runs.detail.cancelConfirm")}
      />
    </Panel>
  );
}

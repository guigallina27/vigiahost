import { useQuery } from "@tanstack/react-query";
import { CircleCheck, CircleX, Play, PlugZap, RefreshCw, TriangleAlert } from "lucide-react";
import { useState, type ReactNode } from "react";
import { useTranslation } from "react-i18next";
import { healthQuery, type Health } from "../api/client";
import { useCurrentUser } from "../auth/session";
import { Badge } from "../components/Badge";
import { Button } from "../components/Button";
import { EmptyState } from "../components/EmptyState";
import { Panel } from "../components/Panel";
import { Timestamp } from "../components/Timestamp";
import { PageHeader } from "../layout/PageHeader";
import { NewRunDialog } from "./runs/NewRunDialog";
import { OverviewSummary } from "./runs/OverviewSummary";

export function OverviewPage() {
  const { t } = useTranslation();
  const health = useQuery(healthQuery);
  const { canOperate } = useCurrentUser();
  const [dialogOpen, setDialogOpen] = useState(false);
  const openDialog = () => setDialogOpen(true);

  return (
    <>
      <PageHeader
        title={t("overview.title")}
        subtitle={t("runs.overview.subtitle")}
        actions={
          <div className="flex flex-wrap items-center gap-3">
            {health.data && (
              <span className="text-sm text-ink-muted">
                {t("overview.updatedAt")} <Timestamp date={new Date(health.dataUpdatedAt)} compact />
              </span>
            )}
            {canOperate && (
              <Button variant="primary" onClick={openDialog}>
                <Play aria-hidden="true" className="size-4" />
                {t("runs.newRun")}
              </Button>
            )}
          </div>
        }
      />

      {health.isPending ? (
        <p className="text-ink-muted">{t("states.loading")}</p>
      ) : health.data ? (
        <div className="flex flex-col gap-6">
          {health.isError && (
            <p role="status" className="m-0 flex items-center gap-2 rounded-control border border-(--vh-medium-fg) bg-(--vh-medium-bg) p-3 text-(--vh-medium-fg)">
              <TriangleAlert aria-hidden="true" className="size-4 shrink-0" />
              {t("overview.staleWarning")}
            </p>
          )}
          <OverviewSummary canOperate={canOperate} onNewRun={openDialog} />
          <div className="grid items-start gap-6 xl:grid-cols-2">
            <ServicePanel health={health.data} />
            <SystemPanel health={health.data} />
          </div>
        </div>
      ) : (
        <EmptyState
          tone="error"
          icon={PlugZap}
          title={t("overview.unreachableTitle")}
          description={
            <>
              <p className="m-0">{t("overview.unreachableDescription", { cause: health.error.message })}</p>
              <p className="m-0 mt-2">
                <Command text={t("overview.unreachableAction", { command: "\u0000" })} command="systemctl status vigiahost-core" />
              </p>
            </>
          }
          action={
            <Button variant="primary" onClick={() => void health.refetch()} disabled={health.isFetching}>
              <RefreshCw aria-hidden="true" className="size-4" />
              {t("states.retry")}
            </Button>
          }
        />
      )}
      <NewRunDialog open={dialogOpen} onClose={() => setDialogOpen(false)} />
    </>
  );
}

/** Insere o comando, em <code>, no ponto marcado do texto traduzido. */
function Command({ text, command }: { text: string; command: string }) {
  const [before, after] = text.split("\u0000");
  return (
    <>
      {before}
      <code className="rounded-sm bg-sunken px-1 py-0.5">{command}</code>
      {after}
    </>
  );
}

function Field({ label, children }: { label: string; children: ReactNode }) {
  return (
    <div className="grid min-w-0 gap-0.5">
      <dt className="text-sm text-ink-muted">{label}</dt>
      <dd className="m-0 min-w-0 font-semibold break-words">{children}</dd>
    </div>
  );
}

function ServicePanel({ health }: { health: Health }) {
  const { t } = useTranslation();
  const ex = health.executor;
  return (
    <Panel title={t("overview.service")}>
      <div className="flex flex-wrap items-center gap-3">
        <span className="font-semibold">{t("overview.executor")}</span>
        {ex.connected ? (
          <Badge tone="ok" icon={CircleCheck}>
            {t("engineHealth.operational")}
          </Badge>
        ) : (
          <Badge tone="critical" icon={CircleX}>
            {t("engineHealth.unavailable")}
          </Badge>
        )}
      </div>
      {!ex.connected && (
        <div className="rounded-control border border-(--vh-critical-fg) bg-(--vh-critical-bg) p-3 text-sm">
          <p className="m-0">{t("overview.executorDown")}</p>
          {ex.error && <p className="m-0 mt-1 font-mono text-[0.8125rem] [overflow-wrap:anywhere]">{ex.error}</p>}
          <p className="m-0 mt-2">
            <Command text={t("overview.executorDownAction", { command: "\u0000" })} command="systemctl status vigiahost-executor" />
          </p>
        </div>
      )}
      <dl className="m-0 grid gap-4 sm:grid-cols-3">
        <Field label={t("overview.coreVersion")}>
          <span className="font-mono">{health.version}</span>
        </Field>
        <Field label={t("overview.executorVersion")}>
          <span className="font-mono">{ex.version ?? "—"}</span>
        </Field>
        <Field label={t("overview.protocol")}>
          <span className="font-mono">{ex.protocol ?? "—"}</span>
        </Field>
      </dl>
    </Panel>
  );
}

function SystemPanel({ health }: { health: Health }) {
  const { t } = useTranslation();
  const sys = health.executor.system;
  if (!sys) {
    return (
      <Panel title={t("overview.system")}>
        <p className="m-0 text-ink-muted">{t("overview.noSystem")}</p>
      </Panel>
    );
  }
  const caps = [
    { ok: sys.systemd, label: t("overview.capSystemd"), off: t("overview.capSystemdOff") },
    { ok: sys.cgroup_v2, label: t("overview.capCgroup"), off: t("overview.capCgroupOff") },
    { ok: sys.psi, label: t("overview.capPsi"), off: t("overview.capPsiOff") },
  ];
  return (
    <Panel title={t("overview.system")}>
      <dl className="m-0 grid gap-4 sm:grid-cols-3">
        <Field label={t("overview.distro")}>{sys.distro_name || sys.distro_id}</Field>
        <Field label={t("overview.kernel")}>
          <span className="font-mono">{sys.kernel}</span>
        </Field>
        <Field label={t("overview.arch")}>
          <span className="font-mono">{sys.arch}</span>
        </Field>
      </dl>
      <div>
        <h3 className="m-0 mb-2 text-base font-semibold">{t("overview.capabilities")}</h3>
        <ul className="m-0 flex list-none flex-col gap-2 p-0">
          {caps.map((c) => (
            <li key={c.label} className="flex flex-wrap items-start gap-x-3 gap-y-1">
              {c.ok ? (
                <Badge tone="ok" icon={CircleCheck}>
                  {t("overview.available")}
                </Badge>
              ) : (
                <Badge tone="high" icon={TriangleAlert}>
                  {t("overview.missing")}
                </Badge>
              )}
              <span className="min-w-0 flex-1">
                <span className="font-semibold">{c.label}</span>
                {!c.ok && <span className="block text-sm text-ink-muted">{c.off}</span>}
              </span>
            </li>
          ))}
        </ul>
      </div>
    </Panel>
  );
}

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { CalendarCheck, CalendarClock, CalendarPlus, CirclePause, Pencil, PlugZap, RefreshCw, Trash2 } from "lucide-react";
import { useState, type ReactNode } from "react";
import { useTranslation } from "react-i18next";
import { api, ApiError, unwrap } from "../../api/client";
import { useCurrentUser } from "../../auth/session";
import { Badge } from "../../components/Badge";
import { Button } from "../../components/Button";
import { ConfirmDialog } from "../../components/ConfirmDialog";
import { EmptyState } from "../../components/EmptyState";
import { PathText } from "../../components/PathText";
import { Timestamp } from "../../components/Timestamp";
import { PageHeader } from "../../layout/PageHeader";
import { cronToText } from "./cronText";
import { profileLabel, retryTransient, schedulesQuery, zoneProp } from "./queries";
import { ScheduleForm } from "./ScheduleForm";
import { emptyScheduleValues, valuesFromSchedule, type Schedule } from "./schedules";
import { useGuardedAction } from "./useGuardedAction";

type Editing = { mode: "new" } | { mode: "edit"; schedule: Schedule } | null;

/** Agendamentos de varredura e de inspeção (rota sugerida: /agendamentos). */
export function SchedulesPage() {
  const { t } = useTranslation();
  const { canOperate } = useCurrentUser();
  const list = useQuery({ ...schedulesQuery, retry: retryTransient });
  const [editing, setEditing] = useState<Editing>(null);
  const [deleting, setDeleting] = useState<Schedule | null>(null);
  const [notice, setNotice] = useState<string | null>(null);

  const createButton = canOperate && !editing && (
    <Button
      variant="primary"
      onClick={() => {
        setNotice(null);
        setEditing({ mode: "new" });
      }}
    >
      <CalendarPlus aria-hidden="true" className="size-4" />
      {t("config.schedules.new")}
    </Button>
  );

  return (
    <>
      <PageHeader title={t("config.schedules.title")} subtitle={t("config.schedules.subtitle")} actions={createButton} />
      <div className="flex min-w-0 flex-col gap-6">
        <p role="status" className={notice ? "m-0 rounded-control border border-line-strong bg-accent-soft p-3" : "visually-hidden"}>
          {notice}
        </p>

        {editing && (
          <ScheduleForm
            key={editing.mode === "edit" ? editing.schedule.id : "new"}
            {...(editing.mode === "edit" ? { editing: editing.schedule } : {})}
            initial={editing.mode === "edit" ? valuesFromSchedule(editing.schedule) : emptyScheduleValues()}
            onCancel={() => setEditing(null)}
            onDone={(saved) => {
              setEditing(null);
              setNotice(t(editing.mode === "edit" ? "config.schedules.saved" : "config.schedules.created", { name: saved.name }));
            }}
          />
        )}

        {list.isPending ? (
          <p role="status" className="m-0 text-ink-muted">
            {t("states.loading")}
          </p>
        ) : list.isError ? (
          <EmptyState
            tone="error"
            icon={PlugZap}
            title={t("config.loadErrorTitle")}
            description={<div role="alert">{list.error.message}</div>}
            action={
              <Button variant="primary" onClick={() => void list.refetch()}>
                <RefreshCw aria-hidden="true" className="size-4" />
                {t("states.retry")}
              </Button>
            }
          />
        ) : list.data.length === 0 ? (
          !editing && (
            <EmptyState
              icon={CalendarClock}
              title={t("config.schedules.emptyTitle")}
              description={canOperate ? t("config.schedules.emptyDescription") : t("config.schedules.emptyReader")}
              action={createButton || undefined}
            />
          )
        ) : (
          <ul className="m-0 grid list-none gap-4 p-0 xl:grid-cols-2">
            {list.data.map((s) => (
              <li key={s.id} className="min-w-0">
                <ScheduleCard
                  schedule={s}
                  canOperate={canOperate}
                  onEdit={() => {
                    setNotice(null);
                    setEditing({ mode: "edit", schedule: s });
                  }}
                  onDelete={() => setDeleting(s)}
                />
              </li>
            ))}
          </ul>
        )}
      </div>

      <DeleteScheduleDialog
        schedule={deleting}
        onClose={() => setDeleting(null)}
        onDeleted={(name) => {
          if (editing?.mode === "edit" && editing.schedule.id === deleting?.id) setEditing(null);
          setNotice(t("config.schedules.deleted", { name }));
        }}
      />
    </>
  );
}

export default SchedulesPage;

function Info({ label, children }: { label: string; children: ReactNode }) {
  return (
    <div className="grid min-w-0 gap-0.5">
      <dt className="text-sm text-ink-muted">{label}</dt>
      <dd className="m-0 min-w-0 break-words">{children}</dd>
    </div>
  );
}

function ScheduleCard({
  schedule: s,
  canOperate,
  onEdit,
  onDelete,
}: {
  schedule: Schedule;
  canOperate: boolean;
  onEdit: () => void;
  onDelete: () => void;
}) {
  const { t, i18n } = useTranslation();
  const zone = zoneProp(s.timezone);
  return (
    <article className="flex h-full min-w-0 flex-col gap-4 rounded-panel border border-line bg-surface p-5 shadow-panel">
      <div className="flex flex-wrap items-start justify-between gap-2">
        <h2 className="m-0 min-w-0 text-lg font-bold [overflow-wrap:anywhere]">{s.name}</h2>
        {s.enabled ? (
          <Badge tone="low" icon={CalendarCheck} variant="outline">
            {t("config.schedules.active")}
          </Badge>
        ) : (
          <Badge tone="neutral" icon={CirclePause} variant="outline">
            {t("config.schedules.paused")}
          </Badge>
        )}
      </div>

      <div className="flex flex-col gap-1">
        <p className="m-0 font-semibold">{cronToText(s.cron, t, i18n.language)}</p>
        <p className="m-0 text-sm text-ink-muted">
          <code>{s.cron}</code> · {t("config.schedules.inZone", { zone: s.timezone })}
        </p>
      </div>

      <dl className="m-0 grid gap-3 sm:grid-cols-2">
        <Info label={t("config.schedules.kind")}>{t(`config.kinds.${s.kind}`)}</Info>
        <Info label={t("config.schedules.profile")}>{profileLabel(s.profile, t)}</Info>
        <Info label={t("config.schedules.missedPolicy")}>{t(s.missed_policy === "skip" ? "config.missed.skip" : "config.missed.run_once")}</Info>
        <Info label={t("config.schedules.lastRun")}>
          {s.last_run_at ? <Timestamp date={new Date(s.last_run_at)} {...zone} compact /> : t("config.schedules.never")}
        </Info>
        {s.kind === "files" && (
          <>
            {(s.accounts?.all || (s.accounts?.uids?.length ?? 0) > 0) && (
              <Info label={t("accounts.picker.legend")}>
                {s.accounts?.all
                  ? t("accounts.picker.summaryAll")
                  : t("accounts.picker.summarySelected", { count: s.accounts?.uids?.length ?? 0 })}
              </Info>
            )}
            <Info label={t("config.schedules.paths")}>
              <ul className="m-0 flex list-none flex-col gap-0.5 p-0">
                {s.paths.map((p) => (
                  <li key={p}>
                    <PathText path={p} />
                  </li>
                ))}
              </ul>
            </Info>
            <Info label={t("config.schedules.exclude")}>
              {s.exclude.length === 0 ? (
                t("config.schedules.noExclude")
              ) : (
                <ul className="m-0 flex list-none flex-col gap-0.5 p-0">
                  {s.exclude.map((p) => (
                    <li key={p}>
                      <PathText path={p} />
                    </li>
                  ))}
                </ul>
              )}
            </Info>
            <Info label={t("config.schedules.incremental")}>{t(s.incremental ? "config.yes" : "config.no")}</Info>
          </>
        )}
      </dl>

      <div className="flex flex-col gap-1">
        <h3 className="m-0 text-sm font-semibold text-ink-muted">{t("config.schedules.nextRuns")}</h3>
        {!s.enabled ? (
          <p className="m-0 text-sm text-ink-muted">{t("config.schedules.pausedHint")}</p>
        ) : s.upcoming.length === 0 ? (
          <p className="m-0 text-sm text-ink-muted">{t("config.schedules.previewEmpty")}</p>
        ) : (
          <ol className="m-0 flex flex-col gap-1 pl-5">
            {s.upcoming.map((d) => (
              <li key={d}>
                <Timestamp date={new Date(d)} {...zone} compact />
              </li>
            ))}
          </ol>
        )}
      </div>

      <p className="m-0 text-sm text-ink-muted">
        {t("config.schedules.createdBy", { who: s.created_by })} · <Timestamp date={new Date(s.updated_at)} compact />
      </p>

      {canOperate && (
        <div className="mt-auto flex flex-wrap gap-2">
          <Button variant="secondary" onClick={onEdit}>
            <Pencil aria-hidden="true" className="size-4" />
            {t("config.schedules.edit")}
            <span className="visually-hidden">: {s.name}</span>
          </Button>
          <Button variant="ghost" onClick={onDelete}>
            <Trash2 aria-hidden="true" className="size-4" />
            {t("config.schedules.delete")}
            <span className="visually-hidden">: {s.name}</span>
          </Button>
        </div>
      )}
    </article>
  );
}

function DeleteScheduleDialog({
  schedule,
  onClose,
  onDeleted,
}: {
  schedule: Schedule | null;
  onClose: () => void;
  onDeleted: (name: string) => void;
}) {
  const { t, i18n } = useTranslation();
  const qc = useQueryClient();
  const guarded = useGuardedAction(false);
  const remove = useMutation({
    mutationFn: (id: number) => unwrap(api.DELETE("/api/v1/schedules/{id}", { params: { path: { id } } })),
  });

  return (
    <ConfirmDialog
      open={schedule !== null}
      onClose={() => {
        guarded.reset();
        onClose();
      }}
      onConfirm={async (input) => {
        if (!schedule) return;
        try {
          await guarded.run(input, () => remove.mutateAsync(schedule.id));
        } catch (err) {
          // Já removido por outra pessoa: o objetivo foi alcançado.
          if (!(err instanceof ApiError && err.status === 404)) throw err;
        }
        void qc.invalidateQueries({ queryKey: ["schedules"] });
        void qc.invalidateQueries({ queryKey: ["overview"] });
        onDeleted(schedule.name);
      }}
      title={t("config.schedules.deleteTitle")}
      object={
        schedule && (
          <span className="flex flex-col gap-1">
            <strong className="[overflow-wrap:anywhere]">{schedule.name}</strong>
            <span>{cronToText(schedule.cron, t, i18n.language)}</span>
          </span>
        )
      }
      impact={t("config.schedules.deleteImpact")}
      reversible={false}
      requireReauth={guarded.requireReauth}
      requireCode={guarded.requireCode}
      confirmLabel={t("config.schedules.deleteConfirm")}
    />
  );
}

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Gauge, Pencil, PlugZap, Plus, RefreshCw, RotateCcw, Trash2, TriangleAlert, UserPen } from "lucide-react";
import { useState, type ReactNode } from "react";
import { useTranslation } from "react-i18next";
import { api, unwrap, type Schemas } from "../../api/client";
import { useCurrentUser } from "../../auth/session";
import { Badge } from "../../components/Badge";
import { Button } from "../../components/Button";
import { ConfirmDialog } from "../../components/ConfirmDialog";
import { EmptyState } from "../../components/EmptyState";
import { Panel } from "../../components/Panel";
import { formatNumber } from "../../lib/format";
import { PageHeader } from "../../layout/PageHeader";
import { ProfileForm } from "./ProfileForm";
import { profileLabel, resourcesQuery, retryTransient } from "./queries";
import { newProfileValues, valuesFromProfile, type ProfileEntry, type ResourceProfile } from "./resources";
import { formatBytes, splitDuration } from "./units";
import { useGuardedAction } from "./useGuardedAction";

type Editing = { mode: "new" } | { mode: "edit"; profile: ResourceProfile } | null;

/** Hardware detectado e perfis de recursos das execuções (rota sugerida: /recursos). */
export function ResourcesPage() {
  const { t } = useTranslation();
  const { isAdmin } = useCurrentUser();
  const q = useQuery({ ...resourcesQuery, retry: retryTransient });
  const [editing, setEditing] = useState<Editing>(null);
  const [removing, setRemoving] = useState<ProfileEntry | null>(null);
  const [notice, setNotice] = useState<string | null>(null);

  const profiles = q.data?.profiles ?? [];
  const names = profiles.map((p) => p.profile.name);

  const createButton = isAdmin && q.data && !editing && (
    <Button
      variant="primary"
      onClick={() => {
        setNotice(null);
        setEditing({ mode: "new" });
      }}
    >
      <Plus aria-hidden="true" className="size-4" />
      {t("config.resources.new")}
    </Button>
  );

  return (
    <>
      <PageHeader title={t("config.resources.title")} subtitle={t("config.resources.subtitle")} actions={createButton} />
      {q.isPending ? (
        <p role="status" className="m-0 text-ink-muted">
          {t("states.loading")}
        </p>
      ) : q.isError ? (
        <EmptyState
          tone="error"
          icon={PlugZap}
          title={t("config.loadErrorTitle")}
          description={<div role="alert">{q.error.message}</div>}
          action={
            <Button variant="primary" onClick={() => void q.refetch()}>
              <RefreshCw aria-hidden="true" className="size-4" />
              {t("states.retry")}
            </Button>
          }
        />
      ) : (
        <div className="flex min-w-0 flex-col gap-6">
          <p role="status" className={notice ? "m-0 rounded-control border border-line-strong bg-accent-soft p-3" : "visually-hidden"}>
            {notice}
          </p>
          <HardwarePanel hardware={q.data.hardware} executorError={q.data.executor_error} />

          {editing && (
            <ProfileForm
              key={editing.mode === "edit" ? editing.profile.name : "new"}
              {...(editing.mode === "edit" ? { editingName: editing.profile.name } : {})}
              initial={
                editing.mode === "edit"
                  ? valuesFromProfile(editing.profile)
                  : newProfileValues(profiles.find((p) => p.profile.name === "padrao")?.profile)
              }
              hardware={q.data.hardware}
              existingNames={names}
              onCancel={() => setEditing(null)}
              onDone={(name) => {
                setEditing(null);
                setNotice(t("config.resources.saved", { name: profileLabel(name, t) }));
              }}
            />
          )}

          <section className="flex min-w-0 flex-col gap-3" aria-labelledby="perfis-titulo">
            <h2 id="perfis-titulo" className="m-0 text-xl font-bold">
              {t("config.resources.profilesTitle")}
            </h2>
            <p className="m-0 max-w-prose text-ink-muted">{t("config.resources.profilesIntro")}</p>
            {profiles.length === 0 ? (
              <EmptyState icon={Gauge} headingLevel={3} title={t("config.resources.emptyTitle")} description={t("config.resources.emptyDescription")} />
            ) : (
              <ul className="m-0 grid list-none gap-4 p-0 lg:grid-cols-2 2xl:grid-cols-3">
                {profiles.map((entry) => (
                  <li key={entry.profile.name} className="min-w-0">
                    <ProfileCard
                      entry={entry}
                      isAdmin={isAdmin}
                      onEdit={() => {
                        setNotice(null);
                        setEditing({ mode: "edit", profile: entry.profile });
                      }}
                      onRemove={() => setRemoving(entry)}
                    />
                  </li>
                ))}
              </ul>
            )}
          </section>
        </div>
      )}

      <RemoveProfileDialog
        entry={removing}
        onClose={() => setRemoving(null)}
        onDone={(entry) => {
          if (editing?.mode === "edit" && editing.profile.name === entry.profile.name) setEditing(null);
          setNotice(
            t(entry.preset ? "config.resources.restored" : "config.resources.removed", { name: profileLabel(entry.profile.name, t) }),
          );
        }}
      />
    </>
  );
}

export default ResourcesPage;

function Item({ label, children, hint }: { label: string; children: ReactNode; hint?: string }) {
  return (
    <div className="grid min-w-0 gap-0.5">
      <dt className="text-sm text-ink-muted">{label}</dt>
      <dd className="m-0 min-w-0 font-semibold break-words tabular-nums">{children}</dd>
      {hint && <dd className="m-0 text-sm text-ink-muted">{hint}</dd>}
    </div>
  );
}

function HardwarePanel({ hardware: hw, executorError }: { hardware: Schemas["Hardware"] | undefined; executorError: string | undefined }) {
  const { t, i18n } = useTranslation();
  const lng = i18n.language;
  return (
    <Panel title={t("config.resources.hardwareTitle")}>
      {executorError && (
        <p role="alert" className="m-0 flex items-start gap-2 rounded-control border border-(--vh-critical-fg) bg-(--vh-critical-bg) p-3 text-sm text-(--vh-critical-fg)">
          <TriangleAlert aria-hidden="true" className="mt-0.5 size-4 shrink-0" />
          <span className="min-w-0 [overflow-wrap:anywhere]">{t("config.resources.executorError", { cause: executorError })}</span>
        </p>
      )}
      {!hw ? (
        <p className="m-0 text-ink-muted">{t("config.resources.noHardware")}</p>
      ) : (
        <dl className="m-0 grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
          <Item label={t("config.resources.cpus")}>{formatNumber(hw.cpus, lng)}</Item>
          <Item label={t("config.resources.memory")}>{formatBytes(hw.memory_bytes, lng)}</Item>
          <Item label={t("config.resources.disk")}>{t(hw.rotational ? "config.resources.diskRotational" : "config.resources.diskSolid")}</Item>
          <Item label={t("config.resources.systemd")}>
            <span className="font-mono">{hw.systemd_version || "—"}</span>
          </Item>
          <Item label={t("config.resources.freezer")} hint={t("config.resources.freezerHint")}>
            {t(hw.freezer ? "config.resources.available" : "config.resources.unavailable")}
          </Item>
          <Item label={t("config.resources.noReserve")} hint={t("config.resources.noReserveHint")}>
            {t(hw.allow_no_reserve ? "config.resources.noReserveAllowed" : "config.resources.noReserveDenied")}
          </Item>
        </dl>
      )}
    </Panel>
  );
}

function ProfileCard({
  entry,
  isAdmin,
  onEdit,
  onRemove,
}: {
  entry: ProfileEntry;
  isAdmin: boolean;
  onEdit: () => void;
  onRemove: () => void;
}) {
  const { t, i18n } = useTranslation();
  const lng = i18n.language;
  const p = entry.profile;
  const label = profileLabel(p.name, t);
  const cores = p.cpu_quota_percent / 100;
  const runtime = splitDuration(p.max_runtime_sec);
  return (
    <article className="flex h-full min-w-0 flex-col gap-4 rounded-panel border border-line bg-surface p-5 shadow-panel">
      <div className="flex flex-wrap items-start justify-between gap-2">
        <h3 className="m-0 min-w-0 text-lg font-bold [overflow-wrap:anywhere]">
          {label}
          {label !== p.name && <span className="ml-2 font-mono text-sm font-normal text-ink-muted">{p.name}</span>}
        </h3>
        <span className="flex flex-wrap gap-1">
          {entry.preset && (
            <Badge tone="neutral" icon={Gauge} variant="outline">
              {t("config.resources.preset")}
            </Badge>
          )}
          {entry.custom && (
            <Badge tone="low" icon={UserPen} variant="outline">
              {t(entry.preset ? "config.resources.adjusted" : "config.resources.custom")}
            </Badge>
          )}
        </span>
      </div>
      <dl className="m-0 grid gap-3 sm:grid-cols-2">
        <Item label={t("config.resources.limits.cpu")} hint={t("config.resources.explain.cpu", { cores: new Intl.NumberFormat(lng, { maximumFractionDigits: 2 }).format(cores) })}>
          {formatNumber(p.cpu_quota_percent, lng)}%
        </Item>
        <Item label={t("config.resources.limits.memory")} hint={t("config.resources.explain.memory")}>
          {p.memory_max_bytes > 0 ? formatBytes(p.memory_max_bytes, lng) : t("config.resources.noLimit")}
        </Item>
        <Item label={t("config.resources.limits.ioRead")} hint={t("config.resources.explain.ioRead")}>
          {p.io_read_bytes_per_sec > 0
            ? t("config.resources.perSecond", { value: formatBytes(p.io_read_bytes_per_sec, lng) })
            : t("config.resources.noBandwidthLimit")}
        </Item>
        <Item label={t("config.resources.limits.ioWeight")} hint={t("config.resources.explain.ioWeight")}>
          {formatNumber(p.io_weight, lng)}
        </Item>
        <Item label={t("config.resources.limits.workers")} hint={t("config.resources.explain.workers")}>
          {formatNumber(p.workers, lng)}
        </Item>
        <Item label={t("config.resources.limits.clamd")} hint={t("config.resources.explain.clamd")}>
          {formatNumber(p.clamd_concurrency, lng)}
        </Item>
        <Item label={t("config.resources.limits.nice")} hint={t("config.resources.explain.nice")}>
          {p.nice}
        </Item>
        <Item label={t("config.resources.limits.runtime")} hint={t("config.resources.explain.runtime")}>
          {t("config.resources.duration", { hours: runtime.hours, minutes: runtime.minutes })}
        </Item>
        <Item label={t("config.resources.limits.maxFile")} hint={t("config.resources.explain.maxFile")}>
          {p.max_file_bytes > 0 ? formatBytes(p.max_file_bytes, lng) : t("config.resources.noLimit")}
        </Item>
      </dl>
      {isAdmin && (
        <div className="mt-auto flex flex-wrap gap-2">
          <Button variant="secondary" onClick={onEdit}>
            <Pencil aria-hidden="true" className="size-4" />
            {t("config.resources.edit")}
            <span className="visually-hidden">: {label}</span>
          </Button>
          {entry.preset && entry.custom && (
            <Button variant="ghost" onClick={onRemove}>
              <RotateCcw aria-hidden="true" className="size-4" />
              {t("config.resources.restore")}
              <span className="visually-hidden">: {label}</span>
            </Button>
          )}
          {!entry.preset && (
            <Button variant="ghost" onClick={onRemove}>
              <Trash2 aria-hidden="true" className="size-4" />
              {t("config.resources.remove")}
              <span className="visually-hidden">: {label}</span>
            </Button>
          )}
        </div>
      )}
    </article>
  );
}

function RemoveProfileDialog({
  entry,
  onClose,
  onDone,
}: {
  entry: ProfileEntry | null;
  onClose: () => void;
  onDone: (entry: ProfileEntry) => void;
}) {
  const { t } = useTranslation();
  const qc = useQueryClient();
  const guarded = useGuardedAction(true);
  const remove = useMutation({
    mutationFn: (name: string) => unwrap(api.DELETE("/api/v1/resources/profiles/{name}", { params: { path: { name } } })),
    onSuccess: (data) => qc.setQueryData(resourcesQuery.queryKey, data),
  });
  const preset = entry?.preset ?? false;
  return (
    <ConfirmDialog
      open={entry !== null}
      onClose={onClose}
      onConfirm={async (input) => {
        if (!entry) return;
        await guarded.run(input, () => remove.mutateAsync(entry.profile.name));
        onDone(entry);
      }}
      title={t(preset ? "config.resources.restoreTitle" : "config.resources.removeTitle")}
      object={entry && <code className="[overflow-wrap:anywhere]">{entry.profile.name}</code>}
      impact={t(preset ? "config.resources.restoreImpact" : "config.resources.removeImpact")}
      reversible={false}
      requireReauth={guarded.requireReauth}
      requireCode={guarded.requireCode}
      confirmLabel={t(preset ? "config.resources.restore" : "config.resources.remove")}
    />
  );
}

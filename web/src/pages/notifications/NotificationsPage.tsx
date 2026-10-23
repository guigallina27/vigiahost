import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import {
  BellOff,
  BellPlus,
  BellRing,
  CircleCheck,
  CirclePause,
  CircleX,
  KeyRound,
  Lock,
  Mail,
  Pencil,
  PlugZap,
  RefreshCw,
  Send,
  Trash2,
  TriangleAlert,
  Webhook,
} from "lucide-react";
import { useState, type ReactNode } from "react";
import { useTranslation } from "react-i18next";
import { api, ApiError, unwrap, type Schemas } from "../../api/client";
import { useCurrentUser } from "../../auth/session";
import { Badge } from "../../components/Badge";
import { Button } from "../../components/Button";
import { ConfirmDialog } from "../../components/ConfirmDialog";
import { EmptyState } from "../../components/EmptyState";
import { Panel } from "../../components/Panel";
import { Timestamp } from "../../components/Timestamp";
import { PageHeader } from "../../layout/PageHeader";
import { escapeHidden } from "../../lib/text";
import { retryTransient } from "../config/queries";
import { useGuardedAction } from "../config/useGuardedAction";
import { ChannelForm } from "./ChannelForm";
import { channelDestination, emptyChannelValues, valuesFromChannel, type Channel } from "./notifications";
import { OutboxPanel, OutboxStateBadge } from "./OutboxPanel";
import { channelsQuery, notificationsKey, rulesQuery } from "./queries";
import { RulesPanel } from "./RulesPanel";

type Editing = { mode: "new" } | { mode: "edit"; channel: Channel } | null;

/** Notificações (E1.12): canais de e-mail e webhook, regras de envio, botão de teste e caixa de saída. */
export function NotificationsPage() {
  const { t } = useTranslation();
  const { isAdmin } = useCurrentUser();
  const channels = useQuery({ ...channelsQuery, enabled: isAdmin, retry: retryTransient });
  const rules = useQuery({ ...rulesQuery, enabled: isAdmin, retry: retryTransient });
  const [editing, setEditing] = useState<Editing>(null);
  const [deleting, setDeleting] = useState<Channel | null>(null);
  const [notice, setNotice] = useState<string | null>(null);

  if (!isAdmin) {
    return (
      <>
        <PageHeader title={t("notifications.title")} subtitle={t("notifications.subtitle")} />
        <EmptyState icon={Lock} title={t("admin.common.forbiddenTitle")} description={t("notifications.forbidden")} />
      </>
    );
  }

  const createButton = !editing && (
    <Button
      variant="primary"
      onClick={() => {
        setNotice(null);
        setEditing({ mode: "new" });
      }}
    >
      <BellPlus aria-hidden="true" className="size-4" />
      {t("notifications.channels.create")}
    </Button>
  );
  const list = channels.data ?? [];

  return (
    <>
      <PageHeader title={t("notifications.title")} subtitle={t("notifications.subtitle")} actions={createButton} />
      <div className="flex min-w-0 flex-col gap-6">
        <p role="status" className={notice ? "m-0 rounded-control border border-line-strong bg-accent-soft p-3" : "visually-hidden"}>
          {notice}
        </p>

        {editing && (
          <ChannelForm
            key={editing.mode === "edit" ? editing.channel.id : "new"}
            {...(editing.mode === "edit" ? { editing: editing.channel } : {})}
            initial={editing.mode === "edit" ? valuesFromChannel(editing.channel) : emptyChannelValues()}
            onCancel={() => setEditing(null)}
            onDone={(saved) => {
              setEditing(null);
              setNotice(t(editing.mode === "edit" ? "notifications.channels.saved" : "notifications.channels.created", { name: saved.name }));
            }}
          />
        )}

        <Panel title={t("notifications.channels.title")}>
          {channels.isPending ? (
            <p role="status" className="m-0 text-ink-muted">
              {t("states.loading")}
            </p>
          ) : channels.isError ? (
            <EmptyState
              tone="error"
              icon={PlugZap}
              headingLevel={3}
              title={t("notifications.loadErrorTitle")}
              description={<span role="alert">{channels.error.message}</span>}
              action={
                <Button variant="primary" onClick={() => void channels.refetch()}>
                  <RefreshCw aria-hidden="true" className="size-4" />
                  {t("states.retry")}
                </Button>
              }
            />
          ) : list.length === 0 ? (
            <EmptyState
              icon={BellOff}
              headingLevel={3}
              title={t("notifications.channels.emptyTitle")}
              description={t("notifications.channels.empty")}
              action={createButton || undefined}
            />
          ) : (
            <ul className="m-0 grid list-none gap-4 p-0 xl:grid-cols-2">
              {list.map((c) => (
                <li key={c.id} className="min-w-0">
                  <ChannelCard
                    channel={c}
                    onEdit={() => {
                      setNotice(null);
                      setEditing({ mode: "edit", channel: c });
                    }}
                    onDelete={() => setDeleting(c)}
                  />
                </li>
              ))}
            </ul>
          )}
        </Panel>

        {rules.isError ? (
          <EmptyState
            tone="error"
            icon={PlugZap}
            title={t("notifications.loadErrorTitle")}
            description={<span role="alert">{rules.error.message}</span>}
          />
        ) : (
          channels.data &&
          rules.data && <RulesPanel channels={channels.data} rules={rules.data} />
        )}

        <OutboxPanel />
      </div>

      <DeleteChannelDialog
        channel={deleting}
        onClose={() => setDeleting(null)}
        onDeleted={(name) => {
          if (editing?.mode === "edit" && editing.channel.id === deleting?.id) setEditing(null);
          setNotice(t("notifications.channels.deleted", { name }));
        }}
      />
    </>
  );
}

export default NotificationsPage;

function Info({ label, children }: { label: string; children: ReactNode }) {
  return (
    <div className="grid min-w-0 gap-0.5">
      <dt className="text-sm text-ink-muted">{label}</dt>
      <dd className="m-0 min-w-0 [overflow-wrap:anywhere]">{children}</dd>
    </div>
  );
}

type TestResult = Schemas["NotificationTestResult"];

function ChannelCard({ channel: c, onEdit, onDelete }: { channel: Channel; onEdit: () => void; onDelete: () => void }) {
  const { t } = useTranslation();
  const qc = useQueryClient();
  const [result, setResult] = useState<TestResult | { ok: false; error: string } | null>(null);
  const test = useMutation({
    mutationFn: () => unwrap(api.POST("/api/v1/notifications/channels/{id}/test", { params: { path: { id: c.id } } })),
    onMutate: () => setResult(null),
    onSuccess: async (r) => {
      setResult(r);
      await qc.invalidateQueries({ queryKey: notificationsKey });
    },
    onError: (err) => setResult({ ok: false, error: err.message }),
  });

  const KindIcon = c.kind === "email" ? Mail : Webhook;
  const secretText = !c.secret_configured
    ? t(c.kind === "email" ? "notifications.channels.noPassword" : "notifications.channels.noSecret")
    : c.secret_readable
      ? t("notifications.channels.secretConfigured")
      : t("notifications.channels.secretUnreadable");

  return (
    <article className="flex h-full min-w-0 flex-col gap-4 rounded-panel border border-line bg-surface p-5 shadow-panel">
      <div className="flex flex-wrap items-start justify-between gap-2">
        <h3 className="m-0 min-w-0 text-lg font-bold [overflow-wrap:anywhere]">{c.name}</h3>
        <div className="flex flex-wrap gap-2">
          <Badge tone="neutral" variant="outline" icon={KindIcon}>
            {t(`notifications.kinds.${c.kind}`)}
          </Badge>
          {c.enabled ? (
            <Badge tone="low" variant="outline" icon={BellRing}>
              {t("notifications.channels.active")}
            </Badge>
          ) : (
            <Badge tone="neutral" variant="outline" icon={CirclePause}>
              {t("notifications.channels.paused")}
            </Badge>
          )}
        </div>
      </div>
      <dl className="m-0 grid gap-3 sm:grid-cols-2">
        <Info label={t("notifications.channels.destination")}>
          <span className="font-mono text-sm">{escapeHidden(channelDestination(c))}</span>
        </Info>
        {c.email && (
          <Info label={t("notifications.channels.security")}>{t(`notifications.security.${c.email.security}`)}</Info>
        )}
        {c.webhook && (
          <Info label={t("notifications.channels.network")}>
            {t(c.webhook.allow_private_network ? "notifications.channels.privateAllowed" : "notifications.channels.publicOnly")}
          </Info>
        )}
        <Info label={t(c.kind === "email" ? "notifications.form.password" : "notifications.form.webhookSecret")}>
          <span className={`inline-flex items-center gap-1.5 ${c.secret_configured && !c.secret_readable ? "text-(--vh-critical-fg)" : ""}`}>
            {c.secret_configured && !c.secret_readable ? (
              <TriangleAlert aria-hidden="true" className="size-4 shrink-0" />
            ) : (
              <KeyRound aria-hidden="true" className="size-4 shrink-0" />
            )}
            {secretText}
          </span>
        </Info>
        <Info label={t("notifications.channels.details")}>
          {t(c.include_details ? "notifications.channels.withDetails" : "notifications.channels.withoutDetails")}
        </Info>
        <Info label={t("notifications.channels.lastDelivery")}>
          {c.last_state && c.last_at ? (
            <span className="flex flex-col items-start gap-1">
              <OutboxStateBadge state={c.last_state} />
              <Timestamp date={new Date(c.last_at)} compact />
              {c.last_error && <span className="text-sm text-(--vh-critical-fg)">{escapeHidden(c.last_error)}</span>}
            </span>
          ) : (
            t("notifications.channels.neverSent")
          )}
        </Info>
      </dl>

      <div aria-live="polite" className="min-w-0">
        {test.isPending && <p className="m-0 text-sm text-ink-muted">{t("notifications.channels.testing")}</p>}
        {result &&
          (result.ok ? (
            <p className="m-0 flex items-start gap-2 rounded-control border border-(--vh-ok-fg) p-3 text-(--vh-ok-fg)">
              <CircleCheck aria-hidden="true" className="mt-0.5 size-4 shrink-0" />
              <span className="min-w-0">{t("notifications.channels.testOk")}</span>
            </p>
          ) : (
            <p className="m-0 flex items-start gap-2 rounded-control bg-(--vh-critical-bg) p-3 text-(--vh-critical-fg)">
              <CircleX aria-hidden="true" className="mt-0.5 size-4 shrink-0" />
              <span className="min-w-0 [overflow-wrap:anywhere]">
                {t("notifications.channels.testFailed", { error: escapeHidden(result.error ?? "") })}
              </span>
            </p>
          ))}
      </div>

      <div className="mt-auto flex flex-wrap gap-2">
        <Button variant="primary" onClick={() => test.mutate()} disabled={test.isPending}>
          <Send aria-hidden="true" className="size-4" />
          {t("notifications.channels.test")}
          <span className="visually-hidden">: {c.name}</span>
        </Button>
        <Button variant="secondary" onClick={onEdit}>
          <Pencil aria-hidden="true" className="size-4" />
          {t("notifications.channels.edit")}
          <span className="visually-hidden">: {c.name}</span>
        </Button>
        <Button variant="ghost" onClick={onDelete}>
          <Trash2 aria-hidden="true" className="size-4" />
          {t("notifications.channels.delete")}
          <span className="visually-hidden">: {c.name}</span>
        </Button>
      </div>
    </article>
  );
}

function DeleteChannelDialog({
  channel,
  onClose,
  onDeleted,
}: {
  channel: Channel | null;
  onClose: () => void;
  onDeleted: (name: string) => void;
}) {
  const { t } = useTranslation();
  const qc = useQueryClient();
  const guarded = useGuardedAction(false);
  return (
    <ConfirmDialog
      open={channel !== null}
      onClose={() => {
        guarded.reset();
        onClose();
      }}
      onConfirm={async (input) => {
        if (!channel) return;
        try {
          await guarded.run(input, () =>
            unwrap(api.DELETE("/api/v1/notifications/channels/{id}", { params: { path: { id: channel.id } } })),
          );
        } catch (err) {
          if (!(err instanceof ApiError && err.status === 404)) throw err;
        }
        await qc.invalidateQueries({ queryKey: notificationsKey });
        onDeleted(channel.name);
      }}
      title={t("notifications.channels.deleteTitle")}
      object={
        channel && (
          <span className="flex flex-col gap-1">
            <strong className="[overflow-wrap:anywhere]">{channel.name}</strong>
            <span className="font-mono text-sm [overflow-wrap:anywhere]">{escapeHidden(channelDestination(channel))}</span>
          </span>
        )
      }
      impact={t("notifications.channels.deleteImpact")}
      reversible={false}
      requireReauth={guarded.requireReauth}
      requireCode={guarded.requireCode}
      confirmLabel={t("notifications.channels.deleteConfirm")}
    />
  );
}

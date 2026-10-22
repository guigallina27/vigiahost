import { useInfiniteQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { CircleCheck, CircleX, Clock, Inbox, PlugZap, RefreshCw, Send, type LucideIcon } from "lucide-react";
import type { TFunction } from "i18next";
import { useMemo, useState } from "react";
import { useTranslation } from "react-i18next";
import { api, unwrap } from "../../api/client";
import { Badge, type Tone } from "../../components/Badge";
import { Button } from "../../components/Button";
import { EmptyState } from "../../components/EmptyState";
import { SelectField } from "../../components/Field";
import { Panel } from "../../components/Panel";
import { TableScroll } from "../../components/TableScroll";
import { Timestamp } from "../../components/Timestamp";
import { formatNumber } from "../../lib/format";
import { escapeHidden } from "../../lib/text";
import { outboxStates, outboxSummaryParts, type OutboxEntry, type OutboxState } from "./notifications";
import { notificationsKey, OUTBOX_PAGE, outboxKey } from "./queries";

const stateLook: Record<OutboxState, { tone: Tone; icon: LucideIcon }> = {
  pending: { tone: "low", icon: Clock },
  sent: { tone: "ok", icon: CircleCheck },
  failed: { tone: "critical", icon: CircleX },
};

/** Selo do estado de uma mensagem (estado: selo contornado, ícone + texto). */
export function OutboxStateBadge({ state }: { state: OutboxState }) {
  const { t } = useTranslation();
  const { tone, icon } = stateLook[state];
  return (
    <Badge tone={tone} variant="outline" icon={icon}>
      {t(`notifications.outbox.states.${state}`)}
    </Badge>
  );
}

/** Resumo da mensagem no idioma da tela. */
export function outboxSummary(e: OutboxEntry, t: TFunction): string {
  const p = outboxSummaryParts(e);
  switch (p.key) {
    case "test":
      return t("notifications.summary.test");
    case "findingOne":
      return t("notifications.summary.findingOne", { severity: t(`severity.${p.severity}`).toLocaleLowerCase() });
    case "findingMany":
      return t("notifications.summary.findingMany", { count: p.count, severity: t(`severity.${p.severity}`).toLocaleLowerCase() });
    case "event":
      return p.count > 1
        ? t("notifications.summary.grouped", { event: t(`notifications.events.${p.event}`), count: p.count })
        : t(`notifications.events.${p.event}`);
  }
}

/** Pode reenviar: pendente ou com falha, de canal que ainda existe, e não é teste. */
export function canRetry(e: OutboxEntry): boolean {
  return e.state !== "sent" && e.channel_id !== undefined && e.event !== "test";
}

/** Histórico da caixa de saída com filtro por estado, paginação por cursor e reenvio. */
export function OutboxPanel() {
  const { t, i18n } = useTranslation();
  const qc = useQueryClient();
  const [state, setState] = useState<OutboxState | "">("");
  const [notice, setNotice] = useState<string | null>(null);

  const outbox = useInfiniteQuery({
    queryKey: outboxKey(state),
    queryFn: ({ pageParam, signal }) =>
      unwrap(
        api.GET("/api/v1/notifications/outbox", {
          params: {
            query: {
              limit: OUTBOX_PAGE,
              ...(state ? { state } : {}),
              ...(pageParam !== undefined ? { before: pageParam } : {}),
            },
          },
          signal,
        }),
      ),
    initialPageParam: undefined as number | undefined,
    getNextPageParam: (last) => last.next_before,
    refetchInterval: 30_000,
  });
  const pages = outbox.data?.pages;
  const entries = useMemo(() => pages?.flatMap((p) => p.entries) ?? [], [pages]);

  const retry = useMutation({
    mutationFn: (id: number) =>
      unwrap(api.POST("/api/v1/notifications/outbox/{id}/retry", { params: { path: { id } } })),
    onSuccess: async (e) => {
      setNotice(t("notifications.outbox.retried", { channel: e.channel_name }));
      await qc.invalidateQueries({ queryKey: notificationsKey });
    },
    onError: (err) => setNotice(err.message),
  });

  const lng = i18n.language;

  return (
    <Panel
      title={t("notifications.outbox.title")}
      actions={
        <Button onClick={() => void outbox.refetch()} disabled={outbox.isFetching}>
          <RefreshCw aria-hidden="true" className="size-4" />
          {t("notifications.outbox.refresh")}
        </Button>
      }
    >
      <p className="m-0 text-sm text-ink-muted">{t("notifications.outbox.intro")}</p>
      <SelectField
        className="max-w-xs"
        label={t("notifications.outbox.filter")}
        options={[
          { value: "", label: t("notifications.outbox.allStates") },
          ...outboxStates.map((s) => ({ value: s, label: t(`notifications.outbox.states.${s}`) })),
        ]}
        value={state}
        onChange={(e) => setState(e.target.value as OutboxState | "")}
      />
      <p role="status" className={notice ? "m-0 rounded-control border border-line-strong bg-accent-soft p-3" : "visually-hidden"}>
        {notice}
      </p>
      {outbox.isPending ? (
        <p role="status" className="m-0 text-ink-muted">
          {t("states.loading")}
        </p>
      ) : outbox.isError ? (
        <EmptyState
          tone="error"
          icon={PlugZap}
          headingLevel={3}
          title={t("notifications.loadErrorTitle")}
          description={<span role="alert">{outbox.error.message}</span>}
          action={
            <Button onClick={() => void outbox.refetch()}>
              <RefreshCw aria-hidden="true" className="size-4" />
              {t("states.retry")}
            </Button>
          }
        />
      ) : entries.length === 0 ? (
        <EmptyState
          icon={Inbox}
          headingLevel={3}
          title={t("notifications.outbox.emptyTitle")}
          description={state ? t("notifications.outbox.emptyFiltered") : t("notifications.outbox.empty")}
        />
      ) : (
        <>
          <TableScroll label={t("notifications.outbox.title")}>
            <table className="vh-table">
              <caption className="visually-hidden">{t("notifications.outbox.caption")}</caption>
              <thead>
                <tr>
                  <th scope="col">{t("notifications.outbox.colMessage")}</th>
                  <th scope="col">{t("notifications.outbox.colChannel")}</th>
                  <th scope="col">{t("notifications.outbox.colState")}</th>
                  <th scope="col">{t("notifications.outbox.colCreated")}</th>
                  <th scope="col">{t("notifications.outbox.colDetail")}</th>
                  <th scope="col">{t("notifications.outbox.colActions")}</th>
                </tr>
              </thead>
              <tbody>
                {entries.map((e) => (
                  <tr key={e.id}>
                    <th scope="row" className="min-w-56 text-left font-normal">
                      <span className="block font-semibold [overflow-wrap:anywhere]">{outboxSummary(e, t)}</span>
                      {e.items[0] && (
                        <span className="block text-sm text-ink-muted [overflow-wrap:anywhere]">
                          {escapeHidden(e.items[0].title)}
                          {e.item_count > 1 && ` · ${t("notifications.outbox.items", { count: e.item_count })}`}
                        </span>
                      )}
                    </th>
                    <td className="[overflow-wrap:anywhere]">
                      {e.channel_name}
                      <span className="block text-sm text-ink-muted">
                        {e.channel_id === undefined ? t("notifications.outbox.channelRemoved") : t(`notifications.kinds.${e.channel_kind}`)}
                      </span>
                    </td>
                    <td>
                      <OutboxStateBadge state={e.state} />
                      <span className="block text-sm text-ink-muted tabular-nums">
                        {t("notifications.outbox.attempts", { count: e.attempts, max: e.max_attempts })}
                      </span>
                    </td>
                    <td>
                      <Timestamp date={new Date(e.created_at)} compact />
                    </td>
                    <td className="min-w-48">
                      {e.state === "sent" && e.sent_at && (
                        <span className="text-sm">
                          {t("notifications.outbox.sentAt")} <Timestamp date={new Date(e.sent_at)} compact />
                        </span>
                      )}
                      {e.state === "pending" && e.next_attempt_at && (
                        <span className="text-sm">
                          {t("notifications.outbox.nextAttempt")} <Timestamp date={new Date(e.next_attempt_at)} compact />
                        </span>
                      )}
                      {e.last_error && (
                        <span className="block text-sm text-(--vh-critical-fg) [overflow-wrap:anywhere]">
                          {escapeHidden(e.last_error)}
                        </span>
                      )}
                    </td>
                    <td>
                      {canRetry(e) ? (
                        <Button variant="ghost" onClick={() => retry.mutate(e.id)} disabled={retry.isPending}>
                          <Send aria-hidden="true" className="size-4" />
                          {t("notifications.outbox.retry")}
                          <span className="visually-hidden">: {outboxSummary(e, t)}, {e.channel_name}</span>
                        </Button>
                      ) : (
                        <span className="text-sm text-ink-muted">—</span>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </TableScroll>
          <div className="flex flex-wrap items-center gap-3">
            <span className="text-sm text-ink-muted">
              {t("notifications.outbox.showing", { count: entries.length, shown: formatNumber(entries.length, lng) })}
            </span>
            {outbox.hasNextPage && (
              <Button onClick={() => void outbox.fetchNextPage()} disabled={outbox.isFetchingNextPage}>
                {t("notifications.outbox.loadMore")}
              </Button>
            )}
          </div>
        </>
      )}
    </Panel>
  );
}

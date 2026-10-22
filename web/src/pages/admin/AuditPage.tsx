import { useInfiniteQuery } from "@tanstack/react-query";
import { ClipboardList, Lock, PlugZap, RefreshCw, ShieldAlert, ShieldCheck, TriangleAlert } from "lucide-react";
import { useMemo, useState } from "react";
import { useTranslation } from "react-i18next";
import { api, unwrap } from "../../api/client";
import { useCurrentUser } from "../../auth/session";
import { Badge } from "../../components/Badge";
import { Button } from "../../components/Button";
import { EmptyState } from "../../components/EmptyState";
import { Field, SelectField } from "../../components/Field";
import { Panel } from "../../components/Panel";
import { Timestamp } from "../../components/Timestamp";
import { PageHeader } from "../../layout/PageHeader";
import { formatNumber } from "../../lib/format";
import { escapeHidden } from "../../lib/text";
import { filterAudit, isKnownAuditAction, knownAuditActions, type AuditEntry } from "./adminLogic";
import { SafeText } from "./SecretOnce";

const PAGE_SIZES = [50, 100, 200, 500] as const;

export function auditQueryKey(limit: number) {
  return ["audit", { limit }] as const;
}

/** Auditoria (administrador e auditor): paginação por cursor, filtro local e integridade da cadeia de hashes. */
export function AuditPage() {
  const { t, i18n } = useTranslation();
  const { canAudit } = useCurrentUser();
  const [limit, setLimit] = useState<number>(50);
  const [text, setText] = useState("");
  const [action, setAction] = useState("");

  const audit = useInfiniteQuery({
    queryKey: auditQueryKey(limit),
    queryFn: ({ pageParam, signal }) =>
      unwrap(
        api.GET("/api/v1/audit", {
          params: { query: { limit, ...(pageParam !== undefined ? { before: pageParam } : {}) } },
          signal,
        }),
      ),
    initialPageParam: undefined as number | undefined,
    getNextPageParam: (last) => last.next_before,
    enabled: canAudit,
  });

  const pages = audit.data?.pages;
  const entries = useMemo(() => pages?.flatMap((p) => p.entries) ?? [], [pages]);
  const shown = useMemo(() => filterAudit(entries, { text, action }), [entries, text, action]);
  // Cada resposta confere a cadeia inteira; vale a leitura mais recente.
  const chain = pages?.[pages.length - 1];

  // Ações conhecidas mais as que apareceram nas entradas carregadas (para filtrar por código novo também).
  const actionOptions = useMemo(() => {
    const codes = new Set<string>(knownAuditActions);
    for (const e of entries) codes.add(e.action);
    return [...codes].sort();
  }, [entries]);

  if (!canAudit) {
    return (
      <>
        <PageHeader title={t("admin.audit.title")} subtitle={t("admin.audit.subtitle")} />
        <EmptyState icon={Lock} title={t("admin.common.forbiddenTitle")} description={t("admin.audit.forbidden")} />
      </>
    );
  }

  const lng = i18n.language;
  const filtered = text.trim() !== "" || action !== "";

  return (
    <>
      <PageHeader title={t("admin.audit.title")} subtitle={t("admin.audit.subtitle")} />
      <div className="flex flex-col gap-6">
        {chain && (chain.chain_ok ? (
          <p role="status" className="m-0 flex flex-wrap items-center gap-3 rounded-control border border-line bg-surface p-3">
            <Badge tone="ok" variant="outline" icon={ShieldCheck}>
              {t("admin.audit.chainOkBadge")}
            </Badge>
            <span className="min-w-0 flex-1">{t("admin.audit.chainOk")}</span>
          </p>
        ) : (
          <div role="alert" className="flex flex-col gap-2 rounded-control border border-(--vh-critical-fg) bg-(--vh-critical-bg) p-3 text-(--vh-critical-fg)">
            <p className="m-0 flex flex-wrap items-center gap-3 font-semibold">
              <ShieldAlert aria-hidden="true" className="size-5 shrink-0" />
              <span className="min-w-0 flex-1">
                {chain.broken_at !== undefined
                  ? t("admin.audit.chainBroken", { id: formatNumber(chain.broken_at, lng) })
                  : t("admin.audit.chainBrokenUnknown")}
              </span>
            </p>
            <p className="m-0">{t("admin.audit.chainBrokenAction")}</p>
          </div>
        ))}

        <Panel title={t("admin.audit.filtersTitle")}>
          <div className="grid gap-4 md:grid-cols-3">
            <Field
              label={t("admin.audit.search")}
              hint={t("admin.audit.searchHint")}
              type="search"
              value={text}
              onChange={(e) => setText(e.target.value)}
              autoComplete="off"
              spellCheck={false}
            />
            <SelectField
              label={t("admin.audit.action")}
              options={[
                { value: "", label: t("admin.audit.allActions") },
                ...actionOptions.map((code) => ({
                  value: code,
                  label: isKnownAuditAction(code) ? `${t(`admin.audit.actions.${code}`)} (${code})` : code,
                })),
              ]}
              value={action}
              onChange={(e) => setAction(e.target.value)}
            />
            <SelectField
              label={t("admin.audit.pageSize")}
              options={PAGE_SIZES.map((n) => ({ value: String(n), label: formatNumber(n, lng) }))}
              value={String(limit)}
              onChange={(e) => setLimit(Number(e.target.value))}
            />
          </div>
          <p className="m-0 text-sm text-ink-muted">{t("admin.audit.filterScope")}</p>
        </Panel>

        <Panel
          title={t("admin.audit.listCaption")}
          actions={
            audit.data && (
              <span role="status" className="text-sm text-ink-muted">
                {t("admin.audit.showing", { shown: formatNumber(shown.length, lng), loaded: formatNumber(entries.length, lng) })}
              </span>
            )
          }
        >
          {audit.isPending ? (
            <p className="m-0 text-ink-muted">{t("states.loading")}</p>
          ) : audit.isError && entries.length === 0 ? (
            <EmptyState
              tone="error"
              icon={PlugZap}
              headingLevel={3}
              title={t("admin.common.loadErrorTitle")}
              description={audit.error.message}
              action={
                <Button onClick={() => void audit.refetch()} disabled={audit.isFetching}>
                  <RefreshCw aria-hidden="true" className="size-4" />
                  {t("states.retry")}
                </Button>
              }
            />
          ) : entries.length === 0 ? (
            <EmptyState icon={ClipboardList} headingLevel={3} title={t("admin.audit.title")} description={t("admin.audit.empty")} />
          ) : shown.length === 0 && filtered ? (
            <EmptyState
              icon={ClipboardList}
              headingLevel={3}
              title={t("admin.audit.listCaption")}
              description={t("admin.audit.noMatch")}
              action={
                <Button
                  onClick={() => {
                    setText("");
                    setAction("");
                  }}
                >
                  {t("admin.audit.clearFilters")}
                </Button>
              }
            />
          ) : (
            <AuditTable entries={shown} brokenAt={chain && !chain.chain_ok ? chain.broken_at : undefined} />
          )}

          {audit.isFetchNextPageError && (
            <p role="alert" className="m-0 rounded-control bg-(--vh-critical-bg) p-3 text-sm text-(--vh-critical-fg)">
              {audit.error?.message}
            </p>
          )}
          {entries.length > 0 &&
            (audit.hasNextPage ? (
              <div>
                <Button onClick={() => void audit.fetchNextPage()} disabled={audit.isFetchingNextPage}>
                  {audit.isFetchingNextPage ? t("states.loading") : t("admin.audit.loadMore")}
                </Button>
              </div>
            ) : (
              <p className="m-0 text-sm text-ink-muted">{t("admin.audit.end")}</p>
            ))}
        </Panel>
      </div>
    </>
  );
}

function AuditTable({ entries, brokenAt }: { entries: readonly AuditEntry[]; brokenAt: number | undefined }) {
  const { t, i18n } = useTranslation();
  return (
    <div className="vh-table-wrap">
      <table className="vh-table">
        <caption className="visually-hidden">{t("admin.audit.listCaption")}</caption>
        <thead>
          <tr>
            <th scope="col">{t("admin.audit.colId")}</th>
            <th scope="col">{t("admin.audit.colWhen")}</th>
            <th scope="col">{t("admin.audit.colActor")}</th>
            <th scope="col">{t("admin.audit.colAction")}</th>
            <th scope="col">{t("admin.audit.colTarget")}</th>
            <th scope="col">{t("admin.audit.colDetail")}</th>
            <th scope="col">{t("admin.audit.colIp")}</th>
          </tr>
        </thead>
        <tbody>
          {entries.map((e) => (
            <tr key={e.id} className={e.id === brokenAt ? "bg-(--vh-critical-bg)" : undefined}>
              <td className="tabular-nums">
                {formatNumber(e.id, i18n.language)}
                {e.id === brokenAt && (
                  <span className="mt-1 block">
                    <Badge tone="critical" icon={TriangleAlert}>
                      {t("admin.audit.brokenRow")}
                    </Badge>
                  </span>
                )}
              </td>
              <td className="min-w-44">
                <Timestamp date={new Date(e.at)} compact />
              </td>
              <td>
                <SafeText value={e.actor || "—"} mono />
              </td>
              <td className="min-w-48">
                <span className="grid gap-0.5">
                  {isKnownAuditAction(e.action) && <span>{t(`admin.audit.actions.${e.action}`)}</span>}
                  <code className="font-mono text-sm text-ink-muted" translate="no">
                    {escapeHidden(e.action)}
                  </code>
                </span>
              </td>
              <td className="max-w-64">
                <SafeText value={e.target || "—"} mono />
              </td>
              <td className="max-w-80 min-w-48">
                <SafeText value={e.detail || "—"} />
              </td>
              <td>
                <SafeText value={e.ip || "—"} mono />
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

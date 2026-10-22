import { useQuery } from "@tanstack/react-query";
import { ArrowLeft, FileQuestion, PlugZap, RefreshCw, ShieldCheck } from "lucide-react";
import { useRef, useState, type ReactNode } from "react";
import { useTranslation } from "react-i18next";
import { Link, useLocation, useParams } from "react-router";
import { ApiError, api, unwrap, type Schemas } from "../../api/client";
import { useCurrentUser } from "../../auth/session";
import { Button } from "../../components/Button";
import { EmptyState } from "../../components/EmptyState";
import { HashText } from "../../components/HashText";
import { Panel } from "../../components/Panel";
import { PathText } from "../../components/PathText";
import { SeverityBadge } from "../../components/SeverityBadge";
import { StatusBadge } from "../../components/StatusBadge";
import { Timestamp } from "../../components/Timestamp";
import { PageHeader } from "../../layout/PageHeader";
import { formatNumber } from "../../lib/format";
import { draftFromFinding } from "./exceptionRules";
import { ExceptionForm } from "./ExceptionForm";
import { findingStateList, type FindingState } from "./filters";
import { DetailItem, formatMode, StatusMessage } from "./parts";
import { TransitionForm } from "./TransitionForm";

type FindingDetail = Schemas["FindingDetail"];
type Finding = Schemas["Finding"];

const linkClass = "font-semibold text-accent underline underline-offset-4";

/** Volta para a lista com os mesmos filtros de onde a pessoa veio. */
function useBackHref(): string {
  const state = useLocation().state as { fromSearch?: unknown } | null;
  const search = typeof state?.fromSearch === "string" && state.fromSearch.startsWith("?") ? state.fromSearch : "";
  return `/achados${search}`;
}

/** Detalhe do achado (rota sugerida: /achados/:findingId). */
export function FindingDetailPage() {
  const { t } = useTranslation();
  const { findingId = "" } = useParams();
  const numericId = /^\d+$/.test(findingId) ? Number(findingId) : NaN;
  // Mesma chave que os eventos ao vivo invalidam: ["finding", "<id>"] (o id chega como texto).
  const queryKey = ["finding", String(numericId)] as const;
  const backHref = useBackHref();

  const query = useQuery({
    queryKey,
    queryFn: ({ signal }) =>
      unwrap(api.GET("/api/v1/findings/{findingId}", { params: { path: { findingId: numericId } }, signal })),
    enabled: Number.isSafeInteger(numericId),
    retry: (count, err) => !(err instanceof ApiError && err.status === 404) && count < 2,
  });

  const back = (
    <Link to={backHref} className={`inline-flex min-h-11 items-center gap-2 ${linkClass}`}>
      <ArrowLeft aria-hidden="true" className="size-4" />
      {t("findings.detail.back")}
    </Link>
  );

  const notFound = !Number.isSafeInteger(numericId) || (query.error instanceof ApiError && query.error.status === 404);
  if (notFound) {
    return (
      <>
        <PageHeader title={t("findings.detail.notFoundTitle")} actions={back} />
        <EmptyState
          icon={FileQuestion}
          title={t("findings.detail.notFoundTitle")}
          description={t("findings.detail.notFoundDescription")}
          action={back}
        />
      </>
    );
  }

  if (query.isPending) {
    return (
      <>
        <PageHeader title={t("findings.detail.titleFallback", { id: findingId })} actions={back} />
        <p className="m-0 text-ink-muted" role="status">
          {t("states.loading")}
        </p>
      </>
    );
  }

  if (query.isError) {
    return (
      <>
        <PageHeader title={t("findings.detail.titleFallback", { id: findingId })} actions={back} />
        <EmptyState
          tone="error"
          icon={PlugZap}
          title={t("findings.detail.errorTitle")}
          description={<p className="m-0" role="alert">{query.error.message}</p>}
          action={
            <Button variant="primary" onClick={() => void query.refetch()} disabled={query.isFetching}>
              <RefreshCw aria-hidden="true" className="size-4" />
              {t("states.retry")}
            </Button>
          }
        />
      </>
    );
  }

  return <DetailView detail={query.data} queryKey={queryKey} back={back} />;
}

function DetailView({ detail, queryKey, back }: { detail: FindingDetail; queryKey: readonly unknown[]; back: ReactNode }) {
  const { t } = useTranslation();
  const { canOperate } = useCurrentUser();
  const f = detail.finding;
  const [exceptionOpen, setExceptionOpen] = useState(false);
  const [message, setMessage] = useState<string | null>(null);
  const statusRef = useRef<HTMLParagraphElement>(null);
  const canExcept = canOperate && f.state !== "excepted";

  return (
    <>
      <PageHeader
        title={f.signature || t("findings.detail.titleFallback", { id: f.id })}
        subtitle={
          <span className="flex flex-wrap items-center gap-2">
            <SeverityBadge severity={f.severity} />
            <StatusBadge kind="finding" state={f.state} />
            <span>
              {t(`findings.kind.${f.kind}`)}
              {f.category && ` · ${f.category}`}
            </span>
          </span>
        }
        actions={
          <div className="flex flex-wrap items-center gap-2">
            {back}
            {canExcept && !exceptionOpen && (
              <Button
                onClick={() => {
                  setMessage(null);
                  setExceptionOpen(true);
                }}
              >
                <ShieldCheck aria-hidden="true" className="size-4" />
                {t("findings.createException")}
              </Button>
            )}
          </div>
        }
      />

      <div className="flex flex-col gap-6">
        <StatusMessage ref={statusRef} message={message} />

        {exceptionOpen && (
          <Panel title={t("findings.exceptions.formTitle")}>
            <ExceptionForm
              initial={draftFromFinding(f)}
              hashAvailable={!!f.sha256}
              onCancel={() => setExceptionOpen(false)}
              onCreated={(e) => {
                setExceptionOpen(false);
                setMessage(t("findings.exceptions.created", { id: e.id }));
                // O formulário some: o foco vai para a confirmação, e não para o fim da página.
                requestAnimationFrame(() => statusRef.current?.focus());
              }}
            />
          </Panel>
        )}

        <div className="grid items-start gap-6 xl:grid-cols-[minmax(0,1fr)_24rem]">
          <div className="flex min-w-0 flex-col gap-6">
            <SummaryPanel finding={f} />
            {f.kind === "process" && f.process && <ProcessPanel process={f.process} />}
            {f.kind === "persistence" && f.persistence && <PersistencePanel entry={f.persistence} />}
            {(f.kind === "file" || detail.locations.length > 0) && <LocationsPanel locations={detail.locations} />}
            {Object.keys(f.evidence).length > 0 && (
              <Panel title={t("findings.detail.evidence")}>
                <dl className="m-0 grid gap-3 sm:grid-cols-2">
                  {Object.entries(f.evidence).map(([k, v]) => (
                    <DetailItem key={k} label={k}>
                      <PathText path={v} />
                    </DetailItem>
                  ))}
                </dl>
              </Panel>
            )}
          </div>

          <div className="flex min-w-0 flex-col gap-6">
            <Panel title={t("findings.transition.title")}>
              {canOperate ? (
                <>
                  <TransitionForm detail={detail} queryKey={queryKey} />
                  {(f.state === "new" || f.state === "in_review") && (
                    <p className="m-0 text-sm text-ink-muted">{t("findings.transition.exceptedHint")}</p>
                  )}
                </>
              ) : (
                <p className="m-0 text-ink-muted">{t("findings.transition.readOnly")}</p>
              )}
              {f.exception_id !== undefined && f.state === "excepted" && (
                <p className="m-0 text-sm">
                  {t("findings.detail.exceptionCovered", { id: f.exception_id })}{" "}
                  <Link to="/excecoes" className={linkClass}>
                    {t("findings.detail.exceptionLink")}
                  </Link>
                </p>
              )}
            </Panel>
            <HistoryPanel events={detail.events} />
          </div>
        </div>
      </div>
    </>
  );
}

function SummaryPanel({ finding: f }: { finding: Finding }) {
  const { t, i18n } = useTranslation();
  const lng = i18n.language;
  const optional: [string, ReactNode][] = [];
  if (f.source) optional.push([t("findings.detail.source"), f.source]);
  if (f.license) optional.push([t("findings.detail.license"), f.license]);
  if (f.author) optional.push([t("findings.detail.author"), f.author]);
  if (f.reference) optional.push([t("findings.detail.reference"), <ReferenceValue key="ref" value={f.reference} />]);
  if (f.file_type) optional.push([t("findings.detail.fileType"), f.file_type]);
  if (f.assignee) optional.push([t("findings.detail.assignee"), f.assignee]);

  return (
    <Panel title={t("findings.detail.summary")}>
      <div className="grid gap-1">
        <h3 className="m-0 text-base font-semibold">{t("findings.detail.description")}</h3>
        <p className="m-0 max-w-prose [overflow-wrap:anywhere]">
          {f.description || <span className="text-ink-muted">{t("findings.detail.noDescription")}</span>}
        </p>
      </div>
      <dl className="m-0 grid gap-4 sm:grid-cols-2 2xl:grid-cols-3">
        <DetailItem label={t("findings.detail.engine")}>
          <span className="font-mono">
            {f.engine} {f.engine_version}
          </span>
        </DetailItem>
        <DetailItem label={t("findings.detail.rulesVersion")}>
          <span className="font-mono">{f.rules_version || "—"}</span>
        </DetailItem>
        <DetailItem label={t("findings.detail.category")}>{f.category || "—"}</DetailItem>
        {f.sha256 && (
          <DetailItem label={t("findings.detail.hash")}>
            <HashText value={f.sha256} />
          </DetailItem>
        )}
        <DetailItem label={t("findings.detail.firstSeen")}>
          <Timestamp date={new Date(f.first_seen)} />
        </DetailItem>
        <DetailItem label={t("findings.detail.lastSeen")}>
          <Timestamp date={new Date(f.last_seen)} />
        </DetailItem>
        <DetailItem label={t("findings.detail.timesSeen")}>
          <span className="tabular-nums">{formatNumber(f.times_seen, lng)}</span>
        </DetailItem>
        <DetailItem label={t("findings.detail.stateChanged")}>
          <Timestamp date={new Date(f.state_changed)} />
        </DetailItem>
        <DetailItem label={t("findings.detail.firstRun")}>
          <RunLink id={f.first_run} />
        </DetailItem>
        <DetailItem label={t("findings.detail.lastRun")}>
          <RunLink id={f.last_run} />
        </DetailItem>
        {optional.map(([label, value]) => (
          <DetailItem key={label} label={label}>
            {value}
          </DetailItem>
        ))}
      </dl>
    </Panel>
  );
}

/** Execução: leva à lista de achados filtrada por ela. */
function RunLink({ id }: { id: string }) {
  if (!id) return <>—</>;
  return (
    <Link to={`/achados?state=all&run_id=${encodeURIComponent(id)}`} className={`font-mono ${linkClass}`}>
      {id}
    </Link>
  );
}

/** Referência da regra: vira link só se for http(s); qualquer outra coisa aparece como texto. */
function ReferenceValue({ value }: { value: string }) {
  const url = URL.canParse(value) ? new URL(value) : null;
  if (url && (url.protocol === "https:" || url.protocol === "http:")) {
    return (
      <a href={url.href} target="_blank" rel="noopener noreferrer" className={`[overflow-wrap:anywhere] ${linkClass}`}>
        {value}
      </a>
    );
  }
  return <PathText path={value} />;
}

function LocationsPanel({ locations }: { locations: Schemas["Location"][] }) {
  const { t, i18n } = useTranslation();
  const lng = i18n.language;
  return (
    <Panel title={`${t("findings.detail.locations")} (${formatNumber(locations.length, lng)})`}>
      {locations.length === 0 ? (
        <p className="m-0 text-ink-muted">{t("findings.detail.locationsEmpty")}</p>
      ) : (
        <div className="vh-table-wrap">
          <table className="vh-table">
            <caption className="visually-hidden">{t("findings.detail.locationsCaption")}</caption>
            <thead>
              <tr>
                <th scope="col">{t("findings.detail.path")}</th>
                <th scope="col">{t("findings.detail.owner")}</th>
                <th scope="col" className="text-end">
                  {t("findings.detail.size")}
                </th>
                <th scope="col">{t("findings.detail.mode")}</th>
                <th scope="col">{t("findings.detail.mtime")}</th>
              </tr>
            </thead>
            <tbody>
              {locations.map((l) => (
                <tr key={`${l.dev}:${l.ino}:${l.path}`}>
                  <td className="min-w-64">
                    <PathText path={l.path} />
                    {l.path_hex && (
                      <span className="mt-1 block text-sm text-ink-muted">
                        {t("findings.detail.pathHex")}{" "}
                        <code className="font-mono [overflow-wrap:anywhere]">{l.path_hex}</code>
                      </span>
                    )}
                  </td>
                  <td className="whitespace-nowrap tabular-nums">
                    {t("findings.detail.ownerValue", { uid: l.uid, gid: l.gid })}
                  </td>
                  <td className="text-end whitespace-nowrap tabular-nums">
                    {t("findings.detail.sizeValue", { bytes: formatNumber(l.size, lng) })}
                  </td>
                  <td className="font-mono">{formatMode(l.mode)}</td>
                  <td className="min-w-40">{l.mtime ? <Timestamp date={new Date(l.mtime)} /> : "—"}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </Panel>
  );
}

function List({ items }: { items: string[] | undefined }) {
  const { t } = useTranslation();
  if (!items || items.length === 0) return <>{t("findings.detail.none")}</>;
  return (
    <ul className="m-0 flex list-none flex-col gap-0.5 p-0">
      {items.map((v, i) => (
        <li key={`${i}:${v}`}>
          <PathText path={v} />
        </li>
      ))}
    </ul>
  );
}

function ProcessPanel({ process: p }: { process: Schemas["ProcessEvidence"] }) {
  const { t } = useTranslation();
  return (
    <Panel title={t("findings.detail.process")}>
      <dl className="m-0 grid gap-4 sm:grid-cols-2">
        <DetailItem label={t("findings.detail.pid")}>
          <span className="font-mono tabular-nums">{p.pid}</span>
        </DetailItem>
        <DetailItem label={t("findings.detail.ppid")}>
          <span className="font-mono tabular-nums">{p.ppid}</span>
        </DetailItem>
        <DetailItem label={t("findings.detail.uid")}>
          <span className="font-mono tabular-nums">{p.uid}</span>
        </DetailItem>
        <DetailItem label={t("findings.detail.comm")}>
          <PathText path={p.comm} />
        </DetailItem>
        <div className="sm:col-span-2">
          <DetailItem label={t("findings.detail.exe")}>
            <PathText path={p.exe} />
          </DetailItem>
        </div>
        {p.exe_sha256 && (
          <DetailItem label={t("findings.detail.exeSha256")}>
            <HashText value={p.exe_sha256} />
          </DetailItem>
        )}
        {p.cmdline && p.cmdline.length > 0 && (
          <div className="sm:col-span-2">
            <DetailItem label={t("findings.detail.cmdline")}>
              <span className="block rounded-control bg-sunken p-2">
                <PathText path={p.cmdline.join(" ")} />
              </span>
            </DetailItem>
          </div>
        )}
        {p.unit && (
          <DetailItem label={t("findings.detail.unit")}>
            <PathText path={p.unit} />
          </DetailItem>
        )}
        {p.cgroup && (
          <DetailItem label={t("findings.detail.cgroup")}>
            <PathText path={p.cgroup} />
          </DetailItem>
        )}
        {p.start_time && <DetailItem label={t("findings.detail.startTime")}>{p.start_time}</DetailItem>}
        <DetailItem label={t("findings.detail.listening")}>
          <List items={p.listening} />
        </DetailItem>
        <DetailItem label={t("findings.detail.connected")}>
          <List items={p.connected} />
        </DetailItem>
      </dl>
    </Panel>
  );
}

function PersistencePanel({ entry: p }: { entry: Schemas["PersistenceEntry"] }) {
  const { t } = useTranslation();
  return (
    <Panel title={t("findings.detail.persistence")}>
      <dl className="m-0 grid gap-4 sm:grid-cols-2">
        <DetailItem label={t("findings.detail.persistenceKind")}>{p.kind}</DetailItem>
        {p.change && (
          <DetailItem label={t("findings.detail.change.label")}>{t(`findings.detail.change.${p.change}`)}</DetailItem>
        )}
        <div className="sm:col-span-2">
          <DetailItem label={t("findings.detail.path")}>
            <PathText path={p.path} />
          </DetailItem>
        </div>
        {p.detail && (
          <div className="sm:col-span-2">
            <DetailItem label={t("findings.detail.persistenceDetail")}>
              <span className="block rounded-control bg-sunken p-2">
                <PathText path={p.detail} />
              </span>
            </DetailItem>
          </div>
        )}
        {p.sha256 && (
          <DetailItem label={t("findings.detail.hash")}>
            <HashText value={p.sha256} />
          </DetailItem>
        )}
        {p.owner && <DetailItem label={t("findings.detail.owner")}>{p.owner}</DetailItem>}
        {p.package && <DetailItem label={t("findings.detail.package")}>{p.package}</DetailItem>}
      </dl>
    </Panel>
  );
}

function isFindingState(v: string): v is FindingState {
  return (findingStateList as string[]).includes(v);
}

function StateText({ value }: { value: string }) {
  if (isFindingState(value)) return <StatusBadge kind="finding" state={value} />;
  return <span className="font-mono">{value || "—"}</span>;
}

function HistoryPanel({ events }: { events: Schemas["FindingEvent"][] }) {
  const { t } = useTranslation();
  // Mais recentes primeiro, como no restante do painel.
  const ordered = [...events].sort((a, b) => new Date(b.at).getTime() - new Date(a.at).getTime());
  return (
    <Panel title={t("findings.detail.history")}>
      {ordered.length === 0 ? (
        <p className="m-0 text-ink-muted">{t("findings.detail.historyEmpty")}</p>
      ) : (
        <ol className="m-0 flex list-none flex-col gap-4 p-0">
          {ordered.map((e, i) => (
            <li key={`${e.at}:${i}`} className="flex min-w-0 flex-col gap-1 border-s-2 border-line-strong ps-3">
              <Timestamp date={new Date(e.at)} compact />
              <span className="font-semibold [overflow-wrap:anywhere]">{t("findings.detail.eventBy", { actor: e.actor })}</span>
              {(e.from || e.to) && (
                <span className="flex flex-wrap items-center gap-1.5 text-sm">
                  <EventChange from={e.from} to={e.to} />
                </span>
              )}
              {e.note && <p className="m-0 text-sm [overflow-wrap:anywhere]">{e.note}</p>}
            </li>
          ))}
        </ol>
      )}
    </Panel>
  );
}

/** "de [Novo] para [Em análise]" com os selos no lugar dos marcadores da tradução. */
function EventChange({ from, to }: { from: string; to: string }) {
  const { t } = useTranslation();
  const text = t("findings.detail.eventChange", { from: FROM_MARK, to: TO_MARK });
  const parts = text.split(/(\[\[from\]\]|\[\[to\]\])/);
  return (
    <>
      {parts.map((p, i) =>
        p === FROM_MARK ? (
          <StateText key={i} value={from} />
        ) : p === TO_MARK ? (
          <StateText key={i} value={to} />
        ) : (
          p.trim() && <span key={i}>{p.trim()}</span>
        ),
      )}
    </>
  );
}

const FROM_MARK = "[[from]]";
const TO_MARK = "[[to]]";

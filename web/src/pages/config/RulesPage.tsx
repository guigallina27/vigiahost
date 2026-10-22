import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import {
  Ban,
  BookOpen,
  CircleCheck,
  CircleDashed,
  CircleX,
  Clock,
  Hammer,
  Lock,
  LoaderCircle,
  PlugZap,
  Power,
  PowerOff,
  RefreshCw,
  ServerCrash,
  TriangleAlert,
  type LucideIcon,
} from "lucide-react";
import { useState, type ReactNode } from "react";
import { useTranslation } from "react-i18next";
import { Link } from "react-router";
import { ApiError, type Schemas } from "../../api/client";
import { useCurrentUser } from "../../auth/session";
import { Badge, type Tone } from "../../components/Badge";
import { Button } from "../../components/Button";
import { ConfirmDialog } from "../../components/ConfirmDialog";
import { EmptyState } from "../../components/EmptyState";
import { EngineHealth } from "../../components/EngineHealth";
import { HashText } from "../../components/HashText";
import { Panel } from "../../components/Panel";
import { PathText } from "../../components/PathText";
import { TableScroll } from "../../components/TableScroll";
import { Timestamp } from "../../components/Timestamp";
import { formatNumber } from "../../lib/format";
import { PageHeader } from "../../layout/PageHeader";
import { retryTransient } from "./queries";
import { compileRules, rulesQuery, setLmd, setRuleSource } from "./rulesQueries";
import { useGuardedAction } from "./useGuardedAction";

type Overview = Schemas["RulesOverview"];
type Source = Schemas["RuleSource"];
type SourceState = Schemas["RuleSourceState"];
type Lmd = Schemas["LmdStatus"];

const sourceStates: Record<SourceState, { tone: Tone; icon: LucideIcon }> = {
  ok: { tone: "ok", icon: CircleCheck },
  error: { tone: "critical", icon: CircleX },
  refused: { tone: "high", icon: Ban },
  disabled: { tone: "neutral", icon: PowerOff },
  pending: { tone: "medium", icon: Clock },
};

/** Orientação sobre o LMD conforme o que a API informa (o produto nunca instala ferramentas de terceiros). */
export type LmdGuidance = "missing" | "unusable" | "unavailable" | "selftestFailed" | null;

export function lmdGuidance(l: Lmd): LmdGuidance {
  if (l.state === "unavailable" && l.enabled) return "unavailable";
  if (!l.installed) return "missing";
  if (!l.usable) return "unusable";
  if (l.last_selftest && !l.last_selftest.passed) return "selftestFailed";
  return null;
}

type Toggle = { kind: "source"; source: Source; enabled: boolean } | { kind: "lmd"; enabled: boolean } | null;

/** Fontes de regras YARA, assinaturas do ClamAV e do LMD (rota: /regras). */
export function RulesPage() {
  const { t } = useTranslation();
  const qc = useQueryClient();
  const { isAdmin } = useCurrentUser();
  const q = useQuery({ ...rulesQuery, retry: retryTransient });
  const [notice, setNotice] = useState<string | null>(null);
  const [toggle, setToggle] = useState<Toggle>(null);

  const done = (data: Overview, message: string) => {
    qc.setQueryData(rulesQuery.queryKey, data);
    void qc.invalidateQueries({ queryKey: ["engines"] });
    setNotice(message);
  };
  const compile = useMutation({
    mutationFn: compileRules,
    onSuccess: (data) => done(data, t("rules.compileStarted")),
    onError: (err) => setNotice(err instanceof ApiError && err.status === 409 ? t("rules.compileBusy") : err.message),
  });

  const compiling = q.data?.yara.compiling ?? false;
  const actions = q.data && (
    <div className="flex flex-wrap gap-2">
      <Button variant="secondary" onClick={() => void q.refetch()} disabled={q.isFetching}>
        <RefreshCw aria-hidden="true" className={`size-4 ${q.isFetching ? "motion-safe:animate-spin" : ""}`} />
        {t("rules.refresh")}
      </Button>
      {isAdmin && (
        <Button
          variant="primary"
          onClick={() => {
            setNotice(null);
            compile.mutate();
          }}
          disabled={compile.isPending || compiling}
        >
          <Hammer aria-hidden="true" className="size-4" />
          {t("rules.compile")}
        </Button>
      )}
    </div>
  );

  return (
    <>
      <PageHeader title={t("rules.title")} subtitle={t("rules.subtitle")} actions={actions} />
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
          {q.data.executor_error && (
            <div role="alert" className="flex items-start gap-3 rounded-panel border border-(--vh-critical-fg) bg-(--vh-critical-bg) p-4 text-(--vh-critical-fg)">
              <ServerCrash aria-hidden="true" className="mt-0.5 size-5 shrink-0" />
              <div className="min-w-0">
                <p className="m-0 font-semibold">{t("rules.executorDown")}</p>
                <p className="m-0 mt-1 font-mono text-sm [overflow-wrap:anywhere]">{q.data.executor_error}</p>
              </div>
            </div>
          )}
          {!isAdmin && (
            <p className="m-0 flex items-start gap-2 text-sm text-ink-muted">
              <Lock aria-hidden="true" className="mt-0.5 size-4 shrink-0" />
              {t("rules.adminOnly")}
            </p>
          )}
          <CompilePanel data={q.data} />
          <SourcesPanel
            data={q.data}
            isAdmin={isAdmin}
            onToggle={(source, enabled) => {
              setNotice(null);
              setToggle({ kind: "source", source, enabled });
            }}
          />
          <div className="grid min-w-0 gap-6 xl:grid-cols-2">
            <ClamavPanel data={q.data} />
            <LmdPanel
              lmd={q.data.lmd}
              isAdmin={isAdmin}
              onToggle={(enabled) => {
                setNotice(null);
                setToggle({ kind: "lmd", enabled });
              }}
            />
          </div>
        </div>
      )}
      <ToggleDialog toggle={toggle} onClose={() => setToggle(null)} onDone={done} />
    </>
  );
}

export default RulesPage;

function Row({ label, children }: { label: string; children: ReactNode }) {
  return (
    <>
      <dt className="text-sm text-ink-muted">{label}</dt>
      <dd className="m-0 min-w-0 [overflow-wrap:anywhere]">{children}</dd>
    </>
  );
}

function Unknown() {
  const { t } = useTranslation();
  return <span className="text-ink-muted">{t("config.engines.unknown")}</span>;
}

function CompilePanel({ data }: { data: Overview }) {
  const { t } = useTranslation();
  const last = data.yara.last_compile;
  return (
    <Panel
      title={t("rules.lastCompile.title")}
      actions={
        data.yara.compiling && (
          <Badge tone="neutral" icon={LoaderCircle} variant="outline" spinning>
            {t("rules.compiling")}
          </Badge>
        )
      }
    >
      {!last ? (
        <p className="m-0 text-ink-muted">{t("rules.lastCompile.none")}</p>
      ) : (
        <dl className="m-0 grid grid-cols-[auto_minmax(0,1fr)] items-baseline gap-x-4 gap-y-2">
          <Row label={t("rules.lastCompile.when")}>
            <Timestamp date={new Date(last.at)} compact />
          </Row>
          <Row label={t("rules.lastCompile.trigger")}>{t(`rules.lastCompile.triggers.${last.trigger}`)}</Row>
          <Row label={t("rules.lastCompile.result")}>
            <span className="flex min-w-0 flex-col items-start gap-1">
              {last.ok ? (
                <Badge tone="ok" icon={CircleCheck} variant="outline">
                  {t("rules.lastCompile.ok")}
                </Badge>
              ) : (
                <Badge tone="critical" icon={CircleX} variant="outline">
                  {t("rules.lastCompile.failed")}
                </Badge>
              )}
              {last.error && <span className="font-mono text-sm">{last.error}</span>}
            </span>
          </Row>
          <Row label={t("rules.lastCompile.setVersion")}>{last.set_version ? <code>{last.set_version}</code> : <Unknown />}</Row>
          <Row label={t("rules.lastCompile.yrVersion")}>
            {last.yr_version ?? data.yara.yr_version ? <code>{last.yr_version ?? data.yara.yr_version}</code> : <Unknown />}
          </Row>
          <Row label={t("rules.lastCompile.selftest")}>
            {last.selftest === undefined ? (
              <span className="text-sm text-ink-muted">{t("rules.lastCompile.selftestNotRun")}</span>
            ) : (
              <span className="flex min-w-0 flex-col items-start gap-1">
                {last.selftest ? (
                  <Badge tone="ok" icon={CircleCheck} variant="outline">
                    {t("rules.lastCompile.selftestPassed")}
                  </Badge>
                ) : (
                  <Badge tone="critical" icon={CircleX} variant="outline">
                    {t("rules.lastCompile.selftestFailed")}
                  </Badge>
                )}
                {last.detail && <span className="text-sm">{last.detail}</span>}
              </span>
            )}
          </Row>
        </dl>
      )}
    </Panel>
  );
}

function SourcesPanel({ data, isAdmin, onToggle }: { data: Overview; isAdmin: boolean; onToggle: (s: Source, enabled: boolean) => void }) {
  const { t, i18n } = useTranslation();
  const lng = i18n.language;
  const sources = data.yara.sources;
  return (
    <Panel title={t("rules.sources.title")}>
      {sources.length === 0 ? (
        <EmptyState icon={BookOpen} title={t("rules.sources.empty")} description={t("rules.sources.emptyDescription")} />
      ) : (
        <TableScroll label={t("rules.sources.caption")}>
          <table className="vh-table">
            <caption className="visually-hidden">{t("rules.sources.caption")}</caption>
            <thead>
              <tr>
                <th scope="col">{t("rules.sources.colSource")}</th>
                <th scope="col">{t("rules.sources.colLicense")}</th>
                <th scope="col">{t("rules.sources.colRules")}</th>
                <th scope="col">{t("rules.sources.colUpdated")}</th>
                <th scope="col">{t("rules.sources.colHash")}</th>
                <th scope="col">{t("rules.sources.colState")}</th>
                {isAdmin && <th scope="col">{t("rules.sources.colActions")}</th>}
              </tr>
            </thead>
            <tbody>
              {sources.map((s) => {
                const st = sourceStates[s.state];
                return (
                  <tr key={`${s.origin}:${s.name}`}>
                    <th scope="row" className="min-w-48 text-left font-normal">
                      <span className="grid gap-1">
                        <span className="flex flex-wrap items-center gap-2">
                          <code className="font-semibold">{s.name}</code>
                          <span className="text-sm text-ink-muted">{t(`rules.sources.origin.${s.origin}`)}</span>
                          {s.version && <span className="text-sm text-ink-muted">{t("rules.sources.version", { version: s.version })}</span>}
                        </span>
                        {s.description && <span className="text-sm [overflow-wrap:anywhere]">{s.description}</span>}
                        {s.path && (
                          <span className="text-sm text-ink-muted">
                            <PathText path={s.path} />
                          </span>
                        )}
                      </span>
                    </th>
                    <td className="min-w-28">
                      {s.license ? <span className="[overflow-wrap:anywhere]">{s.license}</span> : <span className="text-ink-muted">{t("rules.sources.noLicense")}</span>}
                    </td>
                    <td className="min-w-36">
                      {t("rules.sources.rulesFiles", { count: s.files, rules: formatNumber(s.rules, lng) })}
                    </td>
                    <td className="min-w-36">{s.updated_at ? <Timestamp date={new Date(s.updated_at)} compact /> : <Unknown />}</td>
                    <td>{s.hash ? <HashText value={s.hash} /> : <Unknown />}</td>
                    <td className="min-w-40">
                      <span className="flex min-w-0 flex-col items-start gap-1">
                        <Badge tone={st.tone} icon={st.icon} variant="outline">
                          {t(`rules.sources.states.${s.state}`)}
                        </Badge>
                        {s.problem && <span className="font-mono text-sm [overflow-wrap:anywhere]">{s.problem}</span>}
                      </span>
                    </td>
                    {isAdmin && (
                      <td>
                        {s.mandatory ? (
                          <span className="text-sm text-ink-muted">{t("rules.sources.mandatory")}</span>
                        ) : (
                          <Button variant="secondary" onClick={() => onToggle(s, !s.enabled)} aria-label={`${t(s.enabled ? "rules.sources.disable" : "rules.sources.enable")} ${s.name}`}>
                            {s.enabled ? <PowerOff aria-hidden="true" className="size-4" /> : <Power aria-hidden="true" className="size-4" />}
                            {t(s.enabled ? "rules.sources.disable" : "rules.sources.enable")}
                          </Button>
                        )}
                      </td>
                    )}
                  </tr>
                );
              })}
            </tbody>
          </table>
        </TableScroll>
      )}
      <p className="m-0 text-sm text-ink-muted">
        <DirText text={t("rules.sources.userDir", { dir: "\u0000" })} dir={data.yara.user_dir} />
      </p>
    </Panel>
  );
}

/** Insere o diretório, em <code>, no ponto marcado do texto traduzido. */
function DirText({ text, dir }: { text: string; dir: string }) {
  const [before, after] = text.split("\u0000");
  return (
    <>
      {before}
      <code className="rounded-sm bg-sunken px-1 py-0.5 text-ink">{dir}</code>
      {after}
    </>
  );
}

function ClamavPanel({ data }: { data: Overview }) {
  const { t } = useTranslation();
  const c = data.clamav;
  return (
    <Panel title={t("rules.clamav.title")}>
      <EngineHealth name="ClamAV" health={c.state} {...(c.version ? { version: c.version } : {})} {...(c.detail ? { detail: c.detail } : {})} />
      <dl className="m-0 grid grid-cols-[auto_minmax(0,1fr)] items-baseline gap-x-4 gap-y-2">
        <Row label={t("config.engines.signaturesVersion")}>{c.signatures_version ? <code>{c.signatures_version}</code> : <Unknown />}</Row>
        <Row label={t("config.engines.signaturesDate")}>{c.signatures_date ? <code>{c.signatures_date}</code> : <Unknown />}</Row>
        <Row label={t("rules.clamav.mode")}>{c.mode ? <code>{c.mode}</code> : <Unknown />}</Row>
      </dl>
      {c.lmd_signatures.length > 0 && (
        <div className="rounded-control border border-line-strong bg-sunken p-3 text-sm">
          <p className="m-0">{t("rules.clamav.lmdLinked")}</p>
          <ul className="m-0 mt-1 flex list-none flex-col gap-0.5 p-0">
            {c.lmd_signatures.map((p) => (
              <li key={p}>
                <PathText path={p} />
              </li>
            ))}
          </ul>
          <p className="m-0 mt-1">{t("rules.clamav.lmdLinkedNote")}</p>
        </div>
      )}
    </Panel>
  );
}

function LmdPanel({ lmd: l, isAdmin, onToggle }: { lmd: Lmd; isAdmin: boolean; onToggle: (enabled: boolean) => void }) {
  const { t, i18n } = useTranslation();
  const lng = i18n.language;
  const guidance = lmdGuidance(l);
  const st = l.last_selftest;
  const n = (v: number) => formatNumber(v, lng);
  const canEnable = l.usable && !l.enabled;
  return (
    <Panel
      title={t("rules.lmd.title")}
      actions={
        isAdmin &&
        (l.enabled || canEnable) && (
          <Button variant="secondary" onClick={() => onToggle(!l.enabled)}>
            {l.enabled ? <PowerOff aria-hidden="true" className="size-4" /> : <Power aria-hidden="true" className="size-4" />}
            {t(l.enabled ? "rules.lmd.disable" : "rules.lmd.enable")}
          </Button>
        )
      }
    >
      <p className="m-0 text-sm text-ink-muted">{t("rules.lmd.role")}</p>
      <EngineHealth name="LMD" health={l.state} {...(l.version ? { version: l.version } : {})} {...(l.detail ? { detail: l.detail } : {})} />
      <dl className="m-0 grid grid-cols-[auto_minmax(0,1fr)] items-baseline gap-x-4 gap-y-2">
        <Row label={t("rules.lmd.enabled")}>
          {l.enabled ? (
            <Badge tone="neutral" icon={Power} variant="outline">
              {t("rules.lmd.on")}
            </Badge>
          ) : (
            <Badge tone="neutral" icon={PowerOff} variant="outline">
              {t("rules.lmd.off")}
            </Badge>
          )}
        </Row>
        <Row label={t("rules.lmd.path")}>{l.installed ? <PathText path={l.path} /> : <span className="text-ink-muted">{t("rules.lmd.notInstalled")}</span>}</Row>
        {l.installed && (
          <>
            <Row label={t("rules.lmd.signaturesVersion")}>{l.signatures_version ? <code>{l.signatures_version}</code> : <Unknown />}</Row>
            <Row label={t("rules.lmd.signaturesDate")}>{l.signatures_date ? <code>{l.signatures_date}</code> : <Unknown />}</Row>
            <Row label={t("rules.lmd.signatures")}>
              {l.signatures ? (
                t("rules.lmd.counts", {
                  md5: n(l.signatures.md5),
                  sha256: n(l.signatures.sha256),
                  hex: n(l.signatures.hex),
                  csig: n(l.signatures.csig),
                  yara: n(l.signatures.yara),
                  user: n(l.signatures.user),
                })
              ) : (
                <Unknown />
              )}
            </Row>
          </>
        )}
        <Row label={t("config.engines.selftest")}>
          {!st ? (
            <span className="text-ink-muted">{t("config.engines.selftestNone")}</span>
          ) : (
            <span className="flex min-w-0 flex-col items-start gap-1">
              {st.passed ? (
                <Badge tone="ok" icon={CircleCheck} variant="outline">
                  {t("config.engines.selftestPassed")}
                </Badge>
              ) : (
                <Badge tone="critical" icon={CircleX} variant="outline">
                  {t("config.engines.selftestFailed")}
                </Badge>
              )}
              {st.detail && <span className="text-sm">{st.detail}</span>}
              <span className="text-sm text-ink-muted">
                {t("config.engines.selftestRun")}{" "}
                <Link to={`/execucoes/${st.run_id}`} className="font-mono font-semibold text-accent underline underline-offset-4">
                  {st.run_id}
                </Link>
              </span>
            </span>
          )}
        </Row>
      </dl>
      {guidance && (
        <p className="m-0 flex items-start gap-2 rounded-control border border-line-strong bg-sunken p-3 text-sm">
          {guidance === "missing" ? (
            <CircleDashed aria-hidden="true" className="mt-0.5 size-4 shrink-0" />
          ) : (
            <TriangleAlert aria-hidden="true" className="mt-0.5 size-4 shrink-0" />
          )}
          <span>{t(`rules.lmd.guidance.${guidance}`)}</span>
        </p>
      )}
    </Panel>
  );
}

function ToggleDialog({ toggle, onClose, onDone }: { toggle: Toggle; onClose: () => void; onDone: (d: Overview, msg: string) => void }) {
  const { t } = useTranslation();
  const guarded = useGuardedAction(true);
  // Mantém o texto da última ação enquanto o diálogo fecha (sem trocar rótulos no meio do fechamento).
  const [shown, setShown] = useState<Toggle>(toggle);
  if (toggle && toggle !== shown) setShown(toggle);
  const on = shown?.enabled ?? false;
  const isSource = shown?.kind === "source";
  const name = shown?.kind === "source" ? shown.source.name : "LMD";
  const prefix = isSource ? "rules.sources" : "rules.lmd";
  return (
    <ConfirmDialog
      open={toggle !== null}
      onClose={onClose}
      onConfirm={async (input) => {
        if (!toggle) return;
        await guarded.run(input, async () => {
          const data = toggle.kind === "source" ? await setRuleSource(toggle.source.name, toggle.enabled) : await setLmd(toggle.enabled);
          const msg = toggle.kind === "source" ? t("rules.sources.toggled", { name }) : t(toggle.enabled ? "rules.lmd.toggledOn" : "rules.lmd.toggledOff");
          onDone(data, msg);
        });
        onClose();
      }}
      title={t(`${prefix}.${on ? "enableTitle" : "disableTitle"}`)}
      object={<code className="[overflow-wrap:anywhere]">{name}</code>}
      impact={t(`${prefix}.${on ? "enableImpact" : "disableImpact"}`)}
      reversible
      destructive={!on}
      requireReauth={guarded.requireReauth}
      requireCode={guarded.requireCode}
      confirmLabel={t(`${prefix}.${on ? "enable" : "disable"}`)}
    />
  );
}

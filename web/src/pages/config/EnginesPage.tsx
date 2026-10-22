import { useQuery } from "@tanstack/react-query";
import { CircleCheck, CircleX, PlugZap, RefreshCw, ServerCrash, SlidersHorizontal } from "lucide-react";
import type { ReactNode } from "react";
import { useTranslation } from "react-i18next";
import { Link } from "react-router";
import type { Schemas } from "../../api/client";
import { Badge } from "../../components/Badge";
import { Button } from "../../components/Button";
import { EmptyState } from "../../components/EmptyState";
import { EngineHealth } from "../../components/EngineHealth";
import { Timestamp } from "../../components/Timestamp";
import { formatRelative } from "../../lib/format";
import { PageHeader } from "../../layout/PageHeader";
import { enginesQuery, retryTransient } from "./queries";

type Engine = Schemas["EngineHealth"];

/** Orientação para o operador conforme o estado do motor; só usa o que a API informa. */
export type EngineGuidance =
  | "executorDown"
  | "clamdFallback"
  | "selftestFailed"
  | "yaraMissing"
  | "clamavMissing"
  | "lmdMissing"
  | "lmdDisabled"
  | "lmdUnavailable"
  | null;

export function engineGuidance(e: Engine, executorError: string | undefined): EngineGuidance {
  if (executorError) return "executorDown";
  if (e.state === "operational") return null;
  // LMD é opcional: desligado ou ausente não é falha; a tela Regras e fontes traz a orientação completa.
  if (e.state === "not_installed") return "lmdMissing";
  if (e.state === "disabled") return "lmdDisabled";
  if (e.last_selftest && !e.last_selftest.passed) return "selftestFailed";
  if (e.id === "clamav" && e.mode === "clamscan") return "clamdFallback";
  if (e.state === "unavailable") return e.id === "clamav" ? "clamavMissing" : e.id === "lmd" ? "lmdUnavailable" : "yaraMissing";
  return null;
}

/** Saúde dos motores de detecção (rota sugerida: /motores). */
export function EnginesPage() {
  const { t } = useTranslation();
  const q = useQuery({ ...enginesQuery, retry: retryTransient });
  return (
    <>
      <PageHeader
        title={t("config.engines.title")}
        subtitle={t("config.engines.subtitle")}
        actions={
          q.data && (
            <Button variant="secondary" onClick={() => void q.refetch()} disabled={q.isFetching}>
              <RefreshCw aria-hidden="true" className={`size-4 ${q.isFetching ? "motion-safe:animate-spin" : ""}`} />
              {t("config.engines.refresh")}
            </Button>
          )
        }
      />
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
          {q.data.executor_error && (
            <div role="alert" className="flex items-start gap-3 rounded-panel border border-(--vh-critical-fg) bg-(--vh-critical-bg) p-4 text-(--vh-critical-fg)">
              <ServerCrash aria-hidden="true" className="mt-0.5 size-5 shrink-0" />
              <div className="min-w-0">
                <p className="m-0 font-semibold">{t("config.engines.executorDown")}</p>
                <p className="m-0 mt-1 font-mono text-sm [overflow-wrap:anywhere]">{q.data.executor_error}</p>
                <p className="m-0 mt-2 text-sm">
                  <Command text={t("config.engines.executorDownAction", { command: "\u0000" })} command="systemctl status vigiahost-executor" />
                </p>
              </div>
            </div>
          )}
          {q.data.engines.length === 0 ? (
            <EmptyState icon={SlidersHorizontal} title={t("config.engines.emptyTitle")} description={t("config.engines.emptyDescription")} />
          ) : (
            <ul className="m-0 grid list-none gap-6 p-0 xl:grid-cols-2">
              {q.data.engines.map((e) => (
                <li key={e.id} className="min-w-0">
                  <EngineCard engine={e} executorError={q.data.executor_error} />
                </li>
              ))}
            </ul>
          )}
          <p className="m-0 text-sm text-ink-muted">
            {t("config.engines.cacheNote")} <Timestamp date={new Date(q.dataUpdatedAt)} compact />
          </p>
        </div>
      )}
    </>
  );
}

export default EnginesPage;

/** Insere o comando, em <code>, no ponto marcado do texto traduzido. */
function Command({ text, command }: { text: string; command: string }) {
  const [before, after] = text.split("\u0000");
  return (
    <>
      {before}
      <code className="rounded-sm bg-surface px-1 py-0.5 text-ink">{command}</code>
      {after}
    </>
  );
}

function Row({ label, children }: { label: string; children: ReactNode }) {
  return (
    <>
      <dt className="text-sm text-ink-muted">{label}</dt>
      <dd className="m-0 min-w-0 break-words">{children}</dd>
    </>
  );
}

function EngineCard({ engine: e, executorError }: { engine: Engine; executorError: string | undefined }) {
  const { t, i18n } = useTranslation();
  const lng = i18n.language;
  const guidance = engineGuidance(e, executorError);
  const sigDate = e.signatures_date ? new Date(e.signatures_date) : null;
  const sigAge = sigDate && !Number.isNaN(sigDate.getTime()) ? formatRelative(sigDate, lng) : null;
  const st = e.last_selftest;

  return (
    <article className="flex h-full min-w-0 flex-col gap-3" aria-label={e.name}>
      <EngineHealth
        name={e.name}
        health={e.state}
        {...(e.version ? { version: e.version } : {})}
        {...(e.detail ? { detail: e.detail } : {})}
      />
      <div className="flex min-w-0 flex-col gap-3 rounded-panel border border-line bg-surface p-4 shadow-panel">
        <dl className="m-0 grid grid-cols-[auto_minmax(0,1fr)] items-baseline gap-x-4 gap-y-2">
          {e.id === "yara-x" && (
            <Row label={t("config.engines.rulesVersion")}>
              {e.rules_version ? <code>{e.rules_version}</code> : <span className="text-ink-muted">{t("config.engines.rulesUnknown")}</span>}
            </Row>
          )}
          {(e.id === "clamav" || e.id === "lmd") && (
            <>
              <Row label={t("config.engines.signaturesVersion")}>
                {e.signatures_version ? <code>{e.signatures_version}</code> : <span className="text-ink-muted">{t("config.engines.unknown")}</span>}
              </Row>
              <Row label={t("config.engines.signaturesDate")}>
                {e.signatures_date ? (
                  <span>
                    <code>{e.signatures_date}</code>
                    {sigAge && <span className="text-ink-muted"> · {sigAge}</span>}
                  </span>
                ) : (
                  <span className="text-ink-muted">{t("config.engines.unknown")}</span>
                )}
              </Row>
              {e.id === "clamav" && (
              <Row label={t("config.engines.mode")}>
                {e.mode === "clamd"
                  ? t("config.engines.modeClamd")
                  : e.mode === "clamscan"
                    ? t("config.engines.modeClamscan")
                    : <span className="text-ink-muted">{t("config.engines.unknown")}</span>}
              </Row>
              )}
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
                {st.detail && <span className="text-sm [overflow-wrap:anywhere]">{st.detail}</span>}
                <span className="text-sm text-ink-muted">
                  {t("config.engines.selftestRun")}{" "}
                  <Link to={`/execucoes/${st.run_id}`} className="font-mono font-semibold text-accent underline underline-offset-4">
                    {st.run_id}
                  </Link>
                  {st.at && (
                    <>
                      {" · "}
                      <Timestamp date={new Date(st.at)} compact />
                    </>
                  )}
                </span>
              </span>
            )}
          </Row>
        </dl>
        {guidance && guidance !== "executorDown" && (
          <p className="m-0 rounded-control border border-line-strong bg-sunken p-3 text-sm">
            {t(`config.engines.guidance.${guidance}`)}
            {e.id === "lmd" && (
              <>
                {" "}
                <Link to="/regras" className="font-semibold text-accent underline underline-offset-4">
                  {t("config.engines.openRules")}
                </Link>
              </>
            )}
          </p>
        )}
      </div>
    </article>
  );
}

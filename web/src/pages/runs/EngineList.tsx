import { FlaskConical, FlaskConicalOff } from "lucide-react";
import type { ReactNode } from "react";
import { useTranslation } from "react-i18next";
import { Link } from "react-router";
import type { Schemas } from "../../api/client";
import { Badge } from "../../components/Badge";
import { EngineHealth } from "../../components/EngineHealth";
import { Timestamp } from "../../components/Timestamp";
import { toDate } from "./runFormat";

type EngineInfo = Schemas["EngineHealth"];

/** Motores com saúde, versões, assinaturas e o último autoteste. Também usado na Visão geral. */
export function EngineList({ engines }: { engines: EngineInfo[] }) {
  return (
    <ul className="m-0 grid list-none items-start gap-4 p-0 md:grid-cols-2">
      {engines.map((e) => (
        <li key={e.id} className="flex min-w-0 flex-col gap-2">
          <EngineHealth name={e.name} health={e.state} {...(e.version ? { version: e.version } : {})} {...(e.detail ? { detail: e.detail } : {})} />
          <EngineExtras engine={e} />
        </li>
      ))}
    </ul>
  );
}

function Extra({ label, children }: { label: string; children: ReactNode }) {
  return (
    <>
      <dt className="text-ink-muted">{label}</dt>
      <dd className="m-0 min-w-0 [overflow-wrap:anywhere]">{children}</dd>
    </>
  );
}

function EngineExtras({ engine }: { engine: EngineInfo }) {
  const { t } = useTranslation();
  const signaturesDate = toDate(engine.signatures_date);
  const selftest = engine.last_selftest;
  const selftestAt = toDate(selftest?.at);
  if (!engine.mode && !engine.rules_version && !engine.signatures_version && !selftest) return null;
  return (
    <dl className="m-0 grid grid-cols-[auto_minmax(0,1fr)] gap-x-3 gap-y-1.5 px-4 text-sm">
      {engine.mode && (
        <Extra label={t("runs.coverage.mode")}>
          <span className="font-mono">{engine.mode}</span>
        </Extra>
      )}
      {engine.rules_version && (
        <Extra label={t("runs.coverage.rulesVersion")}>
          <span className="font-mono">{engine.rules_version}</span>
        </Extra>
      )}
      {engine.signatures_version && (
        <Extra label={t("runs.coverage.signatures")}>
          <span className="font-mono">{engine.signatures_version}</span>
        </Extra>
      )}
      {engine.signatures_date && (
        <Extra label={t("runs.coverage.signaturesDate")}>
          {signaturesDate ? <Timestamp date={signaturesDate} compact /> : <span className="font-mono">{engine.signatures_date}</span>}
        </Extra>
      )}
      {selftest && (
        <Extra label={t("runs.coverage.lastSelftest")}>
          <span className="flex flex-wrap items-center gap-x-2 gap-y-1">
            {selftest.passed ? (
              <Badge tone="ok" icon={FlaskConical} variant="outline">
                {t("runs.coverage.selftestPassed")}
              </Badge>
            ) : (
              <Badge tone="critical" icon={FlaskConicalOff} variant="outline">
                {t("runs.coverage.selftestFailed")}
              </Badge>
            )}
            {selftestAt && <Timestamp date={selftestAt} compact />}
            <Link to={`/execucoes/${encodeURIComponent(selftest.run_id)}`} className="font-mono [overflow-wrap:anywhere]">
              {t("runs.coverage.selftestRun", { id: selftest.run_id })}
            </Link>
          </span>
          {selftest.detail && <span className="block text-ink-muted">{selftest.detail}</span>}
        </Extra>
      )}
    </dl>
  );
}

import { CircleCheck, CircleX, Clock, RefreshCw, TriangleAlert, type LucideIcon } from "lucide-react";
import { useTranslation } from "react-i18next";
import { Badge, type Tone } from "./Badge";
import { Timestamp } from "./Timestamp";

export type Health = "operational" | "degraded" | "unavailable";
export type UpdateState = "current" | "late";

const health: Record<Health, { tone: Tone; icon: LucideIcon }> = {
  operational: { tone: "ok", icon: CircleCheck },
  degraded: { tone: "medium", icon: TriangleAlert },
  unavailable: { tone: "critical", icon: CircleX },
};

type Props = {
  name: string;
  version?: string;
  health: Health;
  /** Atualização é outra dimensão: um motor operacional pode estar com assinaturas atrasadas. */
  update?: UpdateState;
  lastUpdate?: Date;
  timeZone?: string;
  detail?: string;
};

/** Saúde e atualização de um motor, em dimensões separadas (corrige a mistura do preview, seção 14.2). */
export function EngineHealth({ name, version, health: h, update, lastUpdate, timeZone, detail }: Props) {
  const { t } = useTranslation();
  const { tone, icon } = health[h];
  return (
    <div className="flex min-w-0 flex-col gap-2 rounded-panel border border-line bg-surface p-4 shadow-panel">
      <div className="flex min-w-0 flex-wrap items-baseline gap-x-2">
        <h3 className="m-0 text-base font-bold break-words">{name}</h3>
        {version && <span className="font-mono text-sm text-ink-muted">{version}</span>}
      </div>
      <dl className="m-0 grid grid-cols-[auto_minmax(0,1fr)] items-center gap-x-3 gap-y-1.5 text-sm">
        <dt className="text-ink-muted">{t("engineHealth.label")}</dt>
        <dd className="m-0">
          <Badge tone={tone} icon={icon}>
            {t(`engineHealth.${h}`)}
          </Badge>
        </dd>
        {update && (
          <>
            <dt className="text-ink-muted">{t("engineUpdate.label")}</dt>
            <dd className="m-0 flex flex-wrap items-center gap-2">
              <Badge tone={update === "current" ? "ok" : "high"} icon={update === "current" ? RefreshCw : Clock} variant="outline">
                {t(`engineUpdate.${update}`)}
              </Badge>
              {lastUpdate && <Timestamp date={lastUpdate} {...(timeZone ? { timeZone } : {})} compact />}
            </dd>
          </>
        )}
      </dl>
      {detail && <p className="m-0 text-sm text-ink-muted">{detail}</p>}
    </div>
  );
}

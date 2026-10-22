import { Cpu, FolderSearch, Pause } from "lucide-react";
import { useTranslation } from "react-i18next";
import type { Schemas } from "../../api/client";
import { Badge } from "../../components/Badge";
import { StatusBadge } from "../../components/StatusBadge";
import { formatNumber } from "../../lib/format";
import { durationSeconds, formatBytes, formatDuration, type Run, type RunKind } from "./runFormat";

type ResourceProfile = Schemas["ResourceProfile"];

const PRESETS = ["leve", "padrao", "intensivo"] as const;

/** Nome do perfil para exibição: os pré-definidos traduzidos, os personalizados como foram gravados. */
export function useProfileLabel() {
  const { t } = useTranslation();
  return (name: string) => ((PRESETS as readonly string[]).includes(name) ? t(`runs.profiles.${name as (typeof PRESETS)[number]}`) : name);
}

/** "CPU até 2 núcleos · memória até 2 GB · 4 em paralelo". */
export function useProfileSummary() {
  const { t, i18n } = useTranslation();
  const lng = i18n.language;
  return (p: ResourceProfile) => {
    const cores = p.cpu_quota_percent / 100;
    return t("runs.profiles.summary", {
      cpu: t("runs.profiles.cores", { count: cores, formatted: formatNumber(cores, lng) }),
      memory: formatBytes(p.memory_max_bytes, lng),
      workers: formatNumber(p.workers, lng),
    });
  };
}

export function KindLabel({ kind }: { kind: RunKind }) {
  const { t } = useTranslation();
  const Icon = kind === "files" ? FolderSearch : Cpu;
  return (
    <span className="inline-flex items-center gap-1.5 font-semibold">
      <Icon aria-hidden="true" className="size-4 shrink-0 text-ink-muted" />
      {t(`runs.kind.${kind}`)}
    </span>
  );
}

/** Estado da execução e, quando pausada, a indicação de pausa (com ícone e texto). */
export function RunStatus({ run }: { run: Pick<Run, "status" | "paused"> }) {
  const { t } = useTranslation();
  return (
    <span className="inline-flex flex-wrap items-center gap-1.5">
      <StatusBadge kind="run" state={run.status} />
      {run.paused && run.status === "running" && (
        <Badge tone="medium" icon={Pause} variant="outline">
          {t("runs.paused")}
        </Badge>
      )}
    </span>
  );
}

export function OriginText({ run }: { run: Pick<Run, "origin" | "requested_by"> }) {
  const { t } = useTranslation();
  return (
    <span className="flex min-w-0 flex-col">
      <span>{t(`runs.origin.${run.origin}`)}</span>
      {run.requested_by && (
        <span className="text-sm text-ink-muted break-words">{t("runs.origin.by", { name: run.requested_by })}</span>
      )}
    </span>
  );
}

export function DurationText({ run, now }: { run: Pick<Run, "started_at" | "finished_at">; now?: Date }) {
  const { t, i18n } = useTranslation();
  const secs = durationSeconds(run, now);
  if (secs === null) return <span className="text-ink-muted">{t("runs.none")}</span>;
  return (
    <span className="tabular-nums">
      {formatDuration(secs, i18n.language)}
      {!run.finished_at && <span className="text-ink-muted"> ({t("runs.table.running")})</span>}
    </span>
  );
}

export function PhaseText({ phase }: { phase: string }) {
  const { t } = useTranslation();
  switch (phase) {
    case "selftest":
    case "inventory":
    case "scanning":
    case "large_files":
    case "inspect":
    case "done":
      return <>{t(`runs.phase.${phase}`)}</>;
    case "":
      return <span className="text-ink-muted">{t("runs.none")}</span>;
    default:
      return <span className="font-mono">{phase}</span>;
  }
}

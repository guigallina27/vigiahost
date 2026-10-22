import {
  Ban,
  CircleCheck,
  CircleDashed,
  CircleDotDashed,
  CircleSlash,
  CircleX,
  Clock,
  LoaderCircle,
  RotateCcw,
  Search,
  ServerCrash,
  ShieldAlert,
  ShieldCheck,
  type LucideIcon,
} from "lucide-react";
import { useTranslation } from "react-i18next";
import { Badge, type Tone } from "./Badge";

export type FindingState = "new" | "in_review" | "confirmed" | "resolved" | "false_positive" | "excepted";
export type RunState =
  | "queued"
  | "running"
  | "completed"
  | "partial"
  | "failed"
  | "engine_failed"
  | "cancelled"
  | "recovered";

type Entry = { tone: Tone; icon: LucideIcon; spinning?: boolean };

const finding: Record<FindingState, Entry> = {
  new: { tone: "low", icon: CircleDashed },
  in_review: { tone: "neutral", icon: Search },
  confirmed: { tone: "critical", icon: ShieldAlert },
  resolved: { tone: "ok", icon: CircleCheck },
  false_positive: { tone: "neutral", icon: CircleSlash },
  excepted: { tone: "neutral", icon: ShieldCheck },
};

const run: Record<RunState, Entry> = {
  queued: { tone: "neutral", icon: Clock },
  running: { tone: "low", icon: LoaderCircle, spinning: true },
  completed: { tone: "ok", icon: CircleCheck },
  partial: { tone: "medium", icon: CircleDotDashed },
  failed: { tone: "critical", icon: CircleX },
  engine_failed: { tone: "critical", icon: ServerCrash },
  cancelled: { tone: "neutral", icon: Ban },
  recovered: { tone: "medium", icon: RotateCcw },
};

export const findingStates = Object.keys(finding) as FindingState[];
export const runStates = Object.keys(run) as RunState[];

type Props = { kind: "finding"; state: FindingState } | { kind: "run"; state: RunState };

/**
 * Estado de um achado ou de uma execução. Usa contorno, e não preenchimento,
 * para não ser lido como severidade (escopo, seção 14.2: um termo e uma forma por conceito).
 */
export function StatusBadge(props: Props) {
  const { t } = useTranslation();
  const entry = props.kind === "finding" ? finding[props.state] : run[props.state];
  const label = props.kind === "finding" ? t(`findingState.${props.state}`) : t(`runState.${props.state}`);
  return (
    <Badge tone={entry.tone} icon={entry.icon} variant="outline" spinning={entry.spinning ?? false}>
      {label}
    </Badge>
  );
}

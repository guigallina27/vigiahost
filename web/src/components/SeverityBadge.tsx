import { CircleAlert, CircleDot, Info, OctagonAlert, TriangleAlert, type LucideIcon } from "lucide-react";
import { useTranslation } from "react-i18next";
import { Badge, type Tone } from "./Badge";

export type Severity = "critical" | "high" | "medium" | "low" | "info";

// Cada nível tem forma de ícone própria, além da cor: distinguível sem enxergar cores.
const map: Record<Severity, { tone: Tone; icon: LucideIcon }> = {
  critical: { tone: "critical", icon: OctagonAlert },
  high: { tone: "high", icon: TriangleAlert },
  medium: { tone: "medium", icon: CircleAlert },
  low: { tone: "low", icon: CircleDot },
  info: { tone: "neutral", icon: Info },
};

export const severities: Severity[] = ["critical", "high", "medium", "low", "info"];

/** Severidade de um achado. Não confundir com o estado do achado (StatusBadge). */
export function SeverityBadge({ severity }: { severity: Severity }) {
  const { t } = useTranslation();
  const { tone, icon } = map[severity];
  return (
    <Badge tone={tone} icon={icon}>
      {t(`severity.${severity}`)}
    </Badge>
  );
}

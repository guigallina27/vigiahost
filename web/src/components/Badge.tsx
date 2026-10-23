import type { LucideIcon } from "lucide-react";
import type { ReactNode } from "react";

export type Tone = "critical" | "high" | "medium" | "low" | "ok" | "neutral";

// Classes completas (não montadas por concatenação) para o Tailwind encontrá-las no código.
const filled: Record<Tone, string> = {
  critical: "bg-(--vh-critical-bg) text-(--vh-critical-fg)",
  high: "bg-(--vh-high-bg) text-(--vh-high-fg)",
  medium: "bg-(--vh-medium-bg) text-(--vh-medium-fg)",
  low: "bg-(--vh-low-bg) text-(--vh-low-fg)",
  ok: "bg-(--vh-ok-bg) text-(--vh-ok-fg)",
  neutral: "bg-(--vh-neutral-bg) text-(--vh-neutral-fg)",
};

const outlined: Record<Tone, string> = {
  critical: "text-(--vh-critical-fg)",
  high: "text-(--vh-high-fg)",
  medium: "text-(--vh-medium-fg)",
  low: "text-(--vh-low-fg)",
  ok: "text-(--vh-ok-fg)",
  neutral: "text-(--vh-neutral-fg)",
};

type BadgeProps = {
  tone: Tone;
  icon: LucideIcon;
  /** filled: severidade (o que é); outline: estado (em que pé está). Formas diferentes para não confundir os dois. */
  variant?: "filled" | "outline";
  spinning?: boolean;
  children: ReactNode;
};

/** Indicador de estado: sempre ícone + texto, nunca só cor (WCAG 1.4.1). */
export function Badge({ tone, icon: Icon, variant = "filled", spinning = false, children }: BadgeProps) {
  const look =
    variant === "filled"
      ? `${filled[tone]} border-[color-mix(in_oklab,currentColor_28%,transparent)]`
      : `${outlined[tone]} border-current bg-transparent`;
  return (
    <span
      className={`vh-tone inline-flex max-w-full items-center gap-1.5 rounded-control border px-2 py-0.5 text-sm leading-5 font-semibold whitespace-nowrap ${look}`}
    >
      <Icon
        aria-hidden="true"
        className={`size-3.5 shrink-0 ${spinning ? "motion-safe:animate-spin" : ""}`}
        strokeWidth={2.25}
      />
      <span className="truncate">{children}</span>
    </span>
  );
}

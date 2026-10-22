import type { LucideIcon } from "lucide-react";
import type { ReactNode } from "react";

type Props = {
  icon: LucideIcon;
  title: string;
  description: ReactNode;
  /** Próxima ação: botão ou link com verbo + objeto. */
  action?: ReactNode;
  /** Nível do título dentro da página (padrão h2). */
  headingLevel?: 2 | 3;
  tone?: "neutral" | "error";
};

/** Estado vazio ou de erro: diz o que aconteceu e qual é o próximo passo (seção 14.2). */
export function EmptyState({ icon: Icon, title, description, action, headingLevel = 2, tone = "neutral" }: Props) {
  const Heading = headingLevel === 2 ? "h2" : "h3";
  return (
    <div className="flex flex-col items-start gap-3 rounded-panel border border-dashed border-line-strong bg-surface p-6">
      <span
        className={`grid size-10 place-items-center rounded-full ${
          tone === "error" ? "bg-(--vh-critical-bg) text-(--vh-critical-fg)" : "bg-accent-soft text-accent"
        }`}
      >
        <Icon aria-hidden="true" className="size-5" />
      </span>
      <Heading className="m-0 text-lg font-bold">{title}</Heading>
      <div className="max-w-prose text-ink-muted">{description}</div>
      {action}
    </div>
  );
}

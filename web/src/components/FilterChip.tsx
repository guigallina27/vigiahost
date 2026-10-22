import { X } from "lucide-react";
import type { ReactNode } from "react";
import { useTranslation } from "react-i18next";

type Props = {
  /** Nome do filtro ("Conta"). */
  label: string;
  /** Valor aplicado ("loja (1001)"). */
  value: ReactNode;
  onRemove: () => void;
  /** Rótulo do botão de remover; padrão: "Remover filtro: <label>". */
  removeLabel?: string;
};

/**
 * Filtro aplicado que veio de fora do formulário (link de outra tela, como ?account=): mostra o que está valendo e
 * remove com um clique. O botão tem 44 px e nome próprio para leitor de tela.
 */
export function FilterChip({ label, value, onRemove, removeLabel }: Props) {
  const { t } = useTranslation();
  return (
    <span className="inline-flex max-w-full min-w-0 items-center gap-1 rounded-control border border-accent bg-accent-soft ps-3 text-ink">
      <span className="min-w-0 py-1 [overflow-wrap:anywhere]">
        {label}: <strong className="font-semibold">{value}</strong>
      </span>
      <button
        type="button"
        onClick={onRemove}
        aria-label={removeLabel ?? t("filterChip.remove", { label })}
        className="inline-grid size-11 shrink-0 cursor-pointer place-items-center rounded-control text-ink hover:bg-surface"
      >
        <X aria-hidden="true" className="size-4" />
      </button>
    </span>
  );
}

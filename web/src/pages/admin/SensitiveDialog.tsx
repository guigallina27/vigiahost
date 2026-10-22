import { useState, type ReactNode } from "react";
import { useReauth } from "../../auth/session";
import { ConfirmDialog } from "../../components/ConfirmDialog";

/** Descrição de uma ação sensível à espera de confirmação: objeto, impacto, reversibilidade e o que executar. */
export type PendingAction = {
  title: string;
  object: ReactNode;
  impact: string;
  reversible: boolean;
  confirmLabel: string;
  destructive?: boolean;
  run: () => Promise<unknown>;
};

/**
 * Estado de um diálogo de confirmação com reautenticação. O objeto da ação fica guardado depois de fechar
 * para o <dialog> poder fechar normalmente (e devolver o foco) sem trocar de conteúdo no meio.
 */
export function useSensitiveAction() {
  const [pending, setPending] = useState<PendingAction | null>(null);
  const [open, setOpen] = useState(false);
  return {
    ask(action: PendingAction) {
      setPending(action);
      setOpen(true);
    },
    dialog: <SensitiveDialog pending={pending} open={open} onClose={() => setOpen(false)} />,
  };
}

/** ConfirmDialog sempre com senha (e código, se houver segundo fator): todas as ações desta área são sensíveis. */
function SensitiveDialog({ pending, open, onClose }: { pending: PendingAction | null; open: boolean; onClose: () => void }) {
  const reauth = useReauth();
  if (!pending) return null;
  return (
    <ConfirmDialog
      open={open}
      onClose={onClose}
      onConfirm={(input) => reauth.confirm(input, pending.run)}
      title={pending.title}
      object={pending.object}
      impact={pending.impact}
      reversible={pending.reversible}
      confirmLabel={pending.confirmLabel}
      destructive={pending.destructive ?? true}
      requireReauth
      requireCode={reauth.requireCode}
    />
  );
}

import { TriangleAlert } from "lucide-react";
import { useEffect, useId, useRef, useState, type FormEvent, type ReactNode } from "react";
import { useTranslation } from "react-i18next";
import { Button } from "./Button";

type Props = {
  open: boolean;
  onClose: () => void;
  /** Recebe senha (e código) quando requireReauth; lança erro para manter o diálogo aberto com a mensagem. */
  onConfirm: (input: { password?: string; code?: string }) => Promise<void> | void;
  title: string;
  /** O objeto exato da ação (ex.: o caminho do arquivo). */
  object: ReactNode;
  impact: string;
  reversible: boolean;
  /** Verbo + objeto: "Mover para quarentena", nunca "OK". */
  confirmLabel: string;
  destructive?: boolean;
  requireReauth?: boolean;
  /** Com segundo fator ativo, a reautenticação pede também o código. */
  requireCode?: boolean;
  /** Ações em lote: a pessoa digita a quantidade para confirmar. */
  requireCount?: number;
};

/**
 * Confirmação de ação sensível (escopo, seção 14.2) sobre o <dialog> nativo aberto com showModal():
 * o navegador cuida do foco preso, do Esc e de deixar o resto da página inerte.
 */
export function ConfirmDialog(props: Props) {
  const { open, onClose, onConfirm, title, object, impact, reversible, confirmLabel } = props;
  const { destructive = true, requireReauth = false, requireCode = false, requireCount } = props;
  const { t } = useTranslation();
  const ref = useRef<HTMLDialogElement>(null);
  const titleId = useId();
  const impactId = useId();
  const countId = useId();
  const countHintId = useId();
  const passwordId = useId();
  const codeId = useId();
  const errorId = useId();
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    const dialog = ref.current;
    if (!dialog) return;
    if (open && !dialog.open) {
      setError(null);
      dialog.showModal();
    } else if (!open && dialog.open) {
      dialog.close();
    }
  }, [open]);

  async function submit(e: FormEvent<HTMLFormElement>) {
    e.preventDefault();
    const data = new FormData(e.currentTarget);
    if (requireCount !== undefined && String(data.get("count") ?? "").trim() !== String(requireCount)) {
      setError(t("dialog.countMismatch", { count: requireCount }));
      return;
    }
    setBusy(true);
    setError(null);
    try {
      const input: { password?: string; code?: string } = {};
      if (requireReauth) input.password = String(data.get("password") ?? "");
      if (requireReauth && requireCode) input.code = String(data.get("code") ?? "").trim();
      await onConfirm(input);
      onClose();
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setBusy(false);
    }
  }

  return (
    <dialog
      ref={ref}
      aria-labelledby={titleId}
      aria-describedby={impactId}
      onClose={onClose}
      className="vh-dialog m-auto w-[min(34rem,calc(100vw-2rem))] max-h-[calc(100dvh-2rem)] rounded-panel border border-line-strong bg-surface p-0 text-ink shadow-2xl"
    >
      {open && (
        <form onSubmit={submit} className="flex flex-col gap-4 p-5">
          <div className="flex items-start gap-3">
            {destructive && (
              <TriangleAlert aria-hidden="true" className="mt-0.5 size-6 shrink-0 text-(--vh-critical-fg)" />
            )}
            <h2 id={titleId} className="m-0 text-xl leading-tight font-bold">
              {title}
            </h2>
          </div>

          <dl className="m-0 grid gap-3 text-sm">
            <div className="grid gap-1">
              <dt className="vh-label text-ink-muted">{t("dialog.object")}</dt>
              <dd className="m-0 min-w-0 rounded-control bg-sunken p-2 text-base">{object}</dd>
            </div>
            <div className="grid gap-1">
              <dt className="vh-label text-ink-muted">{t("dialog.impact")}</dt>
              <dd id={impactId} className="m-0 text-base">
                {impact}
              </dd>
            </div>
            <div className="grid gap-1">
              <dt className="vh-label text-ink-muted">{t("dialog.reversible")}</dt>
              <dd className="m-0 text-base font-semibold">
                {reversible ? t("dialog.reversibleYes") : t("dialog.reversibleNo")}
              </dd>
            </div>
          </dl>

          {requireCount !== undefined && (
            <div className="grid gap-1">
              <label htmlFor={countId} className="font-semibold">
                {t("dialog.countPrompt", { count: requireCount })}
              </label>
              <span id={countHintId} className="visually-hidden">
                {t("dialog.countMismatch", { count: requireCount })}
              </span>
              <input
                id={countId}
                name="count"
                inputMode="numeric"
                autoComplete="off"
                required
                aria-describedby={countHintId}
                className="min-h-11 rounded-control border border-line-strong bg-bg px-3 font-mono"
              />
            </div>
          )}

          {requireReauth && (
            <div className="grid gap-1">
              <label htmlFor={passwordId} className="font-semibold">
                {t("dialog.reauth")}
              </label>
              <span className="text-sm text-ink-muted">{t("dialog.reauthHint")}</span>
              <input
                id={passwordId}
                name="password"
                type="password"
                autoComplete="current-password"
                required
                className="min-h-11 rounded-control border border-line-strong bg-bg px-3"
              />
              {requireCode && (
                <>
                  <label htmlFor={codeId} className="mt-2 font-semibold">
                    {t("dialog.reauthCode")}
                  </label>
                  <input
                    id={codeId}
                    name="code"
                    autoComplete="one-time-code"
                    inputMode="numeric"
                    required
                    maxLength={32}
                    className="min-h-11 rounded-control border border-line-strong bg-bg px-3 font-mono"
                  />
                </>
              )}
            </div>
          )}

          {error && (
            <p id={errorId} role="alert" className="m-0 rounded-control bg-(--vh-critical-bg) p-2 text-sm text-(--vh-critical-fg)">
              {error}
            </p>
          )}

          <div className="flex flex-wrap justify-end gap-2">
            {/* O foco inicial fica em Cancelar: a opção segura é a mais fácil de acionar sem querer. */}
            {/* eslint-disable-next-line jsx-a11y/no-autofocus -- foco inicial recomendado para <dialog> modal */}
            <Button type="button" variant="secondary" onClick={onClose} autoFocus={!requireReauth && requireCount === undefined}>
              {t("dialog.cancel")}
            </Button>
            <Button type="submit" variant={destructive ? "danger" : "primary"} disabled={busy} aria-describedby={error ? errorId : undefined}>
              {confirmLabel}
            </Button>
          </div>
        </form>
      )}
    </dialog>
  );
}

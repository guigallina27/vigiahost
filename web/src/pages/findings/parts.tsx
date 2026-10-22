import { CircleAlert } from "lucide-react";
import { useId, type ReactNode, type Ref, type TextareaHTMLAttributes } from "react";
import { useTranslation } from "react-i18next";
import type { Schemas } from "../../api/client";
import { PathText } from "../../components/PathText";

type Finding = Schemas["Finding"];

/** Objeto do achado em uma linha: caminho do arquivo, processo (PID e executável) ou item de persistência. */
export function FindingObject({ finding }: { finding: Finding }) {
  const { t } = useTranslation();
  if (finding.kind === "process" && finding.process) {
    const p = finding.process;
    return (
      <span className="flex min-w-0 flex-col gap-0.5">
        <span className="font-semibold tabular-nums">
          {t("findings.object.pid", { pid: p.pid })}
          {p.comm && <span className="font-normal text-ink-muted"> · {p.comm}</span>}
        </span>
        {p.exe && <PathText path={p.exe} />}
      </span>
    );
  }
  if (finding.kind === "persistence" && finding.persistence) {
    const p = finding.persistence;
    return (
      <span className="flex min-w-0 flex-col gap-0.5">
        <span className="text-sm text-ink-muted">{p.kind}</span>
        <PathText path={p.path} />
      </span>
    );
  }
  if (finding.location) return <PathText path={finding.location.path} />;
  return <span className="text-ink-muted">{t("findings.object.none")}</span>;
}

/** Par rótulo/valor de uma lista de definições; o valor quebra em qualquer ponto para não estourar. */
export function DetailItem({ label, children }: { label: string; children: ReactNode }) {
  return (
    <div className="grid min-w-0 gap-0.5">
      <dt className="text-sm text-ink-muted">{label}</dt>
      <dd className="m-0 min-w-0 [overflow-wrap:anywhere]">{children}</dd>
    </div>
  );
}

type NoteProps = Omit<TextareaHTMLAttributes<HTMLTextAreaElement>, "id"> & {
  label: string;
  hint?: ReactNode;
  error?: string | null | undefined;
};

/** Texto longo com rótulo, dica e erro ligados por aria-describedby (o TextAreaField comum não tem erro). */
export function NoteField({ label, hint, error, className = "", ...area }: NoteProps) {
  const id = useId();
  const hintId = `${id}-dica`;
  const errorId = `${id}-erro`;
  const describedBy = [hint ? hintId : "", error ? errorId : ""].filter(Boolean).join(" ") || undefined;
  return (
    <div className={`grid min-w-0 gap-1 ${className}`}>
      <label htmlFor={id} className="font-semibold">
        {label}
      </label>
      {hint && (
        <span id={hintId} className="text-sm text-ink-muted">
          {hint}
        </span>
      )}
      <textarea
        id={id}
        aria-invalid={error ? true : undefined}
        aria-describedby={describedBy}
        className={`min-h-24 w-full min-w-0 rounded-control border bg-bg px-3 py-2 ${
          error ? "border-(--vh-critical-fg)" : "border-line-strong"
        }`}
        {...area}
      />
      {error && <FieldError id={errorId} message={error} />}
    </div>
  );
}

/** Erro de um campo: ícone + texto, não só cor. */
export function FieldError({ id, message }: { id?: string; message: string }) {
  return (
    <span id={id} className="flex items-start gap-1 text-sm text-(--vh-critical-fg)">
      <CircleAlert aria-hidden="true" className="mt-0.5 size-4 shrink-0" />
      {message}
    </span>
  );
}

/** Mensagem de sucesso anunciada (WCAG 4.1.3). Fica no DOM vazia para a região já existir quando o texto chegar. */
export function StatusMessage({ message, ref }: { message: string | null; ref?: Ref<HTMLParagraphElement> }) {
  return (
    <p
      ref={ref}
      role="status"
      tabIndex={-1}
      className={
        message
          ? "m-0 rounded-control border border-(--vh-ok-fg) bg-(--vh-ok-bg) p-3 text-sm text-(--vh-ok-fg)"
          : "visually-hidden"
      }
    >
      {message ?? ""}
    </p>
  );
}

/** Permissões em octal ("0644"), como no ls. */
export function formatMode(mode: number): string {
  return (mode & 0o7777).toString(8).padStart(4, "0");
}

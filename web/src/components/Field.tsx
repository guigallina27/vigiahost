import { useId, type InputHTMLAttributes, type ReactNode, type SelectHTMLAttributes, type TextareaHTMLAttributes } from "react";

type Props = Omit<InputHTMLAttributes<HTMLInputElement>, "id"> & {
  label: string;
  hint?: ReactNode;
  error?: string | null;
  mono?: boolean;
};

/** Campo com rótulo visível, dica e erro ligados por aria-describedby (WCAG 1.3.1, 3.3.1, 3.3.2). */
export function Field({ label, hint, error, mono = false, className = "", ...input }: Props) {
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
      <input
        id={id}
        aria-invalid={error ? true : undefined}
        aria-describedby={describedBy}
        className={`min-h-11 w-full min-w-0 rounded-control border bg-bg px-3 ${mono ? "font-mono" : ""} ${
          error ? "border-(--vh-critical-fg)" : "border-line-strong"
        }`}
        {...input}
      />
      {error && (
        <span id={errorId} className="text-sm text-(--vh-critical-fg)">
          {error}
        </span>
      )}
    </div>
  );
}

/** Mensagem de erro do formulário (anunciada ao aparecer). */
export function FormError({ message }: { message: string | null | undefined }) {
  if (!message) return null;
  return (
    <p role="alert" className="m-0 rounded-control bg-(--vh-critical-bg) p-3 text-sm text-(--vh-critical-fg)">
      {message}
    </p>
  );
}

type SelectProps = Omit<SelectHTMLAttributes<HTMLSelectElement>, "id"> & {
  label: string;
  hint?: ReactNode;
  error?: string | null;
  options: { value: string; label: string }[];
};

/** Seleção com rótulo visível (mesmas regras do Field). */
export function SelectField({ label, hint, error, options, className = "", ...select }: SelectProps) {
  const id = useId();
  const describedBy = [hint ? `${id}-dica` : "", error ? `${id}-erro` : ""].filter(Boolean).join(" ") || undefined;
  return (
    <div className={`grid min-w-0 gap-1 ${className}`}>
      <label htmlFor={id} className="font-semibold">
        {label}
      </label>
      {hint && (
        <span id={`${id}-dica`} className="text-sm text-ink-muted">
          {hint}
        </span>
      )}
      <select
        id={id}
        aria-invalid={error ? true : undefined}
        aria-describedby={describedBy}
        className="min-h-11 w-full min-w-0 rounded-control border border-line-strong bg-bg px-3"
        {...select}
      >
        {options.map((o) => (
          <option key={o.value} value={o.value}>
            {o.label}
          </option>
        ))}
      </select>
      {error && (
        <span id={`${id}-erro`} className="text-sm text-(--vh-critical-fg)">
          {error}
        </span>
      )}
    </div>
  );
}

type AreaProps = Omit<TextareaHTMLAttributes<HTMLTextAreaElement>, "id"> & { label: string; hint?: ReactNode; mono?: boolean };

/** Texto longo (lista de caminhos, nota de transição). */
export function TextAreaField({ label, hint, mono = false, className = "", ...area }: AreaProps) {
  const id = useId();
  return (
    <div className={`grid min-w-0 gap-1 ${className}`}>
      <label htmlFor={id} className="font-semibold">
        {label}
      </label>
      {hint && (
        <span id={`${id}-dica`} className="text-sm text-ink-muted">
          {hint}
        </span>
      )}
      <textarea
        id={id}
        aria-describedby={hint ? `${id}-dica` : undefined}
        className={`min-h-24 w-full min-w-0 rounded-control border border-line-strong bg-bg px-3 py-2 ${mono ? "font-mono" : ""}`}
        {...area}
      />
    </div>
  );
}

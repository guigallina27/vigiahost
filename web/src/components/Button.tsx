import type { ButtonHTMLAttributes } from "react";

type Variant = "primary" | "secondary" | "danger" | "ghost";

const variants: Record<Variant, string> = {
  primary: "border-accent bg-accent text-accent-ink hover:not-disabled:brightness-110",
  // Borda com contraste ≥ 3:1 (o preview tinha 1,47:1, seção 14.3).
  secondary: "border-line-strong bg-surface text-ink hover:not-disabled:bg-sunken",
  danger: "border-(--vh-critical-fg) bg-(--vh-critical-fg) text-surface hover:not-disabled:brightness-110",
  ghost: "border-transparent bg-transparent text-ink hover:not-disabled:bg-sunken",
};

type Props = ButtonHTMLAttributes<HTMLButtonElement> & { variant?: Variant };

/** Botão base. Rótulo sempre com verbo + objeto ("Verificar conta"); alvo mínimo de 44 px (seção 14.3). */
export function Button({ variant = "secondary", className = "", type = "button", ...rest }: Props) {
  return (
    <button
      type={type}
      className={`inline-flex min-h-11 cursor-pointer items-center justify-center gap-2 rounded-control border px-4 font-semibold disabled:cursor-not-allowed disabled:opacity-60 ${variants[variant]} ${className}`}
      {...rest}
    />
  );
}

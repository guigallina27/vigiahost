/**
 * Marca do VigiaHost: o "V" da torre de vigia com o farol aceso no alto (âmbar) e os fachos para os lados.
 * Decorativa: o nome do produto vem sempre em texto ao lado.
 */
export function BrandMark({ className = "size-8" }: { className?: string }) {
  return (
    <svg aria-hidden="true" viewBox="0 0 32 32" className={`shrink-0 ${className}`}>
      <rect width="32" height="32" rx="8" fill="oklch(31% 0.1 266)" />
      <path d="M8.5 13.5 16 26.5l7.5-13" fill="none" stroke="oklch(95% 0.012 262)" strokeWidth="3" strokeLinecap="round" strokeLinejoin="round" />
      <path
        d="M10.2 5.6a7 7 0 0 0 0 7.8M21.8 5.6a7 7 0 0 1 0 7.8"
        fill="none"
        stroke="var(--vh-signal)"
        strokeWidth="1.7"
        strokeLinecap="round"
        opacity="0.75"
      />
      <circle cx="16" cy="9.5" r="3" fill="var(--vh-signal)" />
    </svg>
  );
}

/** Marca + nome, para a navegação e as telas de acesso. */
export function Brand({ size = "md" }: { size?: "md" | "lg" }) {
  return (
    <span className="flex items-center gap-2.5">
      <BrandMark className={size === "lg" ? "size-10" : "size-8"} />
      <span className={`${size === "lg" ? "text-2xl" : "text-lg"} font-bold tracking-tight`}>
        Vigia<span className="text-signal">Host</span>
      </span>
    </span>
  );
}

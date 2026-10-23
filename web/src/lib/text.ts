// Tratamento de texto vindo do servidor analisado: nomes de arquivo são controlados pelo atacante
// (escopo, seção 14.2). Caracteres de controle, de direção de texto (bidi) e invisíveis viram escapes visíveis.

export type TextSegment = { kind: "text"; value: string } | { kind: "escape"; value: string; code: number };

const NAMED: Record<number, string> = { 0x09: "\\t", 0x0a: "\\n", 0x0d: "\\r" };

/** Indica se o ponto de código precisa aparecer como escape em vez de ser renderizado. */
export function isHiddenCodePoint(cp: number): boolean {
  return (
    cp <= 0x1f || // controles C0
    (cp >= 0x7f && cp <= 0x9f) || // DEL e controles C1
    cp === 0x061c || // marca de letra árabe (bidi)
    (cp >= 0x200b && cp <= 0x200f) || // larguras zero e marcas LRM/RLM
    (cp >= 0x2028 && cp <= 0x202e) || // separadores de linha/parágrafo e embutimentos bidi
    (cp >= 0x2060 && cp <= 0x2069) || // junção de palavra e isolamentos bidi
    cp === 0xfeff // BOM / espaço sem quebra de largura zero
  );
}

export function escapeCodePoint(cp: number): string {
  const named = NAMED[cp];
  if (named) return named;
  const hex = cp.toString(16).toUpperCase();
  return cp <= 0xff ? `\\x${hex.padStart(2, "0")}` : `\\u${hex.padStart(4, "0")}`;
}

/** Divide o texto em trechos normais e escapes, preservando a ordem original. */
export function segmentHidden(input: string): TextSegment[] {
  const out: TextSegment[] = [];
  let buf = "";
  for (const ch of input) {
    const cp = ch.codePointAt(0) ?? 0;
    if (isHiddenCodePoint(cp)) {
      if (buf) out.push({ kind: "text", value: buf });
      buf = "";
      out.push({ kind: "escape", value: escapeCodePoint(cp), code: cp });
    } else {
      buf += ch;
    }
  }
  if (buf) out.push({ kind: "text", value: buf });
  return out;
}

/** Versão em texto puro, para copiar ou usar em atributos. */
export function escapeHidden(input: string): string {
  return segmentHidden(input)
    .map((s) => s.value)
    .join("");
}

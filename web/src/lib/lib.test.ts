import { describe, expect, it } from "vitest";
import en from "../i18n/en.json";
import ptBR from "../i18n/pt-BR.json";
import { formatPercent, formatRelative } from "./format";
import { escapeHidden, segmentHidden } from "./text";

describe("texto vindo do servidor", () => {
  it("transforma controles e marcas bidi em escapes visíveis", () => {
    expect(escapeHidden("foto\u202Egpj.php")).toBe("foto\\u202Egpj.php");
    expect(escapeHidden("x\n/var/www/limpo.php: OK")).toBe("x\\n/var/www/limpo.php: OK");
    expect(escapeHidden("a\u0000b\u001bc\u200Bd\uFEFF")).toBe("a\\x00b\\x1Bc\\u200Bd\\uFEFF");
  });

  it("mantém acentos, emoji e caracteres comuns", () => {
    const s = "/home/joão/ação 🚀/índice.php";
    expect(segmentHidden(s)).toEqual([{ kind: "text", value: s }]);
  });
});

describe("formatação", () => {
  it("não arredonda cobertura incompleta para 100% nem parcial para 0%", () => {
    expect(formatPercent(124869, 124870, "pt-BR")).toBe("99,9%");
    expect(formatPercent(124870, 124870, "pt-BR")).toBe("100,0%");
    expect(formatPercent(1, 100000, "pt-BR")).toBe("0,1%");
    expect(formatPercent(0, 10, "pt-BR")).toBe("0,0%");
    expect(formatPercent(0, 0, "pt-BR")).toBe("0,0%");
  });

  it("formata tempo relativo no idioma ativo", () => {
    const now = new Date("2026-10-22T15:30:00Z");
    expect(formatRelative(new Date("2026-10-22T09:30:00Z"), "pt-BR", now)).toBe("há 6 horas");
    expect(formatRelative(new Date("2026-10-22T15:29:50Z"), "pt-BR", now)).toBe("agora");
    expect(formatRelative(new Date("2026-10-21T15:30:00Z"), "pt-BR", now)).toBe("ontem");
  });
});

describe("traduções", () => {
  function keys(obj: object, prefix = ""): string[] {
    return Object.entries(obj).flatMap(([k, v]) =>
      typeof v === "object" && v !== null ? keys(v, `${prefix}${k}.`) : [`${prefix}${k}`],
    );
  }
  it("inglês tem exatamente as mesmas chaves do pt-BR", () => {
    expect(keys(en).sort()).toEqual(keys(ptBR).sort());
  });
});

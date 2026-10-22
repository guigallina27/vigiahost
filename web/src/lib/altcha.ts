// Carrega o widget ALTCHA na versão sem estilos e workers embutidos (CSP do core sem 'unsafe-inline' e sem blob:).
// O worker do PBKDF2 vira arquivo próprio no build; o CSS vem como folha de estilo comum.
import "altcha/external";
import "altcha/altcha.css";
import "altcha/i18n/pt-br";
import Pbkdf2Worker from "altcha/workers/pbkdf2?worker";

globalThis.$altcha.algorithms.set("PBKDF2/SHA-256", () => new Pbkdf2Worker());

// setLabels troca os textos padrão pelos do painel (caixa "Não sou um robô").
export function setLabels(lang: "pt-br" | "en", labels: Record<string, string>) {
  const current = globalThis.$altcha.i18n.get(lang) ?? {};
  globalThis.$altcha.i18n.set(lang, { ...current, ...labels });
}

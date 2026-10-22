import i18n from "i18next";
import { initReactI18next } from "react-i18next";
import en from "./en.json";
import enAdmin from "./en/admin.json";
import enConfig from "./en/config.json";
import enFindings from "./en/findings.json";
import enInventory from "./en/inventory.json";
import enRuns from "./en/runs.json";
import ptBR from "./pt-BR.json";
import ptAdmin from "./pt-BR/admin.json";
import ptConfig from "./pt-BR/config.json";
import ptFindings from "./pt-BR/findings.json";
import ptInventory from "./pt-BR/inventory.json";
import ptRuns from "./pt-BR/runs.json";

// pt-BR é o padrão; o inglês fica preparado (escopo, seção 14). Os textos vão no bundle: sem requisição extra.
export const defaultNS = "translation";
// Textos gerais em pt-BR.json/en.json; cada área de páginas tem seu arquivo (chave de topo = nome da área).
export const resources = {
  "pt-BR": { translation: { ...ptBR, ...ptRuns, ...ptFindings, ...ptInventory, ...ptConfig, ...ptAdmin } },
  en: { translation: { ...en, ...enRuns, ...enFindings, ...enInventory, ...enConfig, ...enAdmin } },
} as const;

declare module "i18next" {
  interface CustomTypeOptions {
    defaultNS: typeof defaultNS;
    resources: (typeof resources)["pt-BR"];
  }
}

void i18n.use(initReactI18next).init({
  resources,
  lng: "pt-BR",
  fallbackLng: "pt-BR",
  interpolation: { escapeValue: false }, // o React já escapa o conteúdo
  returnNull: false,
});

export default i18n;

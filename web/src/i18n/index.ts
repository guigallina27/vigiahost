import i18n from "i18next";
import { initReactI18next } from "react-i18next";
import en from "./en.json";
import ptBR from "./pt-BR.json";

// pt-BR é o padrão; o inglês fica preparado (escopo, seção 14). Os textos vão no bundle: sem requisição extra.
export const defaultNS = "translation";
export const resources = {
  "pt-BR": { translation: ptBR },
  en: { translation: en },
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

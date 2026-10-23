import type { AltchaWidgetElement } from "altcha/types/generic";
import type {} from "altcha/types/react";
import { useEffect, useImperativeHandle, useRef, useState, type Ref } from "react";
import { useTranslation } from "react-i18next";

export interface CaptchaHandle {
  /** Volta a caixa ao estado inicial (a solução vale uma vez só: chamar depois de cada envio). */
  reset(): void;
}

interface Props {
  /** Recebe o payload quando a verificação conclui, ou null quando ela é desfeita ou falha. */
  onChange(payload: string | null): void;
  ref?: Ref<CaptchaHandle>;
}

type StateDetail = { payload?: string; state: string };

/**
 * Caixa "Não sou um robô" (ALTCHA): ao marcar, o navegador resolve uma prova de trabalho em segundo plano, sem
 * desafio para o usuário. O widget é carregado sob demanda para não pesar nas demais telas.
 */
export function CaptchaField({ onChange, ref }: Props) {
  const { t, i18n } = useTranslation();
  const el = useRef<AltchaWidgetElement>(null);
  const [ready, setReady] = useState(false);
  const [failed, setFailed] = useState(false);
  const lang = i18n.language.toLowerCase().startsWith("pt") ? "pt-br" : "en";

  useImperativeHandle(ref, () => ({ reset: () => el.current?.reset() }), []);

  useEffect(() => {
    let alive = true;
    import("../lib/altcha")
      .then((m) => {
        m.setLabels(lang, {
          label: t("captcha.label"),
          verifying: t("captcha.verifying"),
          verified: t("captcha.verified"),
          error: t("captcha.error"),
          expired: t("captcha.expired"),
          verificationRequired: t("captcha.required"),
        });
        if (alive) setReady(true);
      })
      .catch(() => alive && setFailed(true));
    return () => {
      alive = false;
    };
  }, [lang, t]);

  useEffect(() => {
    const w = el.current;
    if (!w) return;
    const handler = (e: Event) => {
      const d = (e as CustomEvent<StateDetail>).detail;
      onChange(d.state === "verified" && d.payload ? d.payload : null);
    };
    w.addEventListener("statechange", handler);
    return () => w.removeEventListener("statechange", handler);
  }, [onChange, ready]);

  if (failed) {
    return (
      <p role="alert" className="text-sm text-(--vh-critical-fg)">
        {t("captcha.loadError")}
      </p>
    );
  }
  if (!ready) {
    return <p className="h-[68px] text-sm text-ink-muted">{t("captcha.loading")}</p>;
  }
  return (
    <altcha-widget
      ref={el}
      challenge="/api/v1/auth/challenge"
      auto="off"
      type="checkbox"
      display="standard"
      name="altcha"
      language={lang}
      configuration={JSON.stringify({ hideFooter: true, hideLogo: true, minDuration: 300 })}
    />
  );
}

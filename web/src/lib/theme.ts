import { useCallback, useSyncExternalStore } from "react";

// Preferência de tema por navegador (guia dark-mode-toggle): sem valor salvo, segue o sistema.
// O valor fica no <meta name="color-scheme">, que o CSS reflete em color-scheme via :has().

export type SchemePreference = "system" | "light" | "dark";
const STORAGE_KEY = "vigiahost.color-scheme";
const listeners = new Set<() => void>();

function readStored(): SchemePreference {
  try {
    const v = localStorage.getItem(STORAGE_KEY);
    return v === "light" || v === "dark" ? v : "system";
  } catch {
    return "system";
  }
}

function applyMeta(pref: SchemePreference) {
  const meta = document.querySelector<HTMLMetaElement>('meta[name="color-scheme"]');
  if (meta) meta.content = pref === "system" ? "light dark" : pref;
}

let current: SchemePreference = typeof window === "undefined" ? "system" : readStored();

export function setSchemePreference(pref: SchemePreference) {
  current = pref;
  try {
    if (pref === "system") localStorage.removeItem(STORAGE_KEY);
    else localStorage.setItem(STORAGE_KEY, pref);
  } catch {
    // Armazenamento bloqueado: o tema vale só para esta aba.
  }
  applyMeta(pref);
  listeners.forEach((l) => l());
}

function subscribe(listener: () => void) {
  listeners.add(listener);
  // A escolha pode mudar em outra aba.
  const onStorage = (e: StorageEvent) => {
    if (e.key !== STORAGE_KEY) return;
    current = readStored();
    applyMeta(current);
    listener();
  };
  window.addEventListener("storage", onStorage);
  return () => {
    listeners.delete(listener);
    window.removeEventListener("storage", onStorage);
  };
}

export function useSchemePreference(): [SchemePreference, (p: SchemePreference) => void] {
  const pref = useSyncExternalStore(subscribe, () => current, () => "system" as const);
  return [pref, useCallback((p: SchemePreference) => setSchemePreference(p), [])];
}

const darkQuery = "(prefers-color-scheme: dark)";

function subscribeSystem(listener: () => void) {
  const mql = window.matchMedia(darkQuery);
  mql.addEventListener("change", listener);
  return () => mql.removeEventListener("change", listener);
}

/** Tema atual do sistema operacional, atualizado quando ele muda. */
export function useSystemScheme(): "light" | "dark" {
  return useSyncExternalStore(
    subscribeSystem,
    () => (window.matchMedia(darkQuery).matches ? "dark" : "light"),
    () => "light" as const,
  );
}

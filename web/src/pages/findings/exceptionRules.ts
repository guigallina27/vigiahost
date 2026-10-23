import type { Schemas } from "../../api/client";

// Regras do formulário de exceção, espelhando a validação de CreateException (internal/core/handlers_config.go)
// para o operador ver o problema antes de digitar a senha. Quem decide continua sendo o servidor.

export type ExceptionScope = Schemas["ExceptionScope"];
export type ExceptionCreate = Schemas["ExceptionCreate"];
type Finding = Schemas["Finding"];

export const scopeList: ExceptionScope[] = ["hash", "hash_rule", "rule_prefix", "rule_global"];

/** Prazos oferecidos, em dias; "none" = sem validade. */
export const validityList = ["30", "90", "180", "365", "none"] as const;
export type Validity = (typeof validityList)[number];
export const DEFAULT_VALIDITY: Validity = "90";

export type ScopeNeeds = {
  sha256: boolean;
  signature: boolean;
  pathPrefix: boolean;
  /** O servidor recusa sem validade. */
  expiresRequired: boolean;
  /** Só o administrador cria. */
  adminOnly: boolean;
};

export function scopeNeeds(scope: ExceptionScope): ScopeNeeds {
  switch (scope) {
    case "hash":
      return { sha256: true, signature: false, pathPrefix: false, expiresRequired: false, adminOnly: false };
    case "hash_rule":
      return { sha256: true, signature: true, pathPrefix: false, expiresRequired: false, adminOnly: false };
    case "rule_prefix":
      return { sha256: false, signature: true, pathPrefix: true, expiresRequired: true, adminOnly: false };
    case "rule_global":
      return { sha256: false, signature: true, pathPrefix: false, expiresRequired: false, adminOnly: true };
  }
}

export type ExceptionDraft = {
  scope: ExceptionScope;
  sha256: string;
  signature: string;
  pathPrefix: string;
  reason: string;
  validity: Validity;
  /** Achado de origem: o servidor completa hash e assinatura a partir dele. */
  findingId?: number;
};

/** Códigos de erro por campo; o componente traduz em findings.exceptions.errors.<código>. */
export type DraftErrorCode =
  | "scopeAdminOnly"
  | "sha256Invalid"
  | "signatureRequired"
  | "signatureTooLong"
  | "pathPrefixInvalid"
  | "pathPrefixTooLong"
  | "reasonTooShort"
  | "reasonTooLong"
  | "validityRequired";

export type DraftErrors = Partial<Record<"scope" | "sha256" | "signature" | "pathPrefix" | "reason" | "validity", DraftErrorCode>>;

const SHA256 = /^[0-9a-f]{64}$/;

export function normalizeSha256(value: string): string {
  return value.trim().toLowerCase();
}

/** Diretório sem barra final; "/" continua "/". */
export function normalizePrefix(value: string): string {
  const v = value.trim();
  if (v.length > 1) return v.replace(/\/+$/, "") || "/";
  return v;
}

export function emptyDraft(): ExceptionDraft {
  return { scope: "hash_rule", sha256: "", signature: "", pathPrefix: "", reason: "", validity: DEFAULT_VALIDITY };
}

/** Diretório que contém o caminho ("/a/b/c.php" → "/a/b"). */
export function parentDir(path: string): string {
  const i = path.lastIndexOf("/");
  if (i <= 0) return "/";
  return path.slice(0, i);
}

/** Formulário já preenchido a partir do achado (hash, regra e diretório do objeto). */
export function draftFromFinding(f: Finding): ExceptionDraft {
  const objectPath = f.location?.path ?? f.process?.exe ?? f.persistence?.path ?? "";
  const sha256 = f.sha256 ?? "";
  return {
    scope: sha256 ? "hash_rule" : "rule_prefix",
    sha256,
    signature: f.signature,
    pathPrefix: objectPath.startsWith("/") ? parentDir(objectPath) : "",
    reason: "",
    validity: DEFAULT_VALIDITY,
    findingId: f.id,
  };
}

export function validateDraft(d: ExceptionDraft, opts: { isAdmin: boolean }): DraftErrors {
  const need = scopeNeeds(d.scope);
  const errors: DraftErrors = {};
  if (need.adminOnly && !opts.isAdmin) errors.scope = "scopeAdminOnly";
  if (need.sha256 && !SHA256.test(normalizeSha256(d.sha256))) errors.sha256 = "sha256Invalid";
  if (need.signature) {
    const sig = d.signature.trim();
    if (!sig) errors.signature = "signatureRequired";
    else if (sig.length > 256) errors.signature = "signatureTooLong";
  }
  if (need.pathPrefix) {
    const p = normalizePrefix(d.pathPrefix);
    if (!p.startsWith("/") || p === "/") errors.pathPrefix = "pathPrefixInvalid";
    else if (p.length > 4096) errors.pathPrefix = "pathPrefixTooLong";
  }
  const reason = d.reason.trim();
  if (reason.length < 3) errors.reason = "reasonTooShort";
  else if (reason.length > 2000) errors.reason = "reasonTooLong";
  if (need.expiresRequired && d.validity === "none") errors.validity = "validityRequired";
  return errors;
}

/** Data de vencimento para o prazo escolhido (undefined = sem validade). */
export function expiryFor(validity: Validity, now: Date): Date | undefined {
  if (validity === "none") return undefined;
  return new Date(now.getTime() + Number(validity) * 24 * 60 * 60 * 1000);
}

/** Corpo de POST /api/v1/exceptions com só os campos que o escopo usa. */
export function buildExceptionBody(d: ExceptionDraft, now: Date): ExceptionCreate {
  const need = scopeNeeds(d.scope);
  const body: ExceptionCreate = { scope: d.scope, reason: d.reason.trim() };
  if (d.findingId !== undefined) body.finding_id = d.findingId;
  if (need.sha256) body.sha256 = normalizeSha256(d.sha256);
  if (need.signature) body.signature = d.signature.trim();
  if (need.pathPrefix) body.path_prefix = normalizePrefix(d.pathPrefix);
  const expires = expiryFor(d.validity, now);
  if (expires) body.expires_at = expires.toISOString();
  return body;
}

export type ExceptionStatus = "active" | "revoked" | "expired";

/** Situação da exceção: revogada tem precedência; inativa sem revogação é vencida (o servidor calcula `active`). */
export function exceptionStatus(e: Schemas["Exception"]): ExceptionStatus {
  if (e.revoked_at) return "revoked";
  return e.active ? "active" : "expired";
}

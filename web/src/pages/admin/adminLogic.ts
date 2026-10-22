import type { Schemas } from "../../api/client";

// Regras da área de administração que não dependem de tela: espelham o servidor (internal/auth e
// internal/core/handlers_admin.go) só para orientar a pessoa antes do envio; quem decide é o servidor.

export type Role = Schemas["Role"];
export type User = Schemas["User"];
export type UserUpdate = Schemas["UserUpdate"];
export type ApiToken = Schemas["ApiToken"];
export type AuditEntry = Schemas["AuditEntry"];

export const roles: readonly Role[] = ["admin", "operator", "auditor", "reader"];

/** Mesmos limites de internal/auth/password.go (MinPasswordLen em caracteres, MaxPasswordLen em bytes). */
export const MIN_PASSWORD_CHARS = 12;
export const MAX_PASSWORD_BYTES = 256;

export type PasswordProblem = "short" | "long";

export function checkPassword(pw: string): PasswordProblem | null {
  if ([...pw].length < MIN_PASSWORD_CHARS) return "short";
  if (new TextEncoder().encode(pw).length > MAX_PASSWORD_BYTES) return "long";
  return null;
}

/** Mesma regra de auth.CheckUsername: 2 a 64 caracteres, letras sem acento, números e . - _ @. */
export function checkUsername(name: string): boolean {
  return /^[A-Za-z0-9._@-]{2,64}$/.test(name);
}

// Sem caracteres ambíguos (0/O, 1/l/I) para a senha inicial ser ditada ou digitada sem erro.
const PASSWORD_ALPHABET = "abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789";

/** Senha inicial aleatória (crypto.getRandomValues, sem viés de módulo). */
export function generatePassword(length = 20): string {
  const n = PASSWORD_ALPHABET.length;
  const limit = 256 - (256 % n);
  let out = "";
  const buf = new Uint8Array(length * 2);
  while (out.length < length) {
    crypto.getRandomValues(buf);
    for (const b of buf) {
      if (b < limit) out += PASSWORD_ALPHABET[b % n];
      if (out.length === length) break;
    }
  }
  return out;
}

export function countActiveAdmins(users: readonly User[]): number {
  return users.filter((u) => u.role === "admin" && !u.disabled).length;
}

export type UserGuard = {
  isSelf: boolean;
  /** Único administrador habilitado: não pode ser rebaixado, desativado nem removido. */
  lastAdmin: boolean;
  canDelete: boolean;
};

export function userGuard(target: User, users: readonly User[], selfId: number | undefined): UserGuard {
  const isSelf = selfId !== undefined && target.id === selfId;
  const lastAdmin = target.role === "admin" && !target.disabled && countActiveAdmins(users) <= 1;
  return { isSelf, lastAdmin, canDelete: !isSelf && !lastAdmin };
}

export type UserEdit = { display_name: string; role: Role; disabled: boolean };

/** Monta o PATCH só com o que mudou; null quando nada mudou. */
export function buildUserUpdate(original: User, edit: UserEdit): UserUpdate | null {
  const body: UserUpdate = {};
  const name = edit.display_name.trim();
  if (name !== original.display_name) body.display_name = name;
  if (edit.role !== original.role) body.role = edit.role;
  if (edit.disabled !== original.disabled) body.disabled = edit.disabled;
  return Object.keys(body).length > 0 ? body : null;
}

/** O servidor encerra as sessões da pessoa quando o perfil muda ou quando ela é desativada. */
export function updateEndsSessions(original: User, body: UserUpdate): boolean {
  return (body.role !== undefined && body.role !== original.role) || body.disabled === true;
}

/** A edição deixaria o painel sem administrador habilitado (o servidor responde 409 last_admin). */
export function updateRemovesLastAdmin(original: User, body: UserUpdate, users: readonly User[]): boolean {
  if (original.role !== "admin" || original.disabled) return false;
  const nextRole = body.role ?? original.role;
  const nextDisabled = body.disabled ?? original.disabled;
  if (nextRole === "admin" && !nextDisabled) return false;
  return countActiveAdmins(users) <= 1;
}

/** Perfis que a pessoa pode dar a um token: o próprio ou leitura; o administrador emite qualquer um. */
export function issuableRoles(role: Role | undefined): Role[] {
  if (!role) return [];
  if (role === "admin") return [...roles];
  return role === "reader" ? ["reader"] : [role, "reader"];
}

export type TokenStatus = "active" | "expired" | "revoked";

export function tokenStatus(token: ApiToken, now: number): TokenStatus {
  if (token.revoked_at) return "revoked";
  return Date.parse(token.expires_at) <= now ? "expired" : "active";
}

export const MIN_TOKEN_DAYS = 1;
export const MAX_TOKEN_DAYS = 365;

/** Validade em dias inteiros entre 1 e 365; null quando inválida. */
export function parseTokenDays(raw: string): number | null {
  if (!/^\d{1,3}$/.test(raw.trim())) return null;
  const n = Number(raw.trim());
  return n >= MIN_TOKEN_DAYS && n <= MAX_TOKEN_DAYS ? n : null;
}

/** Ações registradas hoje pelo servidor (s.audit e DB.Audit); outras aparecem só com o código técnico. */
export const knownAuditActions = [
  "login",
  "logout",
  "reauth",
  "recovery_code_used",
  "mfa_enabled",
  "password_changed",
  "first_admin_created",
  "password_reset_with_token",
  "reset_token_issued",
  "api_token_created",
  "api_token_revoked",
  "user_created",
  "user_updated",
  "user_deleted",
  "user_mfa_reset",
  "exception_created",
  "exception_revoked",
  "schedule_created",
  "schedule_updated",
  "schedule_deleted",
  "resource_profile_saved",
  "resource_profile_reset",
  "run_created",
  "run_canceled",
  "run_paused",
  "run_resumed",
  "run_limits_changed",
  "finding_transition",
  "backup_created",
] as const;

export type KnownAuditAction = (typeof knownAuditActions)[number];

export function isKnownAuditAction(action: string): action is KnownAuditAction {
  return (knownAuditActions as readonly string[]).includes(action);
}

export type AuditFilter = { text: string; action: string };

/** Filtro local sobre as entradas já carregadas (a API só pagina por cursor). */
export function filterAudit(entries: readonly AuditEntry[], filter: AuditFilter): AuditEntry[] {
  const needle = filter.text.trim().toLocaleLowerCase();
  return entries.filter((e) => {
    if (filter.action && e.action !== filter.action) return false;
    if (!needle) return true;
    return [e.actor, e.target, e.detail, e.ip, e.action].some((v) => v.toLocaleLowerCase().includes(needle));
  });
}

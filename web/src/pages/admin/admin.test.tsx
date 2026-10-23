import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router";
import { afterEach, beforeAll, describe, expect, it, vi } from "vitest";
import type { Schemas } from "../../api/client";
import { validatePasswordForm } from "./AccountPanel";
import {
  buildUserUpdate,
  checkPassword,
  checkUsername,
  countActiveAdmins,
  filterAudit,
  generatePassword,
  issuableRoles,
  parseTokenDays,
  tokenStatus,
  updateEndsSessions,
  updateRemovesLastAdmin,
  userGuard,
  type AuditEntry,
  type User,
} from "./adminLogic";
import { TokensPage } from "./TokensPage";

function user(over: Partial<User>): User {
  return {
    id: 1,
    username: "ana",
    display_name: "Ana",
    role: "admin",
    disabled: false,
    mfa_enabled: true,
    created_at: "2026-10-01T10:00:00Z",
    ...over,
  };
}

describe("regras de usuários", () => {
  const ana = user({ id: 1 });
  const bruno = user({ id: 2, username: "bruno", role: "operator" });
  const carla = user({ id: 3, username: "carla", role: "admin", disabled: true });

  it("conta só administradores habilitados", () => {
    expect(countActiveAdmins([ana, bruno, carla])).toBe(1);
  });

  it("protege o último administrador e impede remover a si mesmo", () => {
    expect(userGuard(ana, [ana, bruno, carla], 2)).toEqual({ isSelf: false, lastAdmin: true, canDelete: false });
    expect(userGuard(bruno, [ana, bruno], 2)).toEqual({ isSelf: true, lastAdmin: false, canDelete: false });
    expect(userGuard(ana, [ana, user({ id: 4, username: "davi" })], 2).canDelete).toBe(true);
  });

  it("monta o PATCH só com o que mudou", () => {
    expect(buildUserUpdate(bruno, { display_name: " Ana ", role: "operator", disabled: false })).toBeNull();
    expect(buildUserUpdate(bruno, { display_name: "Bruno S.", role: "reader", disabled: true })).toEqual({
      display_name: "Bruno S.",
      role: "reader",
      disabled: true,
    });
  });

  it("avisa quando as sessões serão encerradas", () => {
    expect(updateEndsSessions(bruno, { display_name: "B" })).toBe(false);
    expect(updateEndsSessions(bruno, { role: "reader" })).toBe(true);
    expect(updateEndsSessions(bruno, { disabled: true })).toBe(true);
    expect(updateEndsSessions(bruno, { disabled: false })).toBe(false);
  });

  it("recusa rebaixar ou desativar o último administrador", () => {
    expect(updateRemovesLastAdmin(ana, { role: "operator" }, [ana, bruno])).toBe(true);
    expect(updateRemovesLastAdmin(ana, { disabled: true }, [ana, bruno])).toBe(true);
    expect(updateRemovesLastAdmin(ana, { display_name: "A" }, [ana, bruno])).toBe(false);
    expect(updateRemovesLastAdmin(ana, { role: "operator" }, [ana, user({ id: 5, username: "eva" })])).toBe(false);
  });

  it("valida nome de usuário e senha como o servidor", () => {
    expect(checkUsername("ana.souza@loja")).toBe(true);
    expect(checkUsername("joão")).toBe(false);
    expect(checkUsername("a")).toBe(false);
    expect(checkPassword("curta")).toBe("short");
    // 12 caracteres com acento: conta caracteres, não bytes.
    expect(checkPassword("ááááááááááá1")).toBeNull();
    expect(checkPassword("é".repeat(129))).toBe("long");
  });

  it("gera senha inicial longa, sem caracteres ambíguos", () => {
    const pw = generatePassword();
    expect(pw).toHaveLength(20);
    expect(pw).not.toMatch(/[0O1lI]/);
    expect(generatePassword()).not.toBe(pw);
  });
});

describe("regras de tokens", () => {
  it("limita o perfil do token ao do usuário ou leitura", () => {
    expect(issuableRoles("admin")).toEqual(["admin", "operator", "auditor", "reader"]);
    expect(issuableRoles("operator")).toEqual(["operator", "reader"]);
    expect(issuableRoles("auditor")).toEqual(["auditor", "reader"]);
    expect(issuableRoles("reader")).toEqual(["reader"]);
    expect(issuableRoles(undefined)).toEqual([]);
  });

  it("aceita validade inteira de 1 a 365 dias", () => {
    expect(parseTokenDays("90")).toBe(90);
    expect(parseTokenDays(" 365 ")).toBe(365);
    for (const bad of ["0", "366", "1.5", "-3", "", "abc"]) expect(parseTokenDays(bad)).toBeNull();
  });

  it("classifica ativo, expirado e revogado", () => {
    const base: Schemas["ApiToken"] = {
      id: 1,
      name: "zabbix",
      username: "ana",
      role: "reader",
      prefix: "vht_abcdef",
      created_at: "2026-01-01T00:00:00Z",
      expires_at: "2026-12-31T00:00:00Z",
    };
    const now = Date.parse("2026-10-22T00:00:00Z");
    expect(tokenStatus(base, now)).toBe("active");
    expect(tokenStatus({ ...base, expires_at: "2026-10-01T00:00:00Z" }, now)).toBe("expired");
    expect(tokenStatus({ ...base, revoked_at: "2026-10-02T00:00:00Z" }, now)).toBe("revoked");
  });
});

describe("filtro da auditoria", () => {
  const entries: AuditEntry[] = [
    { id: 3, at: "2026-10-22T10:00:00Z", actor: "ana", action: "user_created", target: "bruno", detail: "perfil operator", ip: "10.0.0.5" },
    { id: 2, at: "2026-10-22T09:00:00Z", actor: "bruno", action: "login", target: "", detail: "", ip: "10.0.0.9" },
    { id: 1, at: "2026-10-22T08:00:00Z", actor: "root", action: "reset_token_issued", target: "Ana", detail: "terminal do servidor", ip: "" },
  ];

  it("combina ação e texto, sem diferenciar maiúsculas", () => {
    expect(filterAudit(entries, { text: "", action: "" }).map((e) => e.id)).toEqual([3, 2, 1]);
    expect(filterAudit(entries, { text: "ANA", action: "" }).map((e) => e.id)).toEqual([3, 1]);
    expect(filterAudit(entries, { text: "ana", action: "user_created" }).map((e) => e.id)).toEqual([3]);
    expect(filterAudit(entries, { text: "10.0.0.9", action: "" }).map((e) => e.id)).toEqual([2]);
  });
});

describe("troca de senha", () => {
  const t = (key: string) => key;
  it("exige senha atual, tamanho mínimo, diferença e repetição", () => {
    expect(validatePasswordForm({ current: "", next: "curta", repeat: "outra" }, t)).toEqual({
      current: "admin.account.currentRequired",
      next: "admin.common.passwordShort",
      repeat: "admin.account.mismatch",
    });
    expect(validatePasswordForm({ current: "senha-antiga-123", next: "senha-antiga-123", repeat: "senha-antiga-123" }, t)).toEqual({
      next: "admin.account.sameAsCurrent",
    });
    expect(validatePasswordForm({ current: "senha-antiga-123", next: "frase longa e nova", repeat: "frase longa e nova" }, t)).toEqual({});
  });
});

describe("TokensPage", () => {
  beforeAll(() => {
    // O jsdom não implementa o modo modal do <dialog>.
    HTMLDialogElement.prototype.showModal ??= function (this: HTMLDialogElement) {
      this.setAttribute("open", "");
    };
    HTMLDialogElement.prototype.close ??= function (this: HTMLDialogElement) {
      this.removeAttribute("open");
      this.dispatchEvent(new Event("close"));
    };
  });
  afterEach(() => vi.restoreAllMocks());

  it("reautentica, cria o token com o corpo certo e mostra o valor uma única vez", async () => {
    const session: Schemas["Session"] = {
      authenticated: true,
      setup_required: false,
      secure_transport: true,
      stage: "full",
      user: { id: 7, username: "op", display_name: "Operadora", role: "operator", mfa_enabled: false },
    };
    const calls: { method: string; path: string; body: unknown }[] = [];
    let tokens: Schemas["ApiToken"][] = [];
    vi.spyOn(globalThis, "fetch").mockImplementation(async (input) => {
      const req = input as Request;
      const path = new URL(req.url).pathname;
      const body = req.method === "GET" ? undefined : await req.json();
      calls.push({ method: req.method, path, body });
      const json = (data: unknown, status = 200) =>
        new Response(JSON.stringify(data), { status, headers: { "Content-Type": "application/json" } });
      if (path === "/api/v1/tokens" && req.method === "GET") return json(tokens);
      if (path === "/api/v1/auth/reauth") return json(session);
      if (path === "/api/v1/tokens" && req.method === "POST") {
        const info: Schemas["ApiToken"] = {
          id: 1,
          name: "zabbix",
          username: "op",
          role: "reader",
          prefix: "vht_secret",
          created_at: "2026-10-22T10:00:00Z",
          expires_at: "2027-01-20T10:00:00Z",
        };
        tokens = [info];
        return json({ token: "vht_secretvalue123", info }, 201);
      }
      return json({ error: "inesperado" }, 500);
    });

    const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
    qc.setQueryData(["session"], session);
    const ui = userEvent.setup();
    render(
      <QueryClientProvider client={qc}>
        <MemoryRouter initialEntries={["/tokens"]}>
          <TokensPage />
        </MemoryRouter>
      </QueryClientProvider>,
    );

    expect(await screen.findByText(/Nenhum token criado/)).toBeInTheDocument();
    expect(screen.getByText("Authorization: Bearer <token>")).toBeInTheDocument();

    await ui.click(screen.getByRole("button", { name: "Criar token" }));
    // Operador só emite operador ou leitura.
    const roleSelect = screen.getByLabelText("Perfil do token");
    expect(within(roleSelect).getAllByRole("option").map((o) => o.getAttribute("value"))).toEqual(["operator", "reader"]);

    const form = screen.getByLabelText("Nome").closest("form") as HTMLFormElement;
    const submit = within(form).getByRole("button", { name: "Criar token" });
    await ui.type(screen.getByLabelText("Nome"), "  zabbix  ");
    const days = screen.getByLabelText("Validade em dias");
    await ui.clear(days);
    await ui.type(days, "400");
    await ui.click(submit);
    expect(screen.getByText("Informe um número inteiro de 1 a 365.")).toBeInTheDocument();

    await ui.clear(days);
    await ui.type(days, "90");
    await ui.click(submit);

    const dialog = await screen.findByRole("dialog");
    await ui.type(within(dialog).getByLabelText("Confirme sua senha"), "minha-senha-forte");
    await ui.click(within(dialog).getByRole("button", { name: "Criar token" }));

    expect(await screen.findByText("vht_secretvalue123")).toBeInTheDocument();
    expect(screen.getByText(/não será exibido de novo/)).toBeInTheDocument();
    expect(calls.filter((c) => c.method === "POST")).toEqual([
      { method: "POST", path: "/api/v1/auth/reauth", body: { password: "minha-senha-forte" } },
      { method: "POST", path: "/api/v1/tokens", body: { name: "zabbix", role: "reader", expires_in_days: 90 } },
    ]);

    await ui.click(screen.getByRole("button", { name: "Já guardei o token" }));
    await waitFor(() => expect(screen.queryByText("vht_secretvalue123")).toBeNull());
    expect(await screen.findByRole("button", { name: "Revogar zabbix" })).toBeInTheDocument();
  });
});

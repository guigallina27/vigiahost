import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router";
import { afterEach, beforeAll, describe, expect, it, vi } from "vitest";
import type { Schemas } from "../../api/client";
import enRules from "../../i18n/en/rules.json";
import ptRules from "../../i18n/pt-BR/rules.json";
import { engineGuidance } from "./EnginesPage";
import { lmdGuidance, RulesPage } from "./RulesPage";

type Overview = Schemas["RulesOverview"];
type Lmd = Schemas["LmdStatus"];

beforeAll(() => {
  // O jsdom não implementa o modo modal do <dialog>; basta simular a abertura e o fechamento.
  HTMLDialogElement.prototype.showModal ??= function (this: HTMLDialogElement) {
    this.setAttribute("open", "");
  };
  HTMLDialogElement.prototype.close ??= function (this: HTMLDialogElement) {
    this.removeAttribute("open");
    this.dispatchEvent(new Event("close"));
  };
});

afterEach(() => vi.unstubAllGlobals());

function keys(obj: object, prefix = ""): string[] {
  return Object.entries(obj).flatMap(([k, v]) =>
    typeof v === "object" && v !== null ? keys(v as object, `${prefix}${k}.`) : [`${prefix}${k}`],
  );
}

const lmdOff: Lmd = { installed: false, usable: false, enabled: false, state: "not_installed", path: "/usr/local/maldetect" };

function overview(patch: Partial<Overview> = {}): Overview {
  return {
    yara: {
      user_dir: "/etc/vigiahost/rules.d",
      compiling: false,
      yr_version: "1.21.0",
      last_compile: { at: "2026-10-22T11:00:00Z", trigger: "manual", ok: true, set_version: "abc123", selftest: true },
      sources: [
        { name: "controle", origin: "builtin", enabled: true, mandatory: true, files: 1, rules: 1, bytes: 300, state: "ok", license: "GPL-3.0-only" },
        { name: "vigiahost", origin: "builtin", enabled: true, mandatory: false, files: 1, rules: 15, bytes: 9000, state: "ok", license: "GPL-3.0-only" },
        {
          name: "loja",
          origin: "local",
          enabled: true,
          mandatory: false,
          files: 2,
          rules: 4,
          bytes: 1200,
          state: "error",
          problem: "linha 3: erro de sintaxe",
          path: "/etc/vigiahost/rules.d/loja",
          hash: "a".repeat(64),
          updated_at: "2026-10-21T10:00:00Z",
        },
      ],
    },
    clamav: { state: "operational", version: "1.4.3", signatures_version: "27800", mode: "clamd", lmd_signatures: [] },
    lmd: lmdOff,
    ...patch,
  };
}

function session(role: Schemas["Role"]): Schemas["Session"] {
  return {
    authenticated: true,
    setup_required: false,
    secure_transport: true,
    stage: "full",
    user: { id: 1, username: "adm", display_name: "Admin", role, mfa_enabled: false },
  };
}

const adminSession = session("admin");

function json(body: unknown, status = 200) {
  return new Response(JSON.stringify(body), { status, headers: { "Content-Type": "application/json" } });
}

type Call = { method: string; path: string; body?: unknown };

function mockApi(data: Overview, opts: { compileStatus?: number } = {}) {
  const calls: Call[] = [];
  vi.stubGlobal(
    "fetch",
    vi.fn(async (req: Request) => {
      const path = new URL(req.url).pathname;
      const text = req.method === "GET" ? "" : await req.text();
      calls.push({ method: req.method, path, ...(text ? { body: JSON.parse(text) } : {}) });
      if (path === "/api/v1/rules" && req.method === "GET") return json(data);
      if (path === "/api/v1/rules/compile") {
        if (opts.compileStatus) return json({ error: "já há uma compilação", code: "conflict" }, opts.compileStatus);
        return json({ ...data, yara: { ...data.yara, compiling: true } });
      }
      if (path === "/api/v1/auth/reauth") return json(adminSession);
      if (path.startsWith("/api/v1/rules/sources/")) {
        const name = path.split("/").pop();
        const enabled = (JSON.parse(text) as { enabled: boolean }).enabled;
        return json({
          ...data,
          yara: {
            ...data.yara,
            compiling: true,
            sources: data.yara.sources.map((s) => (s.name === name ? { ...s, enabled, state: enabled ? "pending" : "disabled" } : s)),
          },
        });
      }
      if (path === "/api/v1/rules/lmd") {
        const enabled = (JSON.parse(text) as { enabled: boolean }).enabled;
        return json({ ...data, lmd: { ...data.lmd, enabled, state: enabled ? "operational" : "disabled" } });
      }
      return json({ error: "inesperado" }, 500);
    }),
  );
  return calls;
}

function renderPage(role: Schemas["Role"]) {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } });
  qc.setQueryData(["session"], session(role));
  render(
    <QueryClientProvider client={qc}>
      <MemoryRouter initialEntries={["/regras"]}>
        <RulesPage />
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

describe("textos da tela Regras e fontes", () => {
  it("mesmas chaves nos dois idiomas", () => {
    expect(keys(enRules).sort()).toEqual(keys(ptRules).sort());
  });
});

describe("orientação do LMD", () => {
  it("distingue ausente, inutilizável, ligado sem servir e autoteste", () => {
    expect(lmdGuidance(lmdOff)).toBe("missing");
    expect(lmdGuidance({ ...lmdOff, installed: true, state: "not_installed" })).toBe("unusable");
    expect(lmdGuidance({ ...lmdOff, installed: true, enabled: true, state: "unavailable" })).toBe("unavailable");
    expect(lmdGuidance({ ...lmdOff, installed: true, usable: true, state: "disabled" })).toBeNull();
    expect(
      lmdGuidance({
        ...lmdOff,
        installed: true,
        usable: true,
        enabled: true,
        state: "degraded",
        last_selftest: { run_id: "r1", passed: false, detail: "EICAR não detectado" },
      }),
    ).toBe("selftestFailed");
  });

  it("na tela Motores, desligado e ausente não são falha", () => {
    expect(engineGuidance({ id: "lmd", name: "LMD", state: "not_installed" }, undefined)).toBe("lmdMissing");
    expect(engineGuidance({ id: "lmd", name: "LMD", state: "disabled" }, undefined)).toBe("lmdDisabled");
    expect(engineGuidance({ id: "lmd", name: "LMD", state: "unavailable" }, undefined)).toBe("lmdUnavailable");
    expect(engineGuidance({ id: "lmd", name: "LMD", state: "operational" }, undefined)).toBeNull();
  });
});

describe("tela Regras e fontes", () => {
  it("mostra fontes, estado da compilação e orientação do LMD ausente para quem só lê", async () => {
    mockApi(overview());
    renderPage("reader");
    const table = await screen.findByRole("table", { name: "Fontes de regras YARA" });
    expect(within(table).getAllByRole("row")).toHaveLength(4);
    expect(within(table).getByText("linha 3: erro de sintaxe")).toBeInTheDocument();
    expect(within(table).getByText("Com erro")).toBeInTheDocument();
    expect(within(table).getByText("4 regras em 2 arquivos")).toBeInTheDocument();
    expect(screen.getByText("Conjunto compilado")).toBeInTheDocument();
    expect(screen.getByText(/O LMD 2.x não está instalado/)).toBeInTheDocument();
    expect(screen.getByText(/Só o administrador compila regras/)).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Compilar regras" })).toBeNull();
    expect(screen.queryByRole("button", { name: /Desativar fonte/ })).toBeNull();
    expect(screen.queryByRole("button", { name: "Ligar o LMD" })).toBeNull();
  });

  it("desativa uma fonte com reautenticação e mostra o novo estado", async () => {
    const calls = mockApi(overview());
    renderPage("admin");
    const ui = userEvent.setup();
    // O controle positivo é obrigatório: sem botão.
    const table = await screen.findByRole("table", { name: "Fontes de regras YARA" });
    expect(within(table).getByText("Obrigatória")).toBeInTheDocument();
    await ui.click(screen.getByRole("button", { name: "Desativar fonte loja" }));
    const dialog = await screen.findByRole("dialog");
    expect(within(dialog).getByText("loja")).toBeInTheDocument();
    await ui.type(within(dialog).getByLabelText("Confirme sua senha"), "minha-senha-forte");
    await ui.click(within(dialog).getByRole("button", { name: "Desativar fonte" }));
    expect(await screen.findByText("Fonte loja atualizada; a compilação foi pedida.")).toBeInTheDocument();
    expect(screen.getByText("Desativada")).toBeInTheDocument();
    expect(screen.getByText("Compilando as regras…")).toBeInTheDocument();
    expect(calls.filter((c) => c.method !== "GET")).toEqual([
      { method: "POST", path: "/api/v1/auth/reauth", body: { password: "minha-senha-forte" } },
      { method: "PUT", path: "/api/v1/rules/sources/loja", body: { enabled: false } },
    ]);
  });

  it("compila as regras e avisa quando já há compilação em andamento", async () => {
    const calls = mockApi(overview(), { compileStatus: 409 });
    renderPage("admin");
    const ui = userEvent.setup();
    await ui.click(await screen.findByRole("button", { name: "Compilar regras" }));
    expect(await screen.findByText("Já há uma compilação de regras em andamento.")).toBeInTheDocument();
    expect(calls.some((c) => c.method === "POST" && c.path === "/api/v1/rules/compile")).toBe(true);
  });

  it("liga o LMD instalado e mostra as assinaturas", async () => {
    const lmd: Lmd = {
      installed: true,
      usable: true,
      enabled: false,
      state: "disabled",
      path: "/usr/local/maldetect",
      version: "2.0.1",
      signatures_version: "2026052490478",
      signatures_date: "2026-05-24",
      signatures: { md5: 0, sha256: 42634, hex: 2373, csig: 86, yara: 3706, user: 0 },
    };
    const calls = mockApi(
      overview({
        lmd,
        clamav: { state: "operational", mode: "clamd", lmd_signatures: ["/var/lib/clamav/rfxn.ndb"] },
      }),
    );
    renderPage("admin");
    const ui = userEvent.setup();
    expect(await screen.findByText(/42\.634 SHA-256/)).toBeInTheDocument();
    expect(screen.getByText(/As assinaturas do LMD \(rfxn\) já estão/)).toBeInTheDocument();
    await ui.click(screen.getByRole("button", { name: "Ligar o LMD" }));
    const dialog = await screen.findByRole("dialog");
    await ui.type(within(dialog).getByLabelText("Confirme sua senha"), "minha-senha-forte");
    await ui.click(within(dialog).getByRole("button", { name: "Ligar o LMD" }));
    expect(await screen.findByText("LMD ligado para as próximas varreduras de arquivos.")).toBeInTheDocument();
    await waitFor(() => expect(screen.getByRole("button", { name: "Desligar o LMD" })).toBeInTheDocument());
    expect(calls.filter((c) => c.method === "PUT")).toEqual([{ method: "PUT", path: "/api/v1/rules/lmd", body: { enabled: true } }]);
  });
});

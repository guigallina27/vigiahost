import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen } from "@testing-library/react";
import { MemoryRouter, Route, Routes } from "react-router";
import { afterEach, describe, expect, it, vi } from "vitest";
import type { Schemas } from "../../api/client";
import {
  buildExceptionBody,
  draftFromFinding,
  emptyDraft,
  exceptionStatus,
  normalizePrefix,
  validateDraft,
  type ExceptionDraft,
} from "./exceptionRules";
import { filtersToParams, filtersToQuery, hasActiveFilters, openStates, parseFilters, splitCategories, toggleValue, severityList } from "./filters";
import { FindingsPage } from "./FindingsPage";
import { buildTransition, manualTargets } from "./transitions";

const SHA = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08";

function finding(over: Partial<Schemas["Finding"]> = {}): Schemas["Finding"] {
  return {
    id: 42,
    kind: "file",
    engine: "yara",
    engine_version: "4.5.2",
    rules_version: "2026.10.01",
    signature: "PHP_Webshell_Generic",
    source: "",
    license: "",
    author: "",
    reference: "",
    description: "Webshell PHP genérico",
    category: "webshell",
    severity: "critical",
    sha256: SHA,
    file_type: "php",
    state: "new",
    assignee: "",
    first_run: "r-1",
    last_run: "r-2",
    first_seen: "2026-10-20T10:00:00Z",
    last_seen: "2026-10-21T10:00:00Z",
    state_changed: "2026-10-20T10:00:00Z",
    times_seen: 2,
    locations_count: 3,
    evidence: {},
    location: { path: "/home/loja/public_html/up/x.php", dev: 1, ino: 2, size: 10, mode: 0o100644, uid: 1000, gid: 1000, nlink: 1 },
    ...over,
  };
}

describe("filtros da lista de achados", () => {
  it("sem estado na URL mostra os abertos; state=all mostra todos", () => {
    expect(parseFilters(new URLSearchParams("")).states).toEqual(openStates);
    expect(parseFilters(new URLSearchParams("state=all")).states).toEqual([]);
    expect(parseFilters(new URLSearchParams("state=bogus")).states).toEqual(openStates);
  });

  it("aceita os links da visão geral (severity, run_id) e descarta valores desconhecidos", () => {
    const f = parseFilters(new URLSearchParams("severity=critical&severity=xx&run_id=r-9&kind=process"));
    expect(f.severities).toEqual(["critical"]);
    expect(f.kinds).toEqual(["process"]);
    expect(f.runId).toBe("r-9");
    expect(parseFilters(new URLSearchParams("run=r-7")).runId).toBe("r-7");
  });

  it("URL curta: o padrão não aparece, e o vaivém URL → filtros → URL é estável", () => {
    expect(filtersToParams(parseFilters(new URLSearchParams(""))).toString()).toBe("");
    expect(hasActiveFilters(parseFilters(new URLSearchParams("")))).toBe(false);
    const url = "state=resolved&severity=high&category=miner&run_id=r-1&q=wp-content";
    expect(filtersToParams(parseFilters(new URLSearchParams(url))).toString()).toBe(url);
    expect(filtersToParams({ ...parseFilters(new URLSearchParams("")), states: [] }).toString()).toBe("state=all");
  });

  it("monta a consulta com os nomes do contrato (run, before, limit)", () => {
    const f = parseFilters(new URLSearchParams("severity=critical&run_id=r-1&q=%20x.php%20"));
    expect(filtersToQuery(f, 99)).toEqual({
      limit: 50,
      state: ["new", "in_review", "confirmed"],
      severity: ["critical"],
      run: "r-1",
      q: "x.php",
      before: 99,
    });
    expect(filtersToQuery({ ...f, states: [] })).not.toHaveProperty("state");
  });

  it("alterna valores na ordem canônica e separa categorias", () => {
    expect(toggleValue(["low"], "critical", severityList)).toEqual(["critical", "low"]);
    expect(toggleValue(["critical", "low"], "critical", severityList)).toEqual(["low"]);
    expect(splitCategories(" webshell, miner ,,webshell")).toEqual(["webshell", "miner"]);
  });
});

describe("transições", () => {
  it("tira 'coberto por exceção' das opções manuais", () => {
    expect(manualTargets(["in_review", "excepted", "resolved"])).toEqual(["in_review", "resolved"]);
  });

  it("falso positivo e resolvido pedem nota; os demais não", () => {
    expect(buildTransition(null, "")).toEqual({ ok: false, error: "chooseState" });
    expect(buildTransition("false_positive", "  ")).toEqual({ ok: false, error: "noteMissing" });
    expect(buildTransition("resolved", " limpo ")).toEqual({ ok: true, body: { to: "resolved", note: "limpo" } });
    expect(buildTransition("in_review", "")).toEqual({ ok: true, body: { to: "in_review" } });
  });
});

describe("exceções", () => {
  const now = new Date("2026-10-22T12:00:00Z");

  it("preenche a partir do achado: hash, regra e diretório do arquivo", () => {
    const d = draftFromFinding(finding());
    expect(d).toMatchObject({ scope: "hash_rule", sha256: SHA, signature: "PHP_Webshell_Generic", findingId: 42 });
    expect(d.pathPrefix).toBe("/home/loja/public_html/up");
    const proc = draftFromFinding(finding({ kind: "process", location: undefined as never, process: { pid: 1, ppid: 0, uid: 0, comm: "x", exe: "/tmp/.x/kd" } }));
    expect(proc.pathPrefix).toBe("/tmp/.x");
  });

  it("valida como o servidor: SHA-256, diretório fora da raiz, validade em diretório, global só para admin", () => {
    const base: ExceptionDraft = { ...emptyDraft(), reason: "biblioteca do tema" };
    expect(validateDraft({ ...base, scope: "hash", sha256: "abc" }, { isAdmin: false })).toEqual({ sha256: "sha256Invalid" });
    expect(validateDraft({ ...base, scope: "hash", sha256: SHA.toUpperCase() }, { isAdmin: false })).toEqual({});
    expect(
      validateDraft({ ...base, scope: "rule_prefix", signature: "R", pathPrefix: "///", validity: "none" }, { isAdmin: false }),
    ).toEqual({ pathPrefix: "pathPrefixInvalid", validity: "validityRequired" });
    expect(validateDraft({ ...base, scope: "rule_global", signature: "R" }, { isAdmin: false })).toEqual({ scope: "scopeAdminOnly" });
    expect(validateDraft({ ...base, scope: "rule_global", signature: "R", reason: "x" }, { isAdmin: true })).toEqual({
      reason: "reasonTooShort",
    });
  });

  it("monta o corpo só com os campos do escopo e a validade a partir de agora", () => {
    const d: ExceptionDraft = {
      scope: "rule_prefix",
      sha256: SHA,
      signature: " PHP_Webshell_Generic ",
      pathPrefix: "/home/loja/public_html/cache/",
      reason: "  cache do plugin  ",
      validity: "30",
      findingId: 42,
    };
    expect(buildExceptionBody(d, now)).toEqual({
      scope: "rule_prefix",
      finding_id: 42,
      signature: "PHP_Webshell_Generic",
      path_prefix: "/home/loja/public_html/cache",
      reason: "cache do plugin",
      expires_at: "2026-11-21T12:00:00.000Z",
    });
    expect(buildExceptionBody({ ...d, scope: "hash", validity: "none" }, now)).toEqual({
      scope: "hash",
      finding_id: 42,
      sha256: SHA,
      reason: "cache do plugin",
    });
    expect(normalizePrefix("/")).toBe("/");
  });

  it("situação: revogada antes de vencida", () => {
    const e = { active: false, revoked_at: "2026-10-01T00:00:00Z" } as Schemas["Exception"];
    expect(exceptionStatus(e)).toBe("revoked");
    expect(exceptionStatus({ ...e, revoked_at: undefined } as unknown as Schemas["Exception"])).toBe("expired");
    expect(exceptionStatus({ ...e, revoked_at: undefined, active: true } as unknown as Schemas["Exception"])).toBe("active");
  });
});

describe("FindingsPage", () => {
  afterEach(() => vi.restoreAllMocks());

  it("aplica os filtros da URL na consulta e mostra a linha com severidade, estado e objeto", async () => {
    const requests: string[] = [];
    vi.spyOn(globalThis, "fetch").mockImplementation(async (input) => {
      const url = input instanceof Request ? input.url : String(input);
      requests.push(url);
      return new Response(JSON.stringify({ findings: [finding()] }), {
        status: 200,
        headers: { "Content-Type": "application/json" },
      });
    });
    const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
    render(
      <QueryClientProvider client={qc}>
        <MemoryRouter initialEntries={["/achados?severity=critical&run_id=r-2"]}>
          <Routes>
            <Route path="/achados" element={<FindingsPage />} />
          </Routes>
        </MemoryRouter>
      </QueryClientProvider>,
    );

    expect(await screen.findByRole("link", { name: "PHP_Webshell_Generic" })).toHaveAttribute("href", "/achados/42");
    const url = new URL(requests[0] ?? "");
    expect(url.pathname).toBe("/api/v1/findings");
    expect(url.searchParams.getAll("state")).toEqual(["new", "in_review", "confirmed"]);
    expect(url.searchParams.getAll("severity")).toEqual(["critical"]);
    expect(url.searchParams.get("run")).toBe("r-2");
    expect(screen.getByRole("cell", { name: /Crítico/ })).toBeInTheDocument();
    expect(screen.getByText("Todos os achados com estes filtros estão na lista.")).toBeInTheDocument();
    expect(screen.getByRole("checkbox", { name: "Crítico" })).toBeChecked();
    expect(screen.getByRole("textbox", { name: /Execução/ })).toHaveValue("r-2");
  });
});

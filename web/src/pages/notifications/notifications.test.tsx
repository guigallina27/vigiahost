import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router";
import { afterEach, beforeAll, describe, expect, it, vi } from "vitest";
import type { Schemas } from "../../api/client";
import {
  buildChannelBody,
  buildRuleBody,
  emptyChannelValues,
  emptyRuleValues,
  freeEvents,
  generateWebhookSecret,
  minutesParts,
  outboxSummaryParts,
  splitRecipients,
  valuesFromChannel,
  webhookKeyBytes,
  type Channel,
  type OutboxEntry,
  type Rule,
} from "./notifications";
import { NotificationsPage } from "./NotificationsPage";
import { canRetry } from "./OutboxPanel";

const webhook: Channel = {
  id: 1,
  name: "SOC",
  kind: "webhook",
  enabled: true,
  include_details: true,
  webhook: { url: "https://hooks.example.com/vigiahost", allow_private_network: false },
  secret_configured: true,
  secret_readable: true,
  created_by: "ana",
  created_at: "2026-10-20T10:00:00Z",
  updated_at: "2026-10-20T10:00:00Z",
};

const email: Channel = {
  ...webhook,
  id: 2,
  name: "E-mail do plantão",
  kind: "email",
  email: { host: "smtp.example.com", port: 587, security: "starttls", username: "alertas", from: "vigia@example.com", to: ["a@example.com", "b@example.com"] },
};

delete email.webhook;

describe("corpo do canal", () => {
  it("e-mail completa a porta, separa destinatários e exige senha só quando falta", () => {
    const v = { ...emptyChannelValues("email"), name: " Plantão ", host: "smtp.example.com", from: "VigiaHost <vigia@example.com>", to: "a@example.com, b@example.com\nc@example.com" };
    const built = buildChannelBody(v);
    expect(built).toEqual({
      ok: true,
      body: {
        name: "Plantão",
        kind: "email",
        enabled: true,
        include_details: true,
        email: { host: "smtp.example.com", port: 587, security: "starttls", from: "VigiaHost <vigia@example.com>", to: ["a@example.com", "b@example.com", "c@example.com"] },
      },
    });
    expect(buildChannelBody({ ...v, username: "alertas" })).toMatchObject({ ok: false, field: "secret", error: "passwordRequired" });
    // Editando um canal com senha guardada, o campo vazio mantém a senha (e ela não vai no corpo).
    const kept = buildChannelBody({ ...valuesFromChannel(email) }, email);
    expect(kept.ok && kept.body.secret).toBeUndefined();
    expect(buildChannelBody({ ...v, username: "alertas", secret: "nova" })).toMatchObject({ ok: true, body: { secret: "nova" } });
    expect(buildChannelBody({ ...v, security: "none" })).toMatchObject({ ok: false, error: "plainRemote" });
    expect(buildChannelBody({ ...v, security: "none", host: "localhost" }).ok).toBe(true);
    expect(buildChannelBody({ ...v, host: "smtp://x" })).toMatchObject({ ok: false, field: "host" });
    expect(buildChannelBody({ ...v, port: "70000" })).toMatchObject({ ok: false, field: "port" });
    expect(buildChannelBody({ ...v, to: "não-é-email" })).toMatchObject({ ok: false, error: "toInvalid" });
  });

  it("webhook exige http(s), sem credencial no endereço, e segredo forte", () => {
    const v = { ...emptyChannelValues("webhook"), name: "SOC", url: "https://hooks.example.com/x" };
    expect(buildChannelBody(v)).toMatchObject({ ok: false, error: "secretRequired" });
    expect(buildChannelBody({ ...v, secret: "curto" })).toMatchObject({ ok: false, error: "secretShort" });
    expect(buildChannelBody({ ...v, url: "ftp://x", secret: generateWebhookSecret() })).toMatchObject({ ok: false, error: "urlInvalid" });
    expect(buildChannelBody({ ...v, url: "https://u:p@x.com", secret: generateWebhookSecret() })).toMatchObject({ ok: false, error: "urlInvalid" });
    const secret = generateWebhookSecret();
    expect(buildChannelBody({ ...v, secret, allowPrivate: true })).toMatchObject({
      ok: true,
      body: { webhook: { url: "https://hooks.example.com/x", allow_private_network: true }, secret },
    });
    expect(buildChannelBody(valuesFromChannel(webhook), webhook).ok).toBe(true);
  });

  it("gera segredo no formato whsec_ com 32 bytes", () => {
    const s = generateWebhookSecret();
    expect(s).toMatch(/^whsec_[A-Za-z0-9+/]+=*$/);
    expect(webhookKeyBytes(s)).toBe(32);
    expect(generateWebhookSecret()).not.toBe(s);
    expect(webhookKeyBytes("x".repeat(30))).toBe(30);
    expect(webhookKeyBytes("whsec_@@@")).toBe(0);
  });

  it("separa destinatários por linha, vírgula ou ponto e vírgula", () => {
    expect(splitRecipients(" a@x.com ;b@x.com,\n\n c@x.com ")).toEqual(["a@x.com", "b@x.com", "c@x.com"]);
  });
});

describe("regras e caixa de saída", () => {
  const rule: Rule = {
    id: 9,
    channel_id: 1,
    event: "finding_new",
    min_severity: "high",
    dedup_minutes: 1440,
    enabled: true,
    created_at: "2026-10-20T10:00:00Z",
    updated_at: "2026-10-20T10:00:00Z",
  };

  it("monta o corpo da regra e valida a janela", () => {
    expect(buildRuleBody(emptyRuleValues(1))).toEqual({
      ok: true,
      body: { channel_id: 1, event: "finding_new", min_severity: "high", enabled: true },
    });
    expect(buildRuleBody({ ...emptyRuleValues(1), dedupMinutes: "30" })).toMatchObject({ ok: true, body: { dedup_minutes: 30 } });
    expect(buildRuleBody({ ...emptyRuleValues(1), dedupMinutes: "99999" })).toEqual({ ok: false, error: "dedupInvalid" });
    expect(buildRuleBody(emptyRuleValues())).toEqual({ ok: false, error: "channelRequired" });
  });

  it("oferece só eventos sem regra no canal", () => {
    expect(freeEvents([rule], 1)).not.toContain("finding_new");
    expect(freeEvents([rule], 1, "finding_new")).toContain("finding_new");
    expect(freeEvents([rule], 2)).toContain("finding_new");
    expect(minutesParts(1440)).toEqual({ unit: "days", count: 1 });
    expect(minutesParts(360)).toEqual({ unit: "hours", count: 6 });
    expect(minutesParts(45)).toEqual({ unit: "minutes", count: 45 });
  });

  it("resume a mensagem pelo evento e pela maior severidade", () => {
    const base = { item_count: 1, severity_counts: {}, items: [] } as Pick<OutboxEntry, "item_count" | "severity_counts" | "items">;
    expect(outboxSummaryParts({ ...base, event: "test" })).toEqual({ key: "test" });
    expect(outboxSummaryParts({ ...base, event: "finding_new", item_count: 500, severity_counts: { high: 499, critical: 1 } })).toEqual({
      key: "findingMany",
      count: 500,
      severity: "critical",
    });
    expect(outboxSummaryParts({ ...base, event: "backup_failed" })).toEqual({ key: "event", event: "backup_failed", count: 1 });
  });
});

const failedEntry: OutboxEntry = {
  id: 31,
  channel_id: 1,
  channel_name: "SOC",
  channel_kind: "webhook",
  event: "finding_new",
  summary: "3 achados novos (maior severidade: crítica)",
  item_count: 3,
  severity_counts: { critical: 1, high: 2 },
  items: [{ severity: "critical", title: "YARA-X: Webshell.PHP.Generic", finding_id: 7 }],
  state: "failed",
  attempts: 8,
  max_attempts: 8,
  last_error: "webhook respondeu HTTP 503: indisponível",
  created_at: "2026-10-22T09:00:00Z",
  updated_at: "2026-10-22T11:00:00Z",
};

describe("NotificationsPage", () => {
  beforeAll(() => {
    HTMLDialogElement.prototype.showModal ??= function (this: HTMLDialogElement) {
      this.setAttribute("open", "");
    };
    HTMLDialogElement.prototype.close ??= function (this: HTMLDialogElement) {
      this.removeAttribute("open");
      this.dispatchEvent(new Event("close"));
    };
  });
  afterEach(() => vi.restoreAllMocks());

  const adminSession: Schemas["Session"] = {
    authenticated: true,
    setup_required: false,
    secure_transport: true,
    stage: "full",
    user: { id: 1, username: "ana", display_name: "Ana", role: "admin", mfa_enabled: false },
  };

  function setup(session: Schemas["Session"]) {
    const calls: { method: string; path: string; body: unknown }[] = [];
    let channels: Channel[] = [webhook];
    vi.spyOn(globalThis, "fetch").mockImplementation(async (input) => {
      const req = input as Request;
      const path = new URL(req.url).pathname;
      const body = req.method === "GET" || req.method === "DELETE" ? undefined : await req.text().then((t) => (t ? JSON.parse(t) : undefined));
      calls.push({ method: req.method, path, body });
      const json = (data: unknown, status = 200) =>
        new Response(JSON.stringify(data), { status, headers: { "Content-Type": "application/json" } });
      if (path === "/api/v1/notifications/channels" && req.method === "GET") return json(channels);
      if (path === "/api/v1/notifications/channels" && req.method === "POST") {
        const created = { ...webhook, id: 5, name: (body as { name: string }).name };
        channels = [...channels, created];
        return json(created, 201);
      }
      if (path === "/api/v1/notifications/rules") return json([]);
      if (path === "/api/v1/notifications/outbox") return json({ entries: [failedEntry] });
      if (path === "/api/v1/notifications/channels/1/test") {
        return json({ ok: false, error: "webhook respondeu HTTP 401: assinatura recusada", entry: { ...failedEntry, id: 40, event: "test", item_count: 1 } });
      }
      if (path === "/api/v1/notifications/outbox/31/retry") return json({ ...failedEntry, state: "pending", attempts: 0 });
      return json({ error: "inesperado" }, 500);
    });
    const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
    qc.setQueryData(["session"], session);
    render(
      <QueryClientProvider client={qc}>
        <MemoryRouter initialEntries={["/notificacoes"]}>
          <NotificationsPage />
        </MemoryRouter>
      </QueryClientProvider>,
    );
    return calls;
  }

  it("mostra o canal sem o segredo, o resultado real do teste e reenvia da caixa de saída", async () => {
    const calls = setup(adminSession);
    const ui = userEvent.setup();
    expect(await screen.findByRole("heading", { name: "SOC" })).toBeInTheDocument();
    expect(screen.getByText("Configurado (nunca é exibido)")).toBeInTheDocument();
    expect(screen.getByText("Nenhuma regra de envio")).toBeInTheDocument();

    await ui.click(screen.getByRole("button", { name: "Enviar teste: SOC" }));
    expect(await screen.findByText(/A mensagem de teste não foi entregue: webhook respondeu HTTP 401/)).toBeInTheDocument();

    const table = await screen.findByRole("table", { name: /Mensagens da caixa de saída/ });
    expect(within(table).getByText("3 achados novos, o mais grave crítico")).toBeInTheDocument();
    expect(within(table).getByText("webhook respondeu HTTP 503: indisponível")).toBeInTheDocument();
    await ui.click(within(table).getByRole("button", { name: /Reenviar agora/ }));
    expect(await screen.findByText("Mensagem para SOC de volta à fila de envio.")).toBeInTheDocument();
    expect(calls.some((c) => c.method === "POST" && c.path === "/api/v1/notifications/outbox/31/retry")).toBe(true);
    expect(canRetry({ ...failedEntry, event: "test" })).toBe(false);
    const removed: OutboxEntry = { ...failedEntry };
    delete removed.channel_id;
    expect(canRetry(removed)).toBe(false);
  });

  it("cria webhook com segredo gerado no navegador", async () => {
    const calls = setup(adminSession);
    const ui = userEvent.setup();
    await screen.findByRole("heading", { name: "SOC" });
    await ui.click(screen.getAllByRole("button", { name: "Criar canal" })[0] as HTMLElement);
    await ui.click(screen.getByRole("radio", { name: /Webhook/ }));
    await ui.type(screen.getByLabelText("Nome"), "SIEM");
    await ui.type(screen.getByLabelText("Endereço"), "https://siem.example.com/hook");
    await ui.click(screen.getByRole("button", { name: "Salvar canal" }));
    expect(screen.getByText("Informe ou gere o segredo de assinatura.")).toBeInTheDocument();
    await ui.click(screen.getByRole("button", { name: "Gerar segredo" }));
    await ui.click(screen.getByRole("button", { name: "Salvar canal" }));
    const dialog = await screen.findByRole("dialog");
    await ui.click(within(dialog).getByRole("button", { name: "Salvar canal" }));
    await waitFor(() => expect(screen.getByText(/Canal SIEM criado/)).toBeInTheDocument());
    const post = calls.find((c) => c.method === "POST" && c.path === "/api/v1/notifications/channels");
    expect(post?.body).toMatchObject({
      name: "SIEM",
      kind: "webhook",
      webhook: { url: "https://siem.example.com/hook", allow_private_network: false },
    });
    expect((post?.body as { secret: string }).secret).toMatch(/^whsec_/);
  });

  it("recusa quem não é administrador sem chamar a API", async () => {
    const op: Schemas["Session"] = {
      ...adminSession,
      user: { id: 2, username: "op", display_name: "Operadora", role: "operator", mfa_enabled: true },
    };
    const calls = setup(op);
    expect(await screen.findByText(/Só administradores configuram notificações/)).toBeInTheDocument();
    expect(calls.filter((c) => c.path.startsWith("/api/v1/notifications/channels") || c.path.endsWith("/rules"))).toEqual([]);
  });
});

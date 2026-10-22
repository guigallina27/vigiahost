import AxeBuilder from "@axe-core/playwright";
import { expect, test, type Page } from "@playwright/test";

// WCAG 2.1 AA (escopo, seção 14.3) com axe-core, nos dois temas, mais checagens de teclado, reflow e tema.

const healthy = {
  status: "ok",
  version: "0.1.0",
  executor: {
    connected: true,
    version: "0.1.0",
    protocol: "1.0",
    system: {
      distro_id: "almalinux",
      distro_version: "9.8",
      distro_name: "AlmaLinux 9.8 (Olive Jaguar)",
      distro_like: ["rhel", "centos", "fedora"],
      kernel: "5.14.0-611.el9.x86_64",
      arch: "amd64",
      systemd: true,
      cgroup_v2: true,
      psi: false,
    },
  },
};

const degraded = {
  status: "degraded",
  version: "0.1.0",
  executor: { connected: false, error: "dial unix /run/vigiahost-executor/executor.sock: connect: no such file or directory" },
};

async function mockHealth(page: Page, mode: "ok" | "degraded" | "offline") {
  await page.route("**/api/v1/health", (route) => {
    if (mode === "offline") return route.abort("connectionrefused");
    return route.fulfill({ status: mode === "ok" ? 200 : 503, json: mode === "ok" ? healthy : degraded });
  });
}

async function expectNoViolations(page: Page) {
  const results = await new AxeBuilder({ page }).withTags(["wcag2a", "wcag2aa", "wcag21a", "wcag21aa"]).analyze();
  const summary = results.violations.map((v) => `${v.id}: ${v.nodes.map((n) => n.target.join(" ")).join(", ")}`);
  expect(summary).toEqual([]);
}

const pages: { name: string; path: string; mode: "ok" | "degraded" | "offline"; ready: string }[] = [
  { name: "visão geral", path: "/", mode: "ok", ready: "Capacidades do sistema" },
  { name: "visão geral sem executor", path: "/", mode: "degraded", ready: "não consegue falar com o executor" },
  { name: "visão geral sem serviço", path: "/", mode: "offline", ready: "Sem resposta do serviço do VigiaHost" },
  { name: "configurações", path: "/configuracoes", mode: "ok", ready: "Aparência" },
  { name: "catálogo", path: "/catalogo", mode: "ok", ready: "ConfirmDialog" },
  { name: "página planejada", path: "/achados", mode: "ok", ready: "Página planejada" },
  { name: "página inexistente", path: "/nao-existe", mode: "ok", ready: "Ir para a visão geral" },
];

for (const scheme of ["light", "dark"] as const) {
  test.describe(`tema ${scheme === "light" ? "claro" : "escuro"}`, () => {
    test.use({ colorScheme: scheme });
    for (const p of pages) {
      test(`${p.name} sem violações de acessibilidade`, async ({ page }) => {
        await mockHealth(page, p.mode);
        await page.goto(p.path);
        await expect(page.getByText(p.ready).first()).toBeVisible();
        await expectNoViolations(page);
      });
    }

    test("diálogo de confirmação aberto sem violações", async ({ page }) => {
      await mockHealth(page, "ok");
      await page.goto("/catalogo");
      await page.getByRole("button", { name: "Abrir confirmação com senha" }).click();
      await expect(page.getByRole("dialog", { name: "Criar exceção global?" })).toBeVisible();
      await expectNoViolations(page);
    });
  });
}

test("link para pular a navegação é o primeiro foco e leva ao conteúdo", async ({ page }) => {
  await mockHealth(page, "ok");
  await page.goto("/");
  await expect(page.getByText("Capacidades do sistema")).toBeVisible();
  await page.keyboard.press("Tab");
  const skip = page.getByRole("link", { name: "Pular para o conteúdo" });
  await expect(skip).toBeFocused();
  await expect(skip).toBeVisible();
  await page.keyboard.press("Enter");
  await expect(page.locator("main")).toBeFocused();
});

test("navegar move o foco para o título da nova página", async ({ page }) => {
  await mockHealth(page, "ok");
  await page.goto("/");
  await page.getByRole("link", { name: "Configurações" }).click();
  await expect(page.getByRole("heading", { level: 1, name: "Configurações" })).toBeFocused();
  await expect(page).toHaveTitle("Configurações · VigiaHost");
});

test("diálogo fecha com Esc e devolve o foco a quem o abriu", async ({ page }) => {
  await mockHealth(page, "ok");
  await page.goto("/catalogo");
  const opener = page.getByRole("button", { name: "Abrir confirmação simples" });
  await opener.click();
  const dialog = page.getByRole("dialog", { name: "Mover para quarentena?" });
  await expect(dialog).toBeVisible();
  await expect(dialog.getByRole("button", { name: "Cancelar" })).toBeFocused();
  await page.keyboard.press("Escape");
  await expect(dialog).toBeHidden();
  await expect(opener).toBeFocused();
});

test("escolha de tema vale na hora e persiste após recarregar", async ({ page }) => {
  await mockHealth(page, "ok");
  await page.emulateMedia({ colorScheme: "light" });
  await page.goto("/configuracoes");
  await page.getByLabel("Escuro").check();
  const scheme = () => page.evaluate(() => getComputedStyle(document.documentElement).colorScheme);
  await expect.poll(scheme).toBe("dark");
  await page.reload();
  await expect.poll(scheme).toBe("dark");
  await page.getByLabel(/Sistema/).check();
  await expect.poll(scheme).toBe("light dark");
  expect(await page.evaluate(() => localStorage.getItem("vigiahost.color-scheme"))).toBeNull();
});

for (const path of ["/", "/catalogo", "/configuracoes"]) {
  test(`sem rolagem horizontal em 320 px: ${path}`, async ({ page }) => {
    await mockHealth(page, "ok");
    await page.setViewportSize({ width: 320, height: 640 });
    await page.goto(path);
    await expect(page.locator("h1")).toBeVisible();
    const overflow = await page.evaluate(() => document.documentElement.scrollWidth - document.documentElement.clientWidth);
    expect(overflow).toBeLessThanOrEqual(0);
  });
}

test("menu móvel abre, mostra a navegação e fecha ao navegar", async ({ page }) => {
  await mockHealth(page, "ok");
  await page.setViewportSize({ width: 375, height: 700 });
  await page.goto("/");
  const toggle = page.getByRole("button", { name: "Abrir menu" });
  await expect(toggle).toHaveAttribute("aria-expanded", "false");
  await expect(page.getByRole("navigation", { name: "Principal" })).toBeHidden();
  await toggle.click();
  await expect(page.getByRole("button", { name: "Fechar menu" })).toHaveAttribute("aria-expanded", "true");
  await page.getByRole("link", { name: "Configurações" }).click();
  await expect(page.getByRole("navigation", { name: "Principal" })).toBeHidden();
});

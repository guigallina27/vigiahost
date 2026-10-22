import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeAll, describe, expect, it, vi } from "vitest";
import { ConfirmDialog } from "./ConfirmDialog";
import { CoverageBar } from "./CoverageBar";
import { HashText } from "./HashText";
import { PathText } from "./PathText";
import { SeverityBadge } from "./SeverityBadge";
import { StatusBadge } from "./StatusBadge";

const SHA = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08";

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

describe("badges", () => {
  it("severidade e estado sempre têm texto, não só cor", () => {
    render(
      <>
        <SeverityBadge severity="critical" />
        <StatusBadge kind="finding" state="false_positive" />
        <StatusBadge kind="run" state="recovered" />
      </>,
    );
    expect(screen.getByText("Crítico")).toBeInTheDocument();
    expect(screen.getByText("Falso positivo")).toBeInTheDocument();
    expect(screen.getByText("Interrompida e recuperada")).toBeInTheDocument();
  });
});

describe("PathText", () => {
  it("expõe o truque de inversão bidi e avisa o leitor de tela", () => {
    const { container } = render(<PathText path={"/var/www/foto‮gpj.php"} />);
    expect(container.querySelector("mark")).toHaveTextContent("\\u202E");
    expect(container.textContent).not.toContain("‮");
    expect(screen.getByText(/caracteres de controle/)).toBeInTheDocument();
  });

  it("não acrescenta aviso a caminho comum", () => {
    const { container } = render(<PathText path="/home/loja/public_html/index.php" />);
    expect(container.querySelector("mark")).toBeNull();
    expect(container.textContent).toBe("/home/loja/public_html/index.php");
  });
});

describe("HashText", () => {
  it("abrevia na tela, mantém o valor completo acessível e copia", async () => {
    const user = userEvent.setup();
    const writeText = vi.spyOn(navigator.clipboard, "writeText").mockResolvedValue();
    render(<HashText value={SHA} />);
    expect(screen.getByText("9f86d081884c…")).toHaveAttribute("aria-hidden", "true");
    expect(screen.getByText(`SHA-256 completo: ${SHA}`)).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "Copiar SHA-256" }));
    expect(writeText).toHaveBeenCalledWith(SHA);
    expect(await screen.findByRole("status")).toHaveTextContent("SHA-256 copiado");
  });
});

describe("CoverageBar", () => {
  it("mostra o número como informação principal", () => {
    render(<CoverageBar analyzed={124869} eligible={124870} skipped={1} />);
    expect(screen.getByText("99,9% de cobertura")).toBeInTheDocument();
    expect(screen.getByText(/124\.869 de 124\.870 arquivos analisados · 1 fora da análise/)).toBeInTheDocument();
  });
});

describe("ConfirmDialog", () => {
  it("em lote, só confirma com a quantidade digitada", async () => {
    const user = userEvent.setup();
    const onConfirm = vi.fn();
    const onClose = vi.fn();
    render(
      <ConfirmDialog
        open
        onClose={onClose}
        onConfirm={onConfirm}
        title="Encerrar processos?"
        object="12 processos"
        impact="Serviços podem cair."
        reversible={false}
        requireCount={12}
        confirmLabel="Encerrar 12 processos"
      />,
    );
    expect(screen.getByText("Não, não pode ser desfeito")).toBeInTheDocument();
    const input = screen.getByLabelText("Digite 12 para confirmar a ação em 12 itens");
    await user.type(input, "11");
    await user.click(screen.getByRole("button", { name: "Encerrar 12 processos" }));
    expect(onConfirm).not.toHaveBeenCalled();
    expect(screen.getByRole("alert")).toHaveTextContent("Digite exatamente 12.");

    await user.clear(input);
    await user.type(input, "12");
    await user.click(screen.getByRole("button", { name: "Encerrar 12 processos" }));
    expect(onConfirm).toHaveBeenCalledWith({});
    expect(onClose).toHaveBeenCalled();
  });

  it("com reautenticação, repassa a senha e mantém aberto se ela for recusada", async () => {
    const user = userEvent.setup();
    const onClose = vi.fn();
    render(
      <ConfirmDialog
        open
        onClose={onClose}
        onConfirm={({ password }) => {
          if (password !== "certa") throw new Error("Senha incorreta. Nada foi alterado.");
        }}
        title="Criar exceção?"
        object="hash"
        impact="Deixa de gerar achados."
        reversible
        requireReauth
        confirmLabel="Criar exceção"
      />,
    );
    await user.type(screen.getByLabelText("Confirme sua senha"), "errada");
    await user.click(screen.getByRole("button", { name: "Criar exceção" }));
    expect(screen.getByRole("alert")).toHaveTextContent("Senha incorreta");
    expect(onClose).not.toHaveBeenCalled();
  });
});

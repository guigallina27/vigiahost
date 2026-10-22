import { FolderSearch } from "lucide-react";
import { useState, type ReactNode } from "react";
import { Brand, BrandMark } from "../components/BrandMark";
import { Button } from "../components/Button";
import { ConfirmDialog } from "../components/ConfirmDialog";
import { CoverageBar } from "../components/CoverageBar";
import { EmptyState } from "../components/EmptyState";
import { EngineHealth } from "../components/EngineHealth";
import { FilterChip } from "../components/FilterChip";
import { HashText } from "../components/HashText";
import { PathText } from "../components/PathText";
import { TableScroll } from "../components/TableScroll";
import { SeverityBadge, severities } from "../components/SeverityBadge";
import { SeverityCounts } from "../components/SeverityCounts";
import { StatusBadge, findingStates, runStates } from "../components/StatusBadge";
import { Timestamp } from "../components/Timestamp";
import { PageHeader } from "../layout/PageHeader";

// Catálogo de componentes (escopo, seção 14.4): só no servidor de desenvolvimento, coberto pelo teste de
// acessibilidade (e2e/a11y.spec.ts) nos dois temas. Os textos de documentação ficam aqui, em pt-BR, por serem internos.

const NOW = new Date("2026-10-22T15:30:00Z");
const SHA = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08";

const tokens = [
  ["--vh-bg", "Fundo da página"],
  ["--vh-surface", "Superfície de painéis"],
  ["--vh-sunken", "Área rebaixada"],
  ["--vh-ink", "Texto"],
  ["--vh-ink-muted", "Texto secundário"],
  ["--vh-line-strong", "Borda de controle (≥ 3:1)"],
  ["--vh-accent", "Ação (azul-cobalto)"],
  ["--vh-accent-soft", "Fundo de destaque"],
  ["--vh-signal", "Farol (só marca e item ativo)"],
  ["--vh-focus", "Foco"],
  ["--vh-nav-bg", "Navegação"],
] as const;

function Section({ id, title, notes, children }: { id: string; title: string; notes: ReactNode; children: ReactNode }) {
  return (
    <section className="flex flex-col gap-4 border-b border-line py-8 first:pt-0">
      <div className="max-w-prose">
        <h2 id={id} className="m-0 text-xl font-bold">
          {title}
        </h2>
        <div className="mt-1 text-sm text-ink-muted">{notes}</div>
      </div>
      {children}
    </section>
  );
}

export default function CatalogPage() {
  const [dialog, setDialog] = useState<null | "simple" | "reauth" | "batch">(null);
  const [chip, setChip] = useState(true);
  return (
    <>
      <PageHeader title="Catálogo de componentes" subtitle="Kit visual vivo (docs/kit-visual.md): marca, tokens, variantes, estados e notas de acessibilidade" />

      <Section
        id="cat-marca"
        title="Marca"
        notes="Torre de vigia com o farol aceso. O âmbar do farol é exclusivo da marca e do item ativo da navegação; nunca vira cor de estado."
      >
        <div className="flex flex-wrap items-center gap-6">
          <span className="rounded-panel bg-nav p-4 text-nav-ink">
            <Brand size="lg" />
          </span>
          <span className="vh-night rounded-panel p-4 text-nav-ink">
            <Brand />
          </span>
          {/* Sobre superfície clara vai só o símbolo: o "Host" em âmbar não tem contraste fora do fundo noturno. */}
          <BrandMark className="size-16" />
        </div>
      </Section>

      <Section
        id="cat-tokens"
        title="Tokens de cor"
        notes="Definidos com light-dark() em src/styles/index.css e expostos ao Tailwind. Troque o tema em Configurações para conferir os dois."
      >
        <ul className="m-0 grid list-none gap-3 p-0 sm:grid-cols-2 lg:grid-cols-5">
          {tokens.map(([name, label]) => (
            <li key={name} className="flex items-center gap-3">
              <span aria-hidden="true" className="size-10 shrink-0 rounded-control border border-line-strong" style={{ background: `var(${name})` }} />
              <span className="min-w-0 text-sm">
                <span className="block font-semibold">{label}</span>
                <code className="text-ink-muted">{name}</code>
              </span>
            </li>
          ))}
        </ul>
      </Section>

      <Section id="cat-type" title="Tipografia" notes="Atkinson Hyperlegible Next e Mono (OFL), embarcadas: distinguem 0/O, 1/l/I e rn/m, o que importa em hashes e caminhos.">
        <p className="m-0 text-3xl font-bold">Visão geral do servidor</p>
        <p className="m-0">Texto corrido com leitura confortável em 16 px e altura de linha 1,5.</p>
        <p className="m-0 font-mono">0O 1lI rnm 5S 8B — /var/www/cliente/public_html/wp-content/uploads</p>
      </Section>

      <Section id="cat-buttons" title="Botões" notes="Verbo + objeto no rótulo. Alvo mínimo de 44 px. A variante de perigo só para ações destrutivas, sempre com ConfirmDialog.">
        <div className="flex flex-wrap gap-3">
          <Button variant="primary">Executar verificação</Button>
          <Button variant="secondary">Exportar achados</Button>
          <Button variant="danger">Mover para quarentena</Button>
          <Button variant="ghost">Ver detalhes</Button>
          <Button variant="primary" disabled>
            Executar verificação
          </Button>
        </div>
      </Section>

      <Section
        id="cat-severity"
        title="SeverityBadge"
        notes="Severidade é o que o achado é. Preenchido, com forma de ícone diferente por nível para não depender só da cor."
      >
        <div className="flex flex-wrap gap-2">
          {severities.map((s) => (
            <SeverityBadge key={s} severity={s} />
          ))}
        </div>
      </Section>

      <Section
        id="cat-status"
        title="StatusBadge"
        notes="Estado do achado e estado da execução são escalas diferentes da severidade; usam contorno para não serem lidos como ela."
      >
        <div className="flex flex-col gap-3">
          <div className="flex flex-wrap gap-2">
            {findingStates.map((s) => (
              <StatusBadge key={s} kind="finding" state={s} />
            ))}
          </div>
          <div className="flex flex-wrap gap-2">
            {runStates.map((s) => (
              <StatusBadge key={s} kind="run" state={s} />
            ))}
          </div>
        </div>
      </Section>

      <Section id="cat-engine" title="EngineHealth" notes="Saúde (Operacional, Degradado, Indisponível) e atualização (Em dia, Atrasada) em linhas separadas.">
        <div className="grid gap-4 md:grid-cols-3">
          <EngineHealth name="ClamAV" version="1.4.3" health="operational" update="current" lastUpdate={new Date("2026-10-22T09:12:00Z")} />
          <EngineHealth
            name="YARA-X"
            version="1.22.0"
            health="degraded"
            update="late"
            lastUpdate={new Date("2026-10-15T03:00:00Z")}
            detail="Regras da fonte YARA Forge sem atualização há 7 dias."
          />
          <EngineHealth name="Linux Malware Detect" health="unavailable" detail="maldet não encontrado em /usr/local/sbin." />
        </div>
      </Section>

      <Section
        id="cat-path"
        title="PathText"
        notes="Quebra em qualquer ponto (de preferência depois das barras) e mostra controles e marcas de direção como escapes destacados."
      >
        <ul className="m-0 flex list-none flex-col gap-2 p-0">
          <li>
            <PathText path="/home/cliente-com-nome-muito-longo/public_html/wp-content/plugins/plugin-com-nome-extenso/includes/vendor/biblioteca/arquivo-suspeito-com-nome-enorme.php" />
          </li>
          <li>
            <PathText path={"/var/www/html/uploads/foto\u202Egpj.php"} />
          </li>
          <li>
            <PathText path={"/tmp/x\n/var/www/limpo.php: OK"} />
          </li>
        </ul>
      </Section>

      <Section id="cat-hash" title="HashText" notes="Abreviado na tela; o valor completo fica para leitores de tela e no botão de copiar, que anuncia o resultado.">
        <HashText value={SHA} />
      </Section>

      <Section
        id="cat-table"
        title="TableScroll"
        notes="Toda tabela de dados vai dentro dele: rola no próprio contêiner (a página nunca rola na horizontal) e a região recebe foco e nome para ser rolada pelo teclado."
      >
        <TableScroll label="Exemplo de tabela larga">
          <table className="vh-table">
            <caption className="visually-hidden">Exemplo de tabela larga</caption>
            <thead>
              <tr>
                <th scope="col">Caminho</th>
                <th scope="col">Assinatura</th>
                <th scope="col">SHA-256</th>
              </tr>
            </thead>
            <tbody>
              <tr>
                <th scope="row" className="text-left font-normal">
                  <PathText path="/home/loja/public_html/wp-content/uploads/2026/10/cache.php" />
                </th>
                <td>vh_webshell_eval_post</td>
                <td>
                  <HashText value={SHA} />
                </td>
              </tr>
            </tbody>
          </table>
        </TableScroll>
      </Section>

      <Section
        id="cat-severity-counts"
        title="SeverityCounts"
        notes="Achados abertos por severidade: selo + número, nunca só cor. Em linha (tabelas) mostra só as severidades com achados; em grade (painéis) mostra todas e pode virar link para a lista filtrada."
      >
        <div className="flex flex-col gap-4">
          <SeverityCounts counts={{ critical: 2, high: 1, medium: 0, low: 4, info: 0, total: 7 }} />
          <SeverityCounts counts={{ critical: 0, high: 0, medium: 0, low: 0, info: 0, total: 0 }} />
          <SeverityCounts counts={{ critical: 2, high: 1, medium: 0, low: 4, info: 0, total: 7 }} layout="grid" hrefFor={(s) => `/catalogo#cat-severity-counts-${s}`} />
        </div>
      </Section>

      <Section
        id="cat-filter-chip"
        title="FilterChip"
        notes="Filtro aplicado que veio de outra tela (ex.: ?account=): mostra o valor e remove com um clique. Botão de 44 px com nome próprio; o valor quebra sem estourar."
      >
        <div className="flex flex-wrap gap-3">
          {chip ? (
            <FilterChip label="Conta" value="loja (1001)" onRemove={() => setChip(false)} removeLabel="Remover filtro de conta" />
          ) : (
            <Button onClick={() => setChip(true)}>Aplicar filtro de conta</Button>
          )}
          <FilterChip label="Execução" value="r-20261021-030000-abcd1234-muito-longa" onRemove={() => undefined} />
        </div>
      </Section>

      <Section id="cat-time" title="Timestamp" notes="Relativo + absoluto + fuso, sempre juntos. O fuso é o do servidor quando a API informar.">
        <div className="flex flex-wrap gap-8">
          <Timestamp date={new Date("2026-10-22T09:30:00Z")} now={NOW} timeZone="America/Sao_Paulo" />
          <Timestamp date={new Date("2026-10-20T22:05:00Z")} now={NOW} timeZone="America/Sao_Paulo" compact />
        </div>
      </Section>

      <Section id="cat-coverage" title="CoverageBar" notes="O número é a informação; a barra é ilustrativa e fica fora da árvore de acessibilidade. 99,99% nunca vira 100%.">
        <div className="grid gap-6 md:grid-cols-2 xl:grid-cols-4">
          <CoverageBar analyzed={124870} eligible={124870} />
          <CoverageBar analyzed={124869} eligible={124870} skipped={1} />
          <CoverageBar analyzed={10450} eligible={12000} skipped={1550} />
          <CoverageBar analyzed={0} eligible={0} />
        </div>
      </Section>

      <Section id="cat-empty" title="EmptyState" notes="Diz o que aconteceu e qual é o próximo passo.">
        <EmptyState
          headingLevel={3}
          icon={FolderSearch}
          title="Nenhum achado nesta conta"
          description="A última execução analisou 99,8% dos arquivos elegíveis e não encontrou indícios."
          action={<Button variant="primary">Verificar conta</Button>}
        />
      </Section>

      <Section
        id="cat-dialog"
        title="ConfirmDialog"
        notes="Mostra o objeto exato, o impacto e se é reversível. Reautenticação para ações sensíveis; em lote, digitar a quantidade."
      >
        <div className="flex flex-wrap gap-3">
          <Button onClick={() => setDialog("simple")}>Abrir confirmação simples</Button>
          <Button onClick={() => setDialog("reauth")}>Abrir confirmação com senha</Button>
          <Button onClick={() => setDialog("batch")}>Abrir confirmação em lote</Button>
        </div>
        <ConfirmDialog
          open={dialog === "simple"}
          onClose={() => setDialog(null)}
          onConfirm={() => undefined}
          title="Mover para quarentena?"
          object={<PathText path="/home/loja/public_html/wp-content/uploads/2026/10/cache.php" />}
          impact="O arquivo sai do lugar e o site pode deixar de carregar recursos que dependam dele."
          reversible
          confirmLabel="Mover para quarentena"
        />
        <ConfirmDialog
          open={dialog === "reauth"}
          onClose={() => setDialog(null)}
          onConfirm={({ password }) => {
            if (password !== "senha-de-exemplo") throw new Error("Senha incorreta. Nada foi alterado.");
          }}
          title="Criar exceção global?"
          object={<HashText value={SHA} />}
          impact="Este conteúdo deixa de gerar achados em todas as contas do servidor."
          reversible
          requireReauth
          confirmLabel="Criar exceção"
        />
        <ConfirmDialog
          open={dialog === "batch"}
          onClose={() => setDialog(null)}
          onConfirm={() => undefined}
          title="Encerrar processos?"
          object="12 processos do usuário loja com binário apagado do disco"
          impact="Os processos são encerrados; serviços legítimos do usuário podem cair até serem reiniciados."
          reversible={false}
          requireCount={12}
          confirmLabel="Encerrar 12 processos"
        />
      </Section>
    </>
  );
}

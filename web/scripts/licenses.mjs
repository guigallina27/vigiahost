// Confere as licenças das dependências de produção da interface (compatíveis com GPL-3.0, como o go-licenses faz
// no Go) e gera o arquivo de avisos de terceiros que vai embarcado junto com a interface (/licencas-terceiros.txt).
// Uso: node scripts/licenses.mjs [arquivo-de-saída]
import { execFileSync } from "node:child_process";
import { readdirSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";

const allowed = new Set(["MIT", "ISC", "BSD-2-Clause", "BSD-3-Clause", "Apache-2.0", "MPL-2.0", "0BSD", "CC0-1.0", "OFL-1.1"]);

// Chamado por um script do pnpm, npm_execpath aponta para o pnpm em uso; assim não depende de shell no Windows.
const args = ["licenses", "list", "--prod", "--json"];
const pnpm = process.env.npm_execpath;
const output = pnpm
  ? execFileSync(process.execPath, [pnpm, ...args], { encoding: "utf8" })
  : execFileSync("pnpm", args, { encoding: "utf8" });
const report = JSON.parse(output);

const problems = [];
const notices = [];
for (const [license, pkgs] of Object.entries(report)) {
  for (const pkg of pkgs) {
    if (!allowed.has(license)) problems.push(`${pkg.name}@${pkg.versions.join(",")}: ${license}`);
    const dir = pkg.paths[0];
    const file = dir && readdirSync(dir).find((f) => /^(licen[cs]e|copying)(\.(md|txt))?$/i.test(f));
    const text = file ? readFileSync(join(dir, file), "utf8").trim() : `Licença ${license} (arquivo de licença não incluído no pacote).`;
    notices.push({ name: pkg.name, version: pkg.versions.join(", "), license, text });
  }
}

if (problems.length) {
  console.error(`licenças não permitidas:\n  ${problems.join("\n  ")}`);
  process.exit(1);
}

const out = process.argv[2];
if (out) {
  notices.sort((a, b) => a.name.localeCompare(b.name));
  const body = notices
    .map((n) => `${"=".repeat(72)}\n${n.name} ${n.version} (${n.license})\n${"=".repeat(72)}\n\n${n.text}\n`)
    .join("\n");
  writeFileSync(out, `Avisos de terceiros da interface do VigiaHost\n\n${body}`);
}
console.log(`licenças conferidas: ${notices.length} pacotes de produção`);

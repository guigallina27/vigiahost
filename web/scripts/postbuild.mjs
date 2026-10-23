// Pós-build: gera versões .br e .gz dos arquivos de texto (o core as serve conforme o Accept-Encoding) e
// recria o README.txt versionado, que o Vite apaga ao limpar o diretório (o go:embed precisa de ao menos um arquivo).
// Usa só o zlib do Node, sem dependência extra. Arquivos pequenos ou que não encolhem ficam sem versão comprimida.
import { execFileSync } from "node:child_process";
import { readdir, readFile, writeFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import { join } from "node:path";
import { brotliCompressSync, constants, gzipSync } from "node:zlib";

const root = new URL("../../internal/webui/dist/", import.meta.url);
const compressible = /\.(js|css|html|svg|json|txt)$/;
const minSize = 1024;

await writeFile(
  new URL("README.txt", root),
  [
    "Destino do build da interface (make web). O conteúdo gerado é ignorado pelo git;",
    "este arquivo existe para o go:embed compilar mesmo sem a interface construída.",
    "",
  ].join("\n"),
);

// Avisos de terceiros (MIT, ISC, OFL...) embarcados com a interface; falha o build se aparecer licença não permitida.
execFileSync(process.execPath, [fileURLToPath(new URL("licenses.mjs", import.meta.url)), fileURLToPath(new URL("licencas-terceiros.txt", root))], {
  stdio: "inherit",
});

let count = 0;
for (const entry of await readdir(root, { recursive: true, withFileTypes: true })) {
  if (!entry.isFile() || !compressible.test(entry.name) || entry.name === "README.txt") continue;
  const path = join(entry.parentPath, entry.name);
  const data = await readFile(path);
  if (data.length < minSize) continue;

  const br = brotliCompressSync(data, {
    params: { [constants.BROTLI_PARAM_QUALITY]: 11, [constants.BROTLI_PARAM_SIZE_HINT]: data.length },
  });
  const gz = gzipSync(data, { level: 9 });
  if (br.length < data.length) await writeFile(`${path}.br`, br);
  if (gz.length < data.length) await writeFile(`${path}.gz`, gz);
  count++;
}
console.log(`compressão prévia: ${count} arquivos`);

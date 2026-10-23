# ADR-009: Repositórios assinados; TUF para tarball e central

**Status:** Aceito · **Data:** 22/10/2026 (aceito com o início da Fase 0)

**Contexto.** Atualizações precisam ser seguras e nativas para o administrador.

**Decisão.** Repositórios APT e DNF assinados como canal principal (estável e beta); script de bootstrap só adiciona o repositório; go-tuf v2 para autoatualização por tarball e para a central. **Em 22/10/2026 decidiu-se distribuir somente pelo GitHub por enquanto**: Releases públicos do repositório `guigallina27/vigiahost` (pré-lançamento até a 1.0) e, a partir do beta externo, GitHub Pages do mesmo repositório; domínio próprio antes do beta. Chave raiz GPG offline em dois tokens de hardware com dois responsáveis; subchave anual e chave do cosign no *environment* `release` do CI, com aprovação manual.

| Opção | Complexidade | Custo no servidor | Escala | Risco |
|---|---|---|---|---|
| **A. Repositórios assinados + TUF** | Média | Nenhum | Boa | Custódia de chaves |
| B. Script que baixa binários e se atualiza | Baixa | Nenhum | Média | Atualização fora do gerenciador; ataques de rollback |
| C. Somente tarball com TUF | Média | Nenhum | Boa | Experiência estranha ao administrador |

**Consequências.** Mais fácil: atualização com as ferramentas do sistema; começar sem domínio nem CDN. Mais difícil: manter repositórios e rotação de chaves; respeitar os limites do Pages (1 GB publicado, banda de referência de 100 GB/mês); migrar a origem dos servidores quando houver domínio (o pacote reescreve o arquivo de origem). Revisitar antes do beta externo (domínio e CDN) e se surgir distribuição sem APT/DNF.

**Ações.** [ ] Cerimônia da chave raiz (épico E0.7). [ ] Atestados de proveniência do GitHub e SBOM assinado com a chave própria do cosign. [ ] Testes de atualização, retorno e troca de origem em VM.

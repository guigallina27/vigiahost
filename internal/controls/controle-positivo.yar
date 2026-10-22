// Regra do controle positivo do VigiaHost (escopo, seção 7.4).
// O marcador é texto inerte, criado pelo projeto: não é malware nem trecho de malware.
// O autoteste da Fase 1A usa a mesma regra para provar que o YARA-X carregou regras e lê arquivos.

rule vigiahost_controle_positivo
{
    meta:
        description = "Marcador inerte de controle positivo do VigiaHost (não é malware)"
        author = "VigiaHost"
        license = "GPL-3.0-only"

    strings:
        $marcador = "VIGIAHOST-CONTROLE-POSITIVO-INERTE-7f3c9a1e"

    condition:
        $marcador
}

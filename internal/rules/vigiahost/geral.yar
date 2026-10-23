// Regras do VigiaHost independentes de linguagem: mineração, shells reversos em scripts e injeções em JavaScript.
// Escritas pelo projeto (GPL-3.0-only). Ver cabeçalho de php.yar sobre metadados e medição de falsos positivos.

rule vh_minerador_stratum
{
    meta:
        description = "Endereço de pool de mineração (protocolo stratum) em arquivo do servidor"
        severity = "high"
        category = "miner"
        author = "VigiaHost"
        license = "GPL-3.0-only"

    strings:
        $s1 = "stratum+tcp://" nocase
        $s2 = "stratum+ssl://" nocase
        $s3 = "stratum2+tcp://" nocase

    condition:
        any of them
}

rule vh_minerador_configuracao
{
    meta:
        description = "Configuração de minerador de criptomoeda (XMRig e derivados)"
        severity = "high"
        category = "miner"
        author = "VigiaHost"
        license = "GPL-3.0-only"

    strings:
        $donate = "\"donate-level\"" nocase
        $pools = "\"pools\"" nocase
        $algo = /"(rx\/0|randomx|cn\/r|cryptonight|kawpow|ghostrider)"/ nocase
        $cli1 = "--donate-level" nocase
        $cli2 = /--algo[= ](rx\/0|randomx|cryptonight)/ nocase

    condition:
        ($donate and ($pools or $algo)) or ($cli1 and $cli2)
}

rule vh_shell_reverso_script
{
    meta:
        description = "Script com shell reverso (bash /dev/tcp, Python ou Perl com socket ligado a /bin/sh)"
        severity = "critical"
        category = "malware"
        author = "VigiaHost"
        license = "GPL-3.0-only"

    strings:
        $bash = /(ba)?sh\s+-i\s+[>&0-9\s]{0,10}\/dev\/tcp\/[0-9A-Za-z.\-]+\/\d{1,5}/
        $bash2 = /\/dev\/tcp\/[0-9A-Za-z.\-]+\/\d{1,5}\s+0>&1/
        $py_sock = "socket.socket(" ascii
        $py_dup = "os.dup2(" ascii
        $py_sh = /["']\/bin\/(ba)?sh["']/
        $pl_sock = /socket\s*\(\s*S\s*,\s*PF_INET/
        $pl_exec = /exec\s*\(\s*["']\/bin\/(ba)?sh/

    condition:
        filesize < 1MB and (
            $bash or $bash2 or
            ($py_sock and $py_dup and $py_sh) or
            ($pl_sock and $pl_exec)
        )
}

rule vh_js_injecao_ofuscada
{
    meta:
        description = "JavaScript que executa código montado a partir de códigos de caractere ou texto codificado (injeção típica em sites)"
        severity = "medium"
        category = "malware"
        author = "VigiaHost"
        license = "GPL-3.0-only"

    strings:
        $a = /eval\s*\(\s*String\.fromCharCode\s*\(\s*\d{2,3}\s*,\s*\d{2,3}\s*,\s*\d{2,3}/
        $b = /document\.write\s*\(\s*unescape\s*\(\s*['"]%3[Cc]%73%63%72%69%70%74/
        $c = /eval\s*\(\s*atob\s*\(\s*['"][A-Za-z0-9+\/]{200,}/

    condition:
        filesize < 5MB and any of them
}

rule vh_elf_upx
{
    meta:
        description = "Executável ELF comprimido com UPX (comum em mineradores e bots; raro em software legítimo de servidor)"
        severity = "low"
        category = "suspicious"
        author = "VigiaHost"
        license = "GPL-3.0-only"

    strings:
        $upx1 = "UPX!"
        $upx2 = "$Info: This file is packed with the UPX"

    condition:
        uint32be(0) == 0x7f454c46 and any of them in (0..4096)
}

// Regras do VigiaHost para PHP em hospedagem. Escritas pelo projeto (GPL-3.0-only), a partir de técnicas
// públicas e bem documentadas de web shells e injeções; nenhuma é cópia de regra de terceiros.
// Metadados usados pelo produto: description, severity (critical, high, medium, low, info), category
// (webshell, malware, miner, suspicious), author, license. Cada regra é medida contra o corpus benigno
// (WordPress, WooCommerce, Joomla, Drupal, phpMyAdmin) e não pode gerar falso positivo nele.

private rule vh_php
{
    condition:
        uint32be(0) == 0x3c3f7068 or // "<?ph"
        for any i in (0..64) : (uint16be(i) == 0x3c3f) // "<?" logo no início
}

rule vh_php_eval_decodificado
{
    meta:
        description = "PHP que executa código decodificado em tempo de execução (eval/assert de base64, gzinflate, str_rot13)"
        severity = "high"
        category = "webshell"
        author = "VigiaHost"
        license = "GPL-3.0-only"

    strings:
        $re = /\b(eval|assert)\s*\(\s*(@\s*)?(base64_decode|gzinflate|gzuncompress|gzdecode|str_rot13|strrev|convert_uudecode|hex2bin)\s*\(/ nocase

    condition:
        vh_php and $re
}

rule vh_php_execucao_de_parametro
{
    meta:
        description = "PHP que executa diretamente um parâmetro da requisição (comando ou código vindo de GET, POST, COOKIE)"
        severity = "critical"
        category = "webshell"
        author = "VigiaHost"
        license = "GPL-3.0-only"

    strings:
        $exec = /\b(eval|assert|system|passthru|shell_exec|exec|popen|proc_open|pcntl_exec)\s*\(\s*(@\s*)?(stripslashes\s*\(\s*|base64_decode\s*\(\s*|urldecode\s*\(\s*|trim\s*\(\s*)?\$_(GET|POST|REQUEST|COOKIE|SERVER)\s*\[/ nocase
        // Crase executa comando no PHP; exige atribuição, echo ou print antes, para não casar com Markdown em comentários.
        $crase = /(=|\becho|\bprint|\breturn)\s*`\s*\$_(GET|POST|REQUEST|COOKIE)\s*\[[^\]]{1,40}\]\s*`/

    condition:
        vh_php and any of them
}

rule vh_php_funcao_variavel_de_parametro
{
    meta:
        description = "PHP que chama como função um valor vindo da requisição ($_GET['f']($_GET['x']))"
        severity = "critical"
        category = "webshell"
        author = "VigiaHost"
        license = "GPL-3.0-only"

    strings:
        $re = /\$_(GET|POST|REQUEST|COOKIE)\s*\[\s*['"]?[A-Za-z0-9_]{1,32}['"]?\s*\]\s*\(\s*\$_(GET|POST|REQUEST|COOKIE)/

    condition:
        vh_php and $re
}

rule vh_php_upload_direto
{
    meta:
        description = "Formulário de upload que grava o arquivo enviado sem nenhuma verificação (uploader de web shell)"
        severity = "medium"
        category = "webshell"
        author = "VigiaHost"
        license = "GPL-3.0-only"

    strings:
        $move = /move_uploaded_file\s*\(\s*\$_FILES\s*\[[^\]]{1,40}\]\s*\[\s*['"]tmp_name['"]\s*\]\s*,\s*\$_FILES\s*\[[^\]]{1,40}\]\s*\[\s*['"]name['"]\s*\]/ nocase
        $form = "multipart/form-data" nocase

    condition:
        vh_php and $move and $form and filesize < 50KB
}

rule vh_php_blob_codificado_com_eval
{
    meta:
        description = "PHP com bloco longo codificado em base64 e chamada de eval/assert/create_function"
        severity = "high"
        category = "webshell"
        author = "VigiaHost"
        license = "GPL-3.0-only"

    strings:
        $blob = /['"][A-Za-z0-9+\/]{3000,}={0,2}['"]/
        $eval = /\b(eval|assert|create_function)\s*\(/ nocase

    condition:
        vh_php and $blob and $eval
}

rule vh_php_ofuscacao_chr
{
    meta:
        description = "PHP ofuscado por concatenação de chr() em grande quantidade junto de eval/assert"
        severity = "high"
        category = "webshell"
        author = "VigiaHost"
        license = "GPL-3.0-only"

    strings:
        $chr = /chr\s*\(\s*\d{2,3}\s*\)\s*\./ nocase
        $eval = /\b(eval|assert)\s*\(/ nocase

    condition:
        vh_php and #chr > 40 and $eval
}

rule vh_php_shell_reverso
{
    meta:
        description = "PHP que abre conexão de saída e liga um shell a ela (shell reverso)"
        severity = "critical"
        category = "webshell"
        author = "VigiaHost"
        license = "GPL-3.0-only"

    strings:
        $sock = /\b(fsockopen|stream_socket_client|socket_create)\s*\(/ nocase
        $sh = /\/bin\/(ba)?sh\b/
        $proc = /\b(proc_open|shell_exec|exec|system|passthru|popen)\s*\(/ nocase

    condition:
        vh_php and $sock and $sh and $proc and filesize < 100KB
}

rule vh_php_wso_filesman
{
    meta:
        description = "Gerenciador de arquivos de web shell da família WSO (marcador FilesMan)"
        severity = "critical"
        category = "webshell"
        author = "VigiaHost"
        license = "GPL-3.0-only"

    strings:
        $a = "FilesMan" fullword
        $b = /\$default_action\s*=\s*['"]FilesMan['"]/

    condition:
        vh_php and any of them
}

rule vh_php_preg_replace_e
{
    meta:
        description = "preg_replace com modificador /e (execução de código), recurso removido no PHP 7 e usado por backdoors"
        severity = "high"
        category = "webshell"
        author = "VigiaHost"
        license = "GPL-3.0-only"

    strings:
        $re = /preg_replace\s*\(\s*['"]\/[^'"\n]{0,200}\/[imsxuADSUX]*e[imsxuADSUX]*['"]\s*,\s*['"]?[^,]{0,80}\$_(GET|POST|REQUEST|COOKIE)/

    condition:
        vh_php and $re
}

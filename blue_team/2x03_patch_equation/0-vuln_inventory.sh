#!/bin/bash

# Vulnerability inventory for Ubuntu/Debian systems.
#
# This script:
# 1. Enumerates installed packages.
# 2. Finds packages with available upgrades.
# 3. Identifies the source pocket.
# 4. Extracts CVEs from security changelogs.
# 5. Uses a local USN mapping as fallback.
# 6. Looks up CVSS scores and CISA KEV status.
# 7. Produces vulnerability_inventory.json.

set -euo pipefail

# ---------------------------------------------------------------------------
# ARQUIVOS E CONFIGURAÇÕES
# ---------------------------------------------------------------------------

# Diretório onde este script está localizado.
SCRIPT_DIR="$(
    cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &&
    pwd
)"

OUTPUT="${SCRIPT_DIR}/vulnerability_inventory.json"
CVE_FEED="${SCRIPT_DIR}/cve_feed.json"
CISA_KEV="${SCRIPT_DIR}/cisa_kev.json"

USN_FILE="/usr/share/ubuntu-advantage-tools/usns.json"
CHANGELOG_TIMEOUT="60"

# Arquivo temporário que guardará um objeto JSON por pacote.
TEMP_PACKAGES="$(mktemp)"

# Remove o arquivo temporário quando o script terminar.
cleanup() {
    rm -f "$TEMP_PACKAGES"
}

trap cleanup EXIT

# ---------------------------------------------------------------------------
# VERIFICAR DEPENDÊNCIAS
# ---------------------------------------------------------------------------

for command in \
    apt \
    apt-cache \
    apt-get \
    awk \
    dpkg \
    dpkg-query \
    grep \
    jq \
    sed \
    sort \
    timeout; do

    if ! command -v "$command" >/dev/null 2>&1; then
        echo "Error: required command not found: $command" >&2
        exit 1
    fi
done

# Valida o feed CVE quando estiver presente.
if [[ -f "$CVE_FEED" ]]; then
    if ! jq empty "$CVE_FEED" 2>/dev/null; then
        echo "Error: invalid JSON file: $CVE_FEED" >&2
        exit 1
    fi
else
    echo "Warning: cve_feed.json not found; CVSS values will be unknown." >&2
fi

# Valida o feed CISA KEV quando estiver presente.
if [[ -f "$CISA_KEV" ]]; then
    if ! jq empty "$CISA_KEV" 2>/dev/null; then
        echo "Error: invalid JSON file: $CISA_KEV" >&2
        exit 1
    fi
else
    echo "Warning: cisa_kev.json not found; KEV values will be false." >&2
fi

# ---------------------------------------------------------------------------
# FUNÇÃO: DESCOBRIR O SOURCE POCKET
#
# Argumentos:
#   $1 = nome do pacote
#   $2 = versão candidata
#
# Prioridade:
#   security > updates > backports
# ---------------------------------------------------------------------------

get_source_pocket() {
    local package="$1"
    local candidate="$2"

    apt-cache policy "$package" |
    awk -v candidate="$candidate" '
        # Início do bloco da versão candidata.
        $1 == candidate {
            found = 1
            next
        }

        # Linha contendo o repositório.
        found && $2 ~ /^https?:\/\// {
            # Exemplo:
            # jammy-security/main
            split($3, pocket, "/")

            if (pocket[1] ~ /-security$/) {
                security = pocket[1]
            } else if (pocket[1] ~ /-updates$/) {
                updates = pocket[1]
            } else if (pocket[1] ~ /-backports$/) {
                backports = pocket[1]
            }

            next
        }

        # Fim do bloco da versão candidata.
        #
        # Não usamos exit para evitar SIGPIPE com pipefail.
        found && $1 == "***" {
            found = 0
            next
        }

        END {
            if (security != "") {
                print security
            } else if (updates != "") {
                print updates
            } else if (backports != "") {
                print backports
            } else {
                print "unknown"
            }
        }
    '
}

# ---------------------------------------------------------------------------
# FUNÇÃO: EXTRAIR CVEs DO USN LOCAL
#
# Argumento:
#   $1 = nome do pacote
#
# O arquivo USN é opcional. Se não existir, a função não retorna nada.
# ---------------------------------------------------------------------------

get_usn_cves() {
    local package="$1"

    if [[ ! -f "$USN_FILE" ]]; then
        return 0
    fi

    jq -r \
        --arg package "$package" \
        '
            [
                .[]
                | select(.package == $package)
                | .cves[]?
            ]
            | unique
            | .[]
        ' \
        "$USN_FILE" \
        2>/dev/null ||
        true
}

# ---------------------------------------------------------------------------
# FUNÇÃO: EXTRAIR CVEs DO CHANGELOG
#
# Argumentos:
#   $1 = nome do pacote
#   $2 = versão instalada
#
# Captura somente entradas de versões superiores à instalada.
# Caso não encontre CVEs, utiliza o USN local como fallback.
# ---------------------------------------------------------------------------

get_package_cves() {
    local package="$1"
    local installed_version="$2"
    local changelog
    local header_regex
    local capture
    local line
    local changelog_version
    local cves

    header_regex='^[^[:space:]]+[[:space:]]+\(([^)]*)\)'
    capture="false"
    changelog=""
    cves=""

    # Tenta baixar o changelog com limite de tempo.
    changelog="$(
        timeout "$CHANGELOG_TIMEOUT" \
            apt-get changelog "$package" \
            2>/dev/null ||
        true
    )"

    if [[ -n "$changelog" ]]; then
        cves="$(
            {
                while IFS= read -r line; do
                    # Detecta um cabeçalho:
                    # pacote (versão) distribuição...
                    if [[ "$line" =~ $header_regex ]]; then
                        changelog_version="${BASH_REMATCH[1]}"

                        # Captura somente versões superiores à instalada.
                        if dpkg --compare-versions \
                            "$changelog_version" \
                            gt \
                            "$installed_version"; then
                            capture="true"
                        else
                            capture="false"
                        fi
                    fi

                    if [[ "$capture" == "true" ]]; then
                        printf '%s\n' "$line"
                    fi
                done <<< "$changelog"
            } |
            grep -Eo 'CVE-[0-9]{4}-[0-9]{4,}' |
            sort -u ||
            true
        )"
    fi

    # Método principal: changelog.
    if [[ -n "$cves" ]]; then
        printf '%s\n' "$cves"
        return 0
    fi

    # Fallback: mapeamento USN local.
    get_usn_cves "$package"
}

# ---------------------------------------------------------------------------
# FUNÇÃO: CONSULTAR O CVSS
#
# Argumento:
#   $1 = identificador CVE
#
# Retorna zero quando:
# - o feed não existe;
# - o CVE não está no feed;
# - o valor não é numérico.
# ---------------------------------------------------------------------------

get_cvss_for_cve() {
    local cve="$1"
    local cvss

    if [[ ! -f "$CVE_FEED" ]]; then
        echo "0"
        return 0
    fi

    cvss="$(
        jq -r \
            --arg cve "$cve" \
            '.cves[$cve].cvss // 0' \
            "$CVE_FEED" \
            2>/dev/null ||
        echo "0"
    )"

    if [[ ! "$cvss" =~ ^[0-9]+([.][0-9]+)?$ ]]; then
        cvss="0"
    fi

    echo "$cvss"
}

# ---------------------------------------------------------------------------
# FUNÇÃO: CALCULAR O MAIOR CVSS
#
# Argumento:
#   $1 = lista de CVEs, um por linha
# ---------------------------------------------------------------------------

get_max_cvss() {
    local cves="$1"
    local scores
    local cve
    local score

    scores=""

    while IFS= read -r cve; do
        if [[ -z "$cve" ]]; then
            continue
        fi

        score="$(get_cvss_for_cve "$cve")"
        scores+="${score}"$'\n'
    done <<< "$cves"

    if [[ -z "$scores" ]]; then
        echo "0"
        return 0
    fi

    printf '%s' "$scores" |
    awk 'NF > 0' |
    sort -nr |
    sed -n '1p'
}

# ---------------------------------------------------------------------------
# FUNÇÃO: CLASSIFICAR A SEVERIDADE
#
# CVSS:
#   9.0–10.0 = critical
#   7.0–8.9  = high
#   4.0–6.9  = medium
#   0.1–3.9  = low
#   0         = unknown
# ---------------------------------------------------------------------------

classify_severity() {
    local cvss="$1"

    awk -v score="$cvss" '
        BEGIN {
            if (score >= 9.0) {
                print "critical"
            } else if (score >= 7.0) {
                print "high"
            } else if (score >= 4.0) {
                print "medium"
            } else if (score > 0) {
                print "low"
            } else {
                print "unknown"
            }
        }
    '
}

# ---------------------------------------------------------------------------
# FUNÇÃO: VERIFICAR UM CVE NO CISA KEV
#
# Argumento:
#   $1 = identificador CVE
#
# Retorna true ou false.
# ---------------------------------------------------------------------------

check_cisa_kev_for_cve() {
    local cve="$1"
    local result

    if [[ ! -f "$CISA_KEV" ]]; then
        echo "false"
        return 0
    fi

    result="$(
        jq -r \
            --arg cve "$cve" \
            '.[$cve].active // false' \
            "$CISA_KEV" \
            2>/dev/null ||
        echo "false"
    )"

    if [[ "$result" == "true" ]]; then
        echo "true"
    else
        echo "false"
    fi
}

# ---------------------------------------------------------------------------
# FUNÇÃO: VERIFICAR TODOS OS CVEs NO CISA KEV
#
# Argumento:
#   $1 = lista de CVEs, um por linha
#
# Se qualquer CVE estiver no KEV, retorna true.
# ---------------------------------------------------------------------------

check_any_cve_in_kev() {
    local cves="$1"
    local cve
    local result

    while IFS= read -r cve; do
        if [[ -z "$cve" ]]; then
            continue
        fi

        result="$(check_cisa_kev_for_cve "$cve")"

        if [[ "$result" == "true" ]]; then
            echo "true"
            return 0
        fi
    done <<< "$cves"

    echo "false"
}

# ---------------------------------------------------------------------------
# ENUMERAR PACOTES INSTALADOS
#
# Formato obrigatório do exercício:
# pacote versão status
# ---------------------------------------------------------------------------

INSTALLED_PACKAGES="$(
    dpkg-query -W \
        -f='${binary:Package} ${Version} ${Status}\n' |
    awk '
        $3 == "install" &&
        $4 == "ok" &&
        $5 == "installed" {
            print $1, $2
        }
    '
)"

INSTALLED_COUNT="$(
    printf '%s\n' "$INSTALLED_PACKAGES" |
    awk '
        NF > 0 {
            count++
        }

        END {
            print count + 0
        }
    '
)"

# ---------------------------------------------------------------------------
# FUNÇÃO: OBTER A VERSÃO INSTALADA DO INVENTÁRIO
#
# Argumento:
#   $1 = nome do pacote
#
# Isso cruza apt list com o conjunto produzido por dpkg-query.
# ---------------------------------------------------------------------------

get_installed_version() {
    local package="$1"

    awk -v target="$package" '
        {
            package_name = $1

            # Remove um possível sufixo de arquitetura:
            # libssl3:amd64 -> libssl3
            sub(/:[^:]+$/, "", package_name)

            if (package_name == target) {
                print $2
                exit
            }
        }
    ' <<< "$INSTALLED_PACKAGES"
}

# ---------------------------------------------------------------------------
# ENUMERAR PACOTES ATUALIZÁVEIS
# ---------------------------------------------------------------------------

# `apt list --upgradable` exits 100 (not 0) when there is simply nothing to
# upgrade - the best possible state, not an error. Under `set -euo pipefail`
# that nonzero status would otherwise kill the whole script via pipefail on
# this very assignment, so it is explicitly tolerated with `|| true`.
UPGRADABLE_PACKAGES="$(
    { apt list --upgradable 2>/dev/null || true; } |
    sed '1d'
)"

UPGRADABLE_COUNT="$(
    printf '%s\n' "$UPGRADABLE_PACKAGES" |
    awk '
        NF > 0 {
            count++
        }

        END {
            print count + 0
        }
    '
)"

# ---------------------------------------------------------------------------
# PROCESSAR PACOTES ATUALIZÁVEIS
# ---------------------------------------------------------------------------

while IFS= read -r line; do
    if [[ -z "$line" ]]; then
        continue
    fi

    # Exemplo:
    # snapd/jammy-updates,jammy-security
    package_field="$(awk '{print $1}' <<< "$line")"

    # Nome do pacote.
    package="${package_field%%/*}"

    # Versão candidata.
    candidate_version="$(awk '{print $2}' <<< "$line")"

    # Cruza o pacote com a lista produzida por dpkg-query.
    installed_version="$(get_installed_version "$package")"

    # Se não estiver instalado, ignora.
    if [[ -z "$installed_version" ]]; then
        continue
    fi

    # Confirma o source pocket.
    source_pocket="$(
        get_source_pocket \
            "$package" \
            "$candidate_version"
    )"

    # Somente atualizações provenientes do security pocket.
    if [[ "$source_pocket" != *-security ]]; then
        continue
    fi

    # Extrai os CVEs.
    cves="$(
        get_package_cves \
            "$package" \
            "$installed_version"
    )"

    # Cria o array JSON de CVEs.
    cves_json="$(
        printf '%s\n' "$cves" |
        jq -R -s '
            split("\n")
            | map(select(length > 0))
            | unique
        '
    )"

    # Calcula o maior CVSS e a severidade.
    max_cvss="$(get_max_cvss "$cves")"
    severity="$(classify_severity "$max_cvss")"

    # Verifica o catálogo CISA KEV.
    in_cisa_kev="$(check_any_cve_in_kev "$cves")"

    # Cria um objeto JSON para o pacote.
    jq -n \
        --arg package "$package" \
        --arg installed "$installed_version" \
        --arg candidate "$candidate_version" \
        --arg pocket "$source_pocket" \
        --argjson cves "$cves_json" \
        --argjson max_cvss "$max_cvss" \
        --arg severity "$severity" \
        --argjson kev "$in_cisa_kev" \
        '{
            package: $package,
            installed_version: $installed,
            candidate_version: $candidate,
            source_pocket: $pocket,
            cves: $cves,
            max_cvss: $max_cvss,
            severity: $severity,
            in_cisa_kev: $kev
        }' >> "$TEMP_PACKAGES"

done < <(
    printf '%s\n' "$UPGRADABLE_PACKAGES"
)

# ---------------------------------------------------------------------------
# CRIAR O JSON FINAL
# ---------------------------------------------------------------------------

GENERATED_AT="$(date -u +"%Y-%m-%dT%H:%M:%SZ")"
HOSTNAME_VALUE="$(hostname)"

jq -s \
    --arg generated_at "$GENERATED_AT" \
    --arg hostname "$HOSTNAME_VALUE" \
    --argjson installed_count "$INSTALLED_COUNT" \
    --argjson upgradable_count "$UPGRADABLE_COUNT" \
    '{
        generated_at: $generated_at,
        hostname: $hostname,
        installed_package_count: $installed_count,
        upgradable_package_count: $upgradable_count,
        packages: .
    }' \
    "$TEMP_PACKAGES" > "$OUTPUT"

VULNERABLE_COUNT="$(
    jq '.packages | length' "$OUTPUT"
)"

# ---------------------------------------------------------------------------
# RESUMO
# ---------------------------------------------------------------------------

echo "Installed packages: $INSTALLED_COUNT"
echo "Upgradable packages: $UPGRADABLE_COUNT"
echo "Vulnerable packages recorded: $VULNERABLE_COUNT"
echo "Report saved to: $OUTPUT"

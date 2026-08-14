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
# FILES AND SETTINGS
# ---------------------------------------------------------------------------

# Directory where this script is located.
SCRIPT_DIR="$(
    cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &&
    pwd
)"

OUTPUT="${SCRIPT_DIR}/vulnerability_inventory.json"
CVE_FEED="${SCRIPT_DIR}/cve_feed.json"
CISA_KEV="${SCRIPT_DIR}/cisa_kev.json"

USN_FILE="/usr/share/ubuntu-advantage-tools/usns.json"
CHANGELOG_TIMEOUT="60"

# Temporary file that will store one JSON object per package.
TEMP_PACKAGES="$(mktemp)"

# Remove the temporary file when the script finishes.
cleanup() {
    rm -f "$TEMP_PACKAGES"
}

trap cleanup EXIT

# ---------------------------------------------------------------------------
# CHECK DEPENDENCIES
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

# Validate the CVE feed when it is present.
if [[ -f "$CVE_FEED" ]]; then
    if ! jq empty "$CVE_FEED" 2>/dev/null; then
        echo "Error: invalid JSON file: $CVE_FEED" >&2
        exit 1
    fi
else
    echo "Warning: cve_feed.json not found; CVSS values will be unknown." >&2
fi

# Validate the CISA KEV feed when it is present.
if [[ -f "$CISA_KEV" ]]; then
    if ! jq empty "$CISA_KEV" 2>/dev/null; then
        echo "Error: invalid JSON file: $CISA_KEV" >&2
        exit 1
    fi
else
    echo "Warning: cisa_kev.json not found; KEV values will be false." >&2
fi

# ---------------------------------------------------------------------------
# FUNCTION: DETERMINE THE SOURCE POCKET
#
# Arguments:
#   $1 = package name
#   $2 = candidate version
#
# Priority:
#   security > updates > backports
# ---------------------------------------------------------------------------

get_source_pocket() {
    local package="$1"
    local candidate="$2"

    apt-cache policy "$package" |
    awk -v candidate="$candidate" '
        # Start of the candidate version block.
        $1 == candidate {
            found = 1
            next
        }

        # Line containing the repository.
        found && $2 ~ /^https?:\/\// {
            # Example:
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

        # End of the candidate version block.
        #
        # Do not use exit, to avoid SIGPIPE with pipefail.
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
# FUNCTION: EXTRACT CVEs FROM THE LOCAL USN MAPPING
#
# Argument:
#   $1 = package name
#
# The USN file is optional. If it does not exist, the function returns nothing.
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
# FUNCTION: EXTRACT CVEs FROM THE CHANGELOG
#
# Arguments:
#   $1 = package name
#   $2 = installed version
#
# Capture only entries for versions newer than the installed version.
# If no CVEs are found, use the local USN mapping as a fallback.
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

    # Try to download the changelog with a time limit.
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
                    # Detect a header:
                    # package (version) distribution...
                    if [[ "$line" =~ $header_regex ]]; then
                        changelog_version="${BASH_REMATCH[1]}"

                        # Capture only versions newer than the installed version.
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

    # Primary method: changelog.
    if [[ -n "$cves" ]]; then
        printf '%s\n' "$cves"
        return 0
    fi

    # Fallback: local USN mapping.
    get_usn_cves "$package"
}

# ---------------------------------------------------------------------------
# FUNCTION: LOOK UP THE CVSS SCORE
#
# Argument:
#   $1 = CVE identifier
#
# Return zero when:
# - the feed does not exist;
# - the CVE is not in the feed;
# - the value is not numeric.
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
# FUNCTION: CALCULATE THE HIGHEST CVSS SCORE
#
# Argument:
#   $1 = list of CVEs, one per line
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
# FUNCTION: CLASSIFY SEVERITY
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
# FUNCTION: CHECK ONE CVE AGAINST CISA KEV
#
# Argument:
#   $1 = CVE identifier
#
# Return true or false.
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
# FUNCTION: CHECK ALL CVEs AGAINST CISA KEV
#
# Argument:
#   $1 = list of CVEs, one per line
#
# If any CVE is in KEV, return true.
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
# ENUMERATE INSTALLED PACKAGES
#
# Format required by the exercise:
# package version status
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
# FUNCTION: GET THE INSTALLED VERSION FROM THE INVENTORY
#
# Argument:
#   $1 = package name
#
# This cross-references apt list with the set produced by dpkg-query.
# ---------------------------------------------------------------------------

get_installed_version() {
    local package="$1"

    awk -v target="$package" '
        {
            package_name = $1

            # Remove a possible architecture suffix:
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
# ENUMERATE UPGRADABLE PACKAGES
# ---------------------------------------------------------------------------

UPGRADABLE_PACKAGES="$(
    apt list --upgradable 2>/dev/null |
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
# PROCESS UPGRADABLE PACKAGES
# ---------------------------------------------------------------------------

while IFS= read -r line; do
    if [[ -z "$line" ]]; then
        continue
    fi

    # Example:
    # snapd/jammy-updates,jammy-security
    package_field="$(awk '{print $1}' <<< "$line")"

    # Package name.
    package="${package_field%%/*}"

    # Candidate version.
    candidate_version="$(awk '{print $2}' <<< "$line")"

    # Cross-reference the package with the list produced by dpkg-query.
    installed_version="$(get_installed_version "$package")"

    # If it is not installed, skip it.
    if [[ -z "$installed_version" ]]; then
        continue
    fi

    # Confirm the source pocket.
    source_pocket="$(
        get_source_pocket \
            "$package" \
            "$candidate_version"
    )"

    # Only updates coming from the security pocket.
    if [[ "$source_pocket" != *-security ]]; then
        continue
    fi

    # Extract the CVEs.
    cves="$(
        get_package_cves \
            "$package" \
            "$installed_version"
    )"

    # Create the JSON array of CVEs.
    cves_json="$(
        printf '%s\n' "$cves" |
        jq -R -s '
            split("\n")
            | map(select(length > 0))
            | unique
        '
    )"

    # Calculate the highest CVSS score and severity.
    max_cvss="$(get_max_cvss "$cves")"
    severity="$(classify_severity "$max_cvss")"

    # Check the CISA KEV catalog.
    in_cisa_kev="$(check_any_cve_in_kev "$cves")"

    # Create one JSON object for the package.
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
# CREATE THE FINAL JSON FILE
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
# SUMMARY
# ---------------------------------------------------------------------------

echo "Installed packages: $INSTALLED_COUNT"
echo "Upgradable packages: $UPGRADABLE_COUNT"
echo "Vulnerable packages recorded: $VULNERABLE_COUNT"
echo "Report saved to: $OUTPUT"

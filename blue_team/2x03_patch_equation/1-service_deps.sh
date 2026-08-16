#!/bin/bash

set -uo pipefail

CRITICALITY_FILE="${1:-service_criticality.json}"
OUTPUT_FILE="${2:-service_dependency_map.json}"

required_commands=(systemctl dpkg ldd jq awk readlink mktemp)

for command_name in "${required_commands[@]}"; do
    if ! command -v "$command_name" >/dev/null 2>&1; then
        printf 'Error: required command not found: %s\n' "$command_name" >&2
        exit 1
    fi
done

if [[ ! -r "$CRITICALITY_FILE" ]]; then
    printf 'Error: criticality file is not readable: %s\n' "$CRITICALITY_FILE" >&2
    exit 1
fi

if ! jq empty "$CRITICALITY_FILE" >/dev/null 2>&1; then
    printf 'Error: invalid JSON in criticality file: %s\n' "$CRITICALITY_FILE" >&2
    exit 1
fi

TEMP_RESULTS=$(mktemp)
trap 'rm -f "$TEMP_RESULTS"' EXIT

# Return the Debian package that owns a path. Try the path as received first,
# then its canonical path to account for merged-/usr symbolic links.
package_for_path() {
    local file_path="$1"
    local canonical_path=""
    local package_name=""

    package_name=$(dpkg -S "$file_path" 2>/dev/null \
        | grep -v '^diversion by ' \
        | awk -F': ' 'NR == 1 { print $1 }')

    if [[ -z "$package_name" ]]; then
        canonical_path=$(readlink -f -- "$file_path" 2>/dev/null || true)
        if [[ -n "$canonical_path" && "$canonical_path" != "$file_path" ]]; then
            package_name=$(dpkg -S "$canonical_path" 2>/dev/null \
                | grep -v '^diversion by ' \
                | awk -F': ' 'NR == 1 { print $1 }')
        fi
    fi

    printf '%s' "$package_name"
}

# Accept either of these service_criticality.json layouts:
# {"ssh.service":"critical"}
# {"ssh.service":{"criticality":"critical"}}
# [{"service":"ssh.service","criticality":"critical"}]
criticality_for_service() {
    local service_name="$1"
    local criticality=""

    criticality=$(jq -r --arg service "$service_name" '
        if type == "object" then
            if (.[$service] | type) == "string" then
                .[$service]
            elif (.[$service] | type) == "object" then
                .[$service].criticality // "low"
            else
                "low"
            end
        elif type == "array" then
            ([.[] | select(.service == $service) | .criticality][0] // "low")
        else
            "low"
        end
    ' "$CRITICALITY_FILE" 2>/dev/null)

    case "$criticality" in
        critical|high|medium|low) printf '%s' "$criticality" ;;
        *) printf 'low' ;;
    esac
}

# Resolve the live executable first. Fall back to the first ExecStart path for
# active services without a readable/running MainPID (for example, oneshot units).
resolve_executable() {
    local service_name="$1"
    local main_pid="$2"
    local executable=""

    if [[ "$main_pid" =~ ^[0-9]+$ && "$main_pid" -gt 0 ]]; then
        executable=$(readlink -f -- "/proc/$main_pid/exe" 2>/dev/null || true)

        if [[ -z "$executable" && ${EUID:-$(id -u)} -ne 0 ]] \
            && command -v sudo >/dev/null 2>&1; then
            executable=$(sudo -n readlink -f -- "/proc/$main_pid/exe" 2>/dev/null || true)
        fi
    fi

    if [[ -z "$executable" ]]; then
        executable=$(systemctl show "$service_name" --property=ExecStart --value \
            | grep -o 'path=[^ ;}]*' \
            | head -n 1 \
            | cut -d= -f2- || true)
    fi

    [[ "$executable" == /* ]] || executable=""
    printf '%s' "$executable"
}

mapfile -t ACTIVE_SERVICES < <(
    systemctl list-units \
        --type=service \
        --state=active \
        --no-legend \
        --plain \
        | awk '{ print $1 }'
)

for service_name in "${ACTIVE_SERVICES[@]}"; do
    main_pid=$(systemctl show "$service_name" --property=MainPID --value 2>/dev/null || printf '0')
    exec_path=$(resolve_executable "$service_name" "$main_pid")
    owning_package=""
    criticality=$(criticality_for_service "$service_name")
    linked_packages_json='[]'
    restart_required=false

    if [[ -n "$exec_path" ]]; then
        owning_package=$(package_for_path "$exec_path")

        mapfile -t library_paths < <(
            ldd "$exec_path" 2>/dev/null \
                | awk '
                    $2 == "=>" && $3 ~ /^\// { print $3 }
                    $1 ~ /^\// { print $1 }
                ' \
                | sort -u
        )

        linked_packages=()
        for library_path in "${library_paths[@]}"; do
            library_package=$(package_for_path "$library_path")
            [[ -n "$library_package" ]] && linked_packages+=("$library_package")
        done

        if ((${#linked_packages[@]} > 0)); then
            linked_packages_json=$(printf '%s\n' "${linked_packages[@]}" \
                | sort -u \
                | jq -Rsc 'split("\n") | map(select(length > 0))')
        fi

        if [[ "$main_pid" =~ ^[0-9]+$ && "$main_pid" -gt 0 ]] \
            && [[ -n "$owning_package" || "$linked_packages_json" != '[]' ]]; then
            restart_required=true
        fi
    fi

    jq -n \
        --arg service "$service_name" \
        --arg exec_path "$exec_path" \
        --arg owning_package "$owning_package" \
        --argjson linked_packages "$linked_packages_json" \
        --arg criticality "$criticality" \
        --argjson restart_required_on_patch "$restart_required" \
        '{
            service: $service,
            exec_path: (if $exec_path == "" then null else $exec_path end),
            owning_package: (if $owning_package == "" then null else $owning_package end),
            linked_packages: $linked_packages,
            criticality: $criticality,
            restart_required_on_patch: $restart_required_on_patch
        }' >> "$TEMP_RESULTS"
done

jq -s '.' "$TEMP_RESULTS" > "$OUTPUT_FILE"

if ! jq empty "$OUTPUT_FILE" >/dev/null 2>&1; then
    printf 'Error: generated output is not valid JSON: %s\n' "$OUTPUT_FILE" >&2
    exit 1
fi

printf 'Created %s with %d service entries.\n' \
    "$OUTPUT_FILE" "${#ACTIVE_SERVICES[@]}"


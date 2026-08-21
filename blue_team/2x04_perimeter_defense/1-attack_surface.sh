#!/bin/bash

set -euo pipefail

# Configuration
BASELINE_FILE="network_baseline.json"
OUTPUT_FILE="attack_surface.json"
LAB_DIR="/home/analyst/MedDefense_Lab"

# Locate catalog and criticality files (lab dir first, then current dir)
CATALOG_FILE="${LAB_DIR}/service_catalog.json"
CRIT_FILE="${LAB_DIR}/service_criticality.json"
if [[ ! -f "$CATALOG_FILE" ]]; then
    CATALOG_FILE="service_catalog.json"
fi
if [[ ! -f "$CRIT_FILE" ]]; then
    CRIT_FILE="service_criticality.json"
fi

# Verify inputs exist
if [[ ! -f "$BASELINE_FILE" ]]; then
    echo "Error: $BASELINE_FILE not found. Run 0-network_baseline.sh first." >&2
    exit 1
fi
if [[ ! -f "$CATALOG_FILE" ]]; then
    echo "Error: service_catalog.json not found in $LAB_DIR or current directory." >&2
    exit 1
fi
if [[ ! -f "$CRIT_FILE" ]]; then
    echo "Error: service_criticality.json not found in $LAB_DIR or current directory." >&2
    exit 1
fi

# Timestamp and hostname from baseline
GENERATED_AT=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
HOSTNAME=$(jq -r '.hostname' "$BASELINE_FILE")

# Count listening sockets
SOCKET_COUNT=$(jq '.listening_sockets | length' "$BASELINE_FILE")

# Accumulator for enriched socket objects
SOCKETS_JSON="[]"

for ((i = 0; i < SOCKET_COUNT; i++)); do
    # Extract socket fields from baseline
    proto=$(jq -r ".listening_sockets[$i].proto // \"unknown\"" "$BASELINE_FILE")
    local_addr=$(jq -r ".listening_sockets[$i].bind_addr // \"\"" "$BASELINE_FILE")
    local_port=$(jq -r ".listening_sockets[$i].port // 0" "$BASELINE_FILE")
    pid=$(jq -r ".listening_sockets[$i].pid // empty" "$BASELINE_FILE")
    process=$(jq -r ".listening_sockets[$i].process // \"\"" "$BASELINE_FILE")

    # ---------------------------------------------------------------
    # Resolve owning binary path via /proc/PID/exe, with fallbacks
    # ---------------------------------------------------------------
    binary_path=""
    if [[ -n "$pid" && "$pid" != "null" ]]; then
        binary_path=$(readlink -f "/proc/${pid}/exe" 2>/dev/null || echo "")
    fi

    # Fallback 1: try pgrep to find PID by process name
    if [[ -z "$binary_path" && -n "$process" ]]; then
        fallback_pid=$(pgrep -x "$process" 2>/dev/null | head -1 || echo "")
        if [[ -n "$fallback_pid" ]]; then
            binary_path=$(readlink -f "/proc/${fallback_pid}/exe" 2>/dev/null || echo "")
        fi
    fi

    # Fallback 2: try pidof to find PID by process name
    if [[ -z "$binary_path" && -n "$process" ]]; then
        fallback_pid=$(pidof "$process" 2>/dev/null | awk '{print $1}' || echo "")
        if [[ -n "$fallback_pid" ]]; then
            binary_path=$(readlink -f "/proc/${fallback_pid}/exe" 2>/dev/null || echo "")
        fi
    fi

    # Fallback 3: try which to find binary path directly
    if [[ -z "$binary_path" && -n "$process" ]]; then
        binary_path=$(which "$process" 2>/dev/null || echo "")
    fi

    # Fallback 4: try common binary locations
    if [[ -z "$binary_path" && -n "$process" ]]; then
        for dir in /usr/sbin /usr/bin /sbin /bin /usr/local/sbin /usr/local/bin; do
            if [[ -x "${dir}/${process}" ]]; then
                binary_path="${dir}/${process}"
                break
            fi
        done
    fi

    # ---------------------------------------------------------------
    # Resolve owning package via dpkg -S
    # ---------------------------------------------------------------
    package=""
    if [[ -n "$binary_path" ]]; then
        package=$(dpkg -S "$binary_path" 2>/dev/null | head -1 | cut -d: -f1 || echo "")
    fi

    # Fallback: try dpkg -S with just the binary name
    if [[ -z "$package" && -n "$process" ]]; then
        package=$(dpkg -S "$(which "$process" 2>/dev/null || echo "$process")" 2>/dev/null | head -1 | cut -d: -f1 || echo "")
    fi

    # ---------------------------------------------------------------
    # Resolve systemd service unit via /proc/PID/cgroup, with fallbacks
    # ---------------------------------------------------------------
    service_unit=""
    if [[ -n "$pid" && "$pid" != "null" ]]; then
        cgroup_file="/proc/${pid}/cgroup"
        if [[ -f "$cgroup_file" ]]; then
            service_unit=$(grep -oP '[a-zA-Z0-9_.-]+\.service' "$cgroup_file" 2>/dev/null | head -1 || echo "")
        fi
    fi

    # Fallback 1: try pgrep to find PID and check its cgroup
    if [[ -z "$service_unit" && -n "$process" ]]; then
        fallback_pid=$(pgrep -x "$process" 2>/dev/null | head -1 || echo "")
        if [[ -n "$fallback_pid" ]]; then
            cgroup_file="/proc/${fallback_pid}/cgroup"
            if [[ -f "$cgroup_file" ]]; then
                service_unit=$(grep -oP '[a-zA-Z0-9_.-]+\.service' "$cgroup_file" 2>/dev/null | head -1 || echo "")
            fi
        fi
    fi

    # Fallback 2: try pidof to find PID and check its cgroup
    if [[ -z "$service_unit" && -n "$process" ]]; then
        fallback_pid=$(pidof "$process" 2>/dev/null | awk '{print $1}' || echo "")
        if [[ -n "$fallback_pid" ]]; then
            cgroup_file="/proc/${fallback_pid}/cgroup"
            if [[ -f "$cgroup_file" ]]; then
                service_unit=$(grep -oP '[a-zA-Z0-9_.-]+\.service' "$cgroup_file" 2>/dev/null | head -1 || echo "")
            fi
        fi
    fi

    # Fallback 3: try systemctl show to find matching service
    if [[ -z "$service_unit" && -n "$process" ]]; then
        service_unit=$(systemctl show -p Id --value "$(basename "$process").service" 2>/dev/null || echo "")
        if [[ -z "$service_unit" || "$service_unit" == "" ]]; then
            service_unit=$(systemctl list-units --type=service --no-pager 2>/dev/null | grep -iP "$process" | awk '{print $1}' | head -1 || echo "")
        fi
    fi

    # ---------------------------------------------------------------
    # Look up function from service_catalog.json (keyed by process name)
    # ---------------------------------------------------------------
    function_label=$(jq -r --arg proc "$process" '.[$proc] // "unknown"' "$CATALOG_FILE")

    # ---------------------------------------------------------------
    # Look up criticality from service_criticality.json (keyed by process name)
    # ---------------------------------------------------------------
    criticality=$(jq -r --arg proc "$process" '.[$proc] // "medium"' "$CRIT_FILE")

    # ---------------------------------------------------------------
    # Determine exposure flags
    # Rules:
    #   1. Bound to 0.0.0.0 on database or rpc
    #   2. Function is telnet, ftp, snmpv1, snmpv2c, rlogin, or nfs
    #   3. Web services exposed on wildcard (web, http, https)
    #   4. Note ssh exposure (ssh is critical but may need segmentation)
    # ---------------------------------------------------------------
    flags="[]"

    # Rule 1: bound to wildcard on database or rpc
    if [[ "$local_addr" == "0.0.0.0" || "$local_addr" == "::" || "$local_addr" == "*" ]]; then
        if [[ "$function_label" == "database" ]]; then
            flags=$(echo "$flags" | jq '. + ["bound_0.0.0.0", "database_exposed"]')
        elif [[ "$function_label" == "rpc" ]]; then
            flags=$(echo "$flags" | jq '. + ["bound_0.0.0.0", "rpc_exposed"]')
        elif [[ "$function_label" == "web" ]]; then
            flags=$(echo "$flags" | jq '. + ["bound_0.0.0.0", "web_exposed"]')
        elif [[ "$function_label" == "ssh" ]]; then
            flags=$(echo "$flags" | jq '. + ["bound_0.0.0.0", "ssh_exposed"]')
        fi
    fi

    # Rule 2: insecure protocols
    case "$function_label" in
        telnet)
            flags=$(echo "$flags" | jq '. + ["insecure_protocol_telnet"]')
            ;;
        ftp)
            flags=$(echo "$flags" | jq '. + ["insecure_protocol_ftp"]')
            ;;
        snmpv1)
            flags=$(echo "$flags" | jq '. + ["insecure_protocol_snmpv1"]')
            ;;
        snmpv2c)
            flags=$(echo "$flags" | jq '. + ["insecure_protocol_snmpv2c"]')
            ;;
        rlogin)
            flags=$(echo "$flags" | jq '. + ["insecure_protocol_rlogin"]')
            ;;
        nfs)
            flags=$(echo "$flags" | jq '. + ["insecure_protocol_nfs"]')
            ;;
    esac

    # Deduplicate flags
    flags=$(echo "$flags" | jq 'unique')

    # ---------------------------------------------------------------
    # Build socket JSON object
    # ---------------------------------------------------------------
    sock_obj=$(jq -n \
        --arg proto "$proto" \
        --argjson port "$local_port" \
        --arg bind_addr "$local_addr" \
        --arg process "$process" \
        --arg package "$package" \
        --arg function "$function_label" \
        --arg criticality "$criticality" \
        --arg service_unit "$service_unit" \
        --arg binary_path "$binary_path" \
        --argjson flags "$flags" \
        '{
            proto: $proto,
            port: $port,
            bind_addr: $bind_addr,
            process: $process,
            package: $package,
            function: $function,
            criticality: $criticality,
            exposure_flags: $flags,
            service_unit: $service_unit,
            binary_path: $binary_path
        }')

    SOCKETS_JSON=$(echo "$SOCKETS_JSON" | jq --argjson obj "$sock_obj" '. + [$obj]')
done

# ---------------------------------------------------------------
# Build summary block counting flagged sockets by severity
# ---------------------------------------------------------------
SUMMARY_JSON=$(echo "$SOCKETS_JSON" | jq '{
    total_sockets: length,
    flagged_sockets: [.[] | select(.exposure_flags | length > 0)] | length,
    unknown_functions: [.[] | select(.function == "unknown")] | length,
    by_severity: {
        critical: [.[] | select(.criticality == "critical" and (.exposure_flags | length > 0))] | length,
        high: [.[] | select(.criticality == "high" and (.exposure_flags | length > 0))] | length,
        medium: [.[] | select(.criticality == "medium" and (.exposure_flags | length > 0))] | length,
        low: [.[] | select(.criticality == "low" and (.exposure_flags | length > 0))] | length
    }
}')

# ---------------------------------------------------------------
# Construct final output JSON
# ---------------------------------------------------------------
FINAL_JSON=$(jq -n \
    --arg ga "$GENERATED_AT" \
    --arg hn "$HOSTNAME" \
    --argjson sockets "$SOCKETS_JSON" \
    --argjson summary "$SUMMARY_JSON" \
    '{
        generated_at: $ga,
        hostname: $hn,
        sockets: $sockets,
        summary: $summary
    }')

# Write to file
echo "$FINAL_JSON" > "$OUTPUT_FILE"

# Human-readable summary to stdout
echo "Attack Surface Report Generated"
echo "================================"
echo "Generated at:   $GENERATED_AT"
echo "Hostname:       $HOSTNAME"
echo "Total sockets:  $(echo "$SUMMARY_JSON" | jq -r '.total_sockets')"
echo "Flagged sockets: $(echo "$SUMMARY_JSON" | jq -r '.flagged_sockets')"
echo "Unknown funcs:  $(echo "$SUMMARY_JSON" | jq -r '.unknown_functions')"
echo ""
echo "Flagged by severity:"
echo "  Critical: $(echo "$SUMMARY_JSON" | jq -r '.by_severity.critical')"
echo "  High:     $(echo "$SUMMARY_JSON" | jq -r '.by_severity.high')"
echo "  Medium:   $(echo "$SUMMARY_JSON" | jq -r '.by_severity.medium')"
echo "  Low:      $(echo "$SUMMARY_JSON" | jq -r '.by_severity.low')"
echo ""
echo "Output: $OUTPUT_FILE"

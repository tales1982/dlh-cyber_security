#!/bin/bash
#
# 8-suricata_setup.sh
#
# MedDefense Health Systems - Perimeter and Network Defense (2x04)
#
# Suricata used exclusively in offline replay mode: point it at a PCAP with
# -r, read eve.json, done. No live interface, no daemon, no collector -
# deterministic and safe to run against production evidence after the
# fact. This script installs the engine, loads the ruleset and proves the
# whole chain works with one smoke-test PCAP before T9-T11 rely on it.
#
# Hint honored: do not start the suricata.service systemd unit. This
# project does not run the daemon - only -T (config test) and -r (offline
# PCAP replay) are ever invoked below, both one-shot processes.
#
# Usage: sudo ./8-suricata_setup.sh [output.json]

set -uo pipefail

OUT_JSON="${1:-setup_verification.json}"
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" >/dev/null 2>&1 && pwd)"
LAB_RULES_DIR="/home/analyst/MedDefense_Lab/suricata/rules"
SURICATA_RULES_DIR="/var/lib/suricata/rules"
YAML_FILE="${SCRIPT_DIR}/suricata.yaml"
SMOKE_PCAP="/home/analyst/MedDefense_Lab/PCAPs/smoke.pcap"

resolve_input() {
    local name="$1" candidate
    for candidate in "./${name}" "${SCRIPT_DIR}/${name}" "${SCRIPT_DIR}/../${name}"; do
        [ -f "$candidate" ] && { echo "$candidate"; return 0; }
    done
    echo "$name"
}
MEDDEFENSE_RULES="$(resolve_input meddefense.rules)"

# --- Install (idempotent) ---------------------------------------------------
INSTALLED_BEFORE="already_installed"
if ! command -v suricata >/dev/null 2>&1; then
    INSTALLED_BEFORE="not_installed"
    echo "[*] Installing suricata and jq..."
    DEBIAN_FRONTEND=noninteractive apt-get install -y suricata jq \
        -o Dpkg::Options::=--force-confdef -o Dpkg::Options::=--force-confold >/dev/null
else
    command -v jq >/dev/null 2>&1 || DEBIAN_FRONTEND=noninteractive apt-get install -y jq >/dev/null
fi
INSTALLED_VERSION="$(suricata --build-info 2>/dev/null | grep -oE '^This is Suricata version [0-9.]+' | awk '{print $NF}')"
echo "[*] suricata: $INSTALLED_BEFORE (version $INSTALLED_VERSION)"

# --- Copy the provided ruleset -----------------------------------------------
mkdir -p "$SURICATA_RULES_DIR"
LAB_FILES_LOADED=0
if [ -d "$LAB_RULES_DIR" ]; then
    cp -f "$LAB_RULES_DIR"/*.rules "$SURICATA_RULES_DIR/" 2>/dev/null
    LAB_FILES_LOADED="$(find "$LAB_RULES_DIR" -maxdepth 1 -name '*.rules' | wc -l)"
fi
# meddefense.rules (T10) is copied too when present, and always listed in
# suricata.yaml even before it exists so T10 does not need to touch this file.
[ -f "$MEDDEFENSE_RULES" ] && cp -f "$MEDDEFENSE_RULES" "$SURICATA_RULES_DIR/meddefense.rules"
[ -f "$SURICATA_RULES_DIR/meddefense.rules" ] || touch "$SURICATA_RULES_DIR/meddefense.rules"
echo "[*] Rules copied to $SURICATA_RULES_DIR: $LAB_FILES_LOADED file(s) from the lab feed + meddefense.rules"

# Single source of truth for rule-files: whatever ended up on disk in
# SURICATA_RULES_DIR, listed once. meddefense.rules is already there from
# the copy above - listing it a second time by hand here caused Suricata to
# load it twice and reject every one of its sids as a duplicate signature.
RULE_FILES_JSON="$(find "$SURICATA_RULES_DIR" -maxdepth 1 -name '*.rules' -printf '%f\n' | sort | jq -R . | jq -s .)"
RULE_COUNT="$(grep -shc '^alert\|^drop\|^pass\|^reject' "$SURICATA_RULES_DIR"/*.rules 2>/dev/null | awk -F: '{s+=$NF} END{print s+0}')"

# --- Render suricata.yaml -----------------------------------------------
# eve-log types: alert, http, dns, tls and "files" (the module name is
# "files" - it is what produces the fileinfo-typed records in eve.json;
# `types: - fileinfo` does not exist as a module name and suricata -T
# rejects it with "No output module named eve-log.fileinfo").
{
    echo "%YAML 1.1"
    echo "---"
    echo "vars:"
    echo "  address-groups:"
    echo "    HOME_NET: \"[10.10.0.0/16]\""
    echo "    EXTERNAL_NET: \"!\$HOME_NET\""
    echo ""
    echo "default-rule-path: $SURICATA_RULES_DIR"
    echo "rule-files:"
    jq -r '.[] | "  - \(.)"' <<<"$RULE_FILES_JSON"
    echo ""
    echo "default-log-dir: /var/log/suricata/"
    echo ""
    echo "outputs:"
    echo "  - eve-log:"
    echo "      enabled: yes"
    echo "      filetype: regular"
    echo "      filename: eve.json"
    echo "      types:"
    echo "        - alert"
    echo "        - http"
    echo "        - dns"
    echo "        - tls"
    echo "        - files"
    echo ""
    echo "pcap-file:"
    echo "  enabled: yes"
    echo ""
    echo "af-packet:"
    echo "  - interface: default"
    echo ""
    echo "app-layer:"
    echo "  protocols:"
    echo "    tls:"
    echo "      enabled: yes"
    echo "    http:"
    echo "      enabled: yes"
    echo "    dns:"
    echo "      enabled: yes"
    echo ""
    echo "classification-file: /etc/suricata/classification.config"
    echo "reference-config-file: /etc/suricata/reference.config"
} > "$YAML_FILE"
echo "[*] Rendered $YAML_FILE"

# --- Config test -----------------------------------------------------
mkdir -p /var/log/suricata
suricata -T -c "$YAML_FILE" -v >/tmp/suricata_test_out.$$ 2>&1
CONFIG_TEST_EXIT=$?
echo "[*] Config test (suricata -T): exit $CONFIG_TEST_EXIT"
[ "$CONFIG_TEST_EXIT" -ne 0 ] && tail -20 /tmp/suricata_test_out.$$ >&2
rm -f /tmp/suricata_test_out.$$

# --- Smoke test: replay one PCAP end to end -----------------------------
SMOKE_ALERTS=0
if [ "$CONFIG_TEST_EXIT" -eq 0 ] && [ -f "$SMOKE_PCAP" ]; then
    SMOKE_DIR="/tmp/suricata-smoke"
    rm -rf "$SMOKE_DIR"; mkdir -p "$SMOKE_DIR"
    suricata -c "$YAML_FILE" -r "$SMOKE_PCAP" -l "$SMOKE_DIR" >/dev/null 2>&1
    if [ -f "$SMOKE_DIR/eve.json" ]; then
        SMOKE_ALERTS="$(jq -sc '[.[] | select(.event_type=="alert")] | length' "$SMOKE_DIR/eve.json" 2>/dev/null)"
    fi
fi
echo "[*] Smoke test ($SMOKE_PCAP): $SMOKE_ALERTS alert(s)"

jq -n \
    --arg installed_version "$INSTALLED_VERSION" --argjson rule_files "$RULE_FILES_JSON" \
    --argjson rule_count "$RULE_COUNT" --argjson config_test_exit "$CONFIG_TEST_EXIT" \
    --arg smoke_pcap "$SMOKE_PCAP" --argjson smoke_alerts "${SMOKE_ALERTS:-0}" \
    '{installed_version: $installed_version, rule_files_loaded: $rule_files, rule_count: $rule_count,
      config_test_exit: $config_test_exit, smoke_pcap: $smoke_pcap, smoke_alerts: $smoke_alerts}' > "$OUT_JSON"

echo "Report saved to: $OUT_JSON"
[ "$CONFIG_TEST_EXIT" -eq 0 ] && [ "${SMOKE_ALERTS:-0}" -gt 0 ]

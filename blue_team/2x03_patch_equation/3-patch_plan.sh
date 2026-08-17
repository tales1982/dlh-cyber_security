#!/bin/bash
#
# 3-patch_plan.sh
#
# MedDefense Health Systems - The Patch Equation (2x03)
#
# The join between "what is vulnerable" (T0) and "what depends on what" (T1),
# filtered through prioritization criteria, into the execution order T4
# consumes. Pure computation - no system state is read or changed here, only
# the two JSON artifacts already on disk.
#
# Usage: ./3-patch_plan.sh [vulnerability_inventory.json] [service_dependency_map.json] [output.json]

set -uo pipefail

VULN_JSON="${1:-vulnerability_inventory.json}"
DEPMAP_JSON="${2:-service_dependency_map.json}"
OUT_JSON="${3:-patch_plan.json}"
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" >/dev/null 2>&1 && pwd)"

resolve_input() {
    local name="$1" candidate
    for candidate in "./${name}" "${SCRIPT_DIR}/${name}" "${SCRIPT_DIR}/../${name}"; do
        if [ -f "$candidate" ]; then
            echo "$candidate"
            return 0
        fi
    done
    echo "$name"
}

[ -f "$VULN_JSON" ] || VULN_JSON="$(resolve_input vulnerability_inventory.json)"
[ -f "$DEPMAP_JSON" ] || DEPMAP_JSON="$(resolve_input service_dependency_map.json)"

if [ ! -r "$VULN_JSON" ]; then
    echo "error: cannot read $VULN_JSON (run 0-vuln_inventory.sh first)" >&2
    exit 1
fi
if [ ! -r "$DEPMAP_JSON" ]; then
    echo "error: cannot read $DEPMAP_JSON (run 1-service_deps.sh first)" >&2
    exit 1
fi

# --- Weights (tune here, nowhere else) --------------------------------------
# score = cvss_weight * max_cvss
#       + kev_weight * in_cisa_kev
#       + criticality_weight * max(criticality_rank of affected services)
#       + exposure_weight * exposure_rank
#
# criticality_rank: critical=3 high=2 medium=1 low=0 (none affected)=0
# exposure_rank: min(distinct affected services, 5) / 5 - a package that
# disturbs many services at once has a wider blast radius than one that
# disturbs a single, isolated one, even at equal CVSS.
cvss_weight=0.6
kev_weight=2.0
criticality_weight=0.8
exposure_weight=1.0

TS="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

jq -n \
    --slurpfile vuln "$VULN_JSON" \
    --slurpfile deps "$DEPMAP_JSON" \
    --arg ts "$TS" \
    --argjson cvss_w "$cvss_weight" \
    --argjson kev_w "$kev_weight" \
    --argjson crit_w "$criticality_weight" \
    --argjson exp_w "$exposure_weight" \
    '
    def kernel_prefixes: ["linux-image", "linux-modules", "linux-generic", "systemd", "linux-headers"];
    def is_kernel_pkg($pkg):
        any(kernel_prefixes[]; . as $p | $pkg | startswith($p));
    def services_for($pkg; $services):
        if is_kernel_pkg($pkg) then
            [{service: "(kernel-wide)", criticality: "critical"}]
        else
            [$services[] | select((.owning_package == $pkg) or (.linked_packages // [] | index($pkg) != null))
             | {service: .service, criticality: .criticality}]
        end;

    ($vuln[0].packages // []) as $packages
    | ($deps[0] // []) as $services
    | {critical: 3, high: 2, medium: 1, low: 0} as $crit_rank

    | [ $packages[] | . as $p
      | services_for($p.package; $services) as $affected
      | ([$affected[].criticality] | map($crit_rank[.] // 0) | (max // 0)) as $crit_score
      | (($affected | length) as $n | ([$n, 5] | min) / 5) as $exposure_rank
      | (($cvss_w * $p.max_cvss)
         + ($kev_w * (if $p.in_cisa_kev then 1 else 0 end))
         + ($crit_w * $crit_score)
         + ($exp_w * $exposure_rank)) as $score_raw
      | ($score_raw * 100 | round / 100) as $score
      | {
          package: $p.package,
          score: $score,
          bucket: (if $score >= 7 then "emergency" elif $score >= 4 then "urgent" else "scheduled" end),
          affected_services: [$affected[].service],
          requires_restart: (($affected | length) > 0 and (is_kernel_pkg($p.package) | not)),
          requires_reboot: is_kernel_pkg($p.package),
          rollback_target_version: $p.installed_version
        }
    ]
    | sort_by(-.score, .package)
    | to_entries | map(.value + {rank: (.key + 1)}) as $plan
    | {
        generated_at: $ts,
        weights: {cvss: $cvss_w, kev: $kev_w, criticality: $crit_w, exposure: $exp_w},
        plan: $plan,
        summary: {
          emergency: ([$plan[] | select(.bucket == "emergency")] | length),
          urgent: ([$plan[] | select(.bucket == "urgent")] | length),
          scheduled: ([$plan[] | select(.bucket == "scheduled")] | length),
          reboot_required: (([$plan[] | select(.requires_reboot)] | length) > 0)
        }
      }
    ' > "$OUT_JSON"

# --- Human-readable summary --------------------------------------------------
emergency="$(jq '.summary.emergency' "$OUT_JSON")"
urgent="$(jq '.summary.urgent' "$OUT_JSON")"
scheduled="$(jq '.summary.scheduled' "$OUT_JSON")"
reboot="$(jq -r 'if .summary.reboot_required then "yes" else "no" end' "$OUT_JSON")"
echo "Emergency: $emergency   Urgent: $urgent   Scheduled: $scheduled"
echo "Reboot required by plan: $reboot"
echo "Report saved to: $OUT_JSON"

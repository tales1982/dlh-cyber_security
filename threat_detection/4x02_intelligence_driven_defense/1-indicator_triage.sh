#!/bin/bash
set -euo pipefail

# Triages the 50 unique indicators produced by 0-intel_intake.md (this
# module's own exact-literal-value dedup of the 89 raw indicators; see that
# file's Section 2.2 for why this figure differs from the lab's 64 reference).
# Classification and justification for each indicator were derived by reading
# every source's own confidence score, acme_note field, and stated evidence
# basis (HC3_Advisory / commercial_feed_extract.json / researcher_blog /
# meddefense_4x00_findings) -- not computed mechanically. Where the commercial
# feed itself says "DO NOT BLOCK" or "LIKELY NOISE", that source judgment is
# preserved and cited directly rather than re-derived.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
INTAKE_FILE="$SCRIPT_DIR/0-intel_intake.md"

if [ ! -f "$INTAKE_FILE" ]; then
	echo "0-intel_intake.md not found -- run Task 0 first." >&2
	exit 1
fi

# Data format: type|value|sources|category|justification|confidence|uncertain
# "uncertain" is Y or N (flag if the category assignment is not straightforward)
DATA='
domain|meddefense-portal.com|HC3,Commercial,Researcher,MedDefense|ACTIONABLE|Primary Stage 1 phishing domain; direct victim telemetry (MedDefense click event) plus confirmed kit access (researcher); corroborated by 4 independent sources|HIGH|N
domain|medequip-supplies.net|HC3,Commercial,Researcher,MedDefense|ACTIONABLE|Stage 1 phishing domain confirmed by kit fingerprint and victim telemetry; corroborated by 4 sources|HIGH|N
domain|meddefense-benefits.org|HC3,Commercial,MedDefense|ACTIONABLE|Stage 1 phishing domain with direct victim-org telemetry (MedDefense) and HC3 HIGH rating|HIGH|N
domain|outlook-protection.com|HC3,Commercial,Researcher|ACTIONABLE|Confirmed kit domain and exfil-mail relay per researcher config.php; passes SPF/DKIM/DMARC (4x00 F3) so email-auth-based detection will miss it, making explicit domain blocking necessary|HIGH|N
domain|healthbane-c2.net|HC3,Commercial,Researcher|ACTIONABLE|Confirmed C2 domain via direct kit config.php reference (EXFIL_ENDPOINT, OPS_CONTACT); bridges Stage1 and Stage2/3 per researcher|HIGH|N
domain|data-sync.healthbane-c2.net|HC3,Commercial|ACTIONABLE|Stage 3 DNS-tunnel exfil subdomain; HC3 direct packet-capture confirmation from 2 compromised orgs|HIGH|N
domain|update-healthbane.net|HC3,Commercial|ACTIONABLE|Stage 2 second-stage download domain; HC3 MEDIUM + Acme 80/100, specific attacker infra not shared hosting|MEDIUM|N
domain|portal-secure-meddefense.com|HC3,Researcher|CONTEXTUAL|Researcher confirms same kit staged but NOT YET LIVE; no observed phishing activity yet. Valuable for proactive monitoring/early-warning, not yet a block-justifying active threat|MEDIUM|Y
domain|rx-benefits-portal.com|Commercial|CONTEXTUAL|Acme confidence 62; explicitly predates the confirmed HEALTHBANE window by 16 days -- "possibly earlier campaign by same operator" per Acme'"'"'s own note, not confirmed same campaign|MEDIUM|Y
domain|healthcare-login.com|Commercial|CONTEXTUAL|Acme confidence 55; Acme'"'"'s own note says sinkholed 2026-04-18, "actionable for historical correlation only" -- source itself says not to block|LOW|N
domain|verify-health-portal.net|Commercial|CONTEXTUAL|Acme confidence 70; Acme'"'"'s own note: "No active phishing observed... registered during campaign window with matching naming pattern" -- naming-pattern match only, no observed malicious use|MEDIUM|Y
domain|secure-insurance-login.com|Commercial|NOISE|Acme confidence 48; Acme'"'"'s own note: "Clustered by ML classifier on name similarity; human review not performed" -- unreviewed automated clustering only|LOW|N
domain|claims-verify-portal.net|Commercial|NOISE|Acme confidence 42; Acme'"'"'s own note: "Clustered on keyword match only. LOW evidence of attacker association"|LOW|N
ip|91.234.99.107|HC3,Commercial,Researcher,MedDefense|ACTIONABLE|Confirmed Stage 1 kit IP (researcher direct access) plus victim telemetry; 4-source corroboration|HIGH|N
ip|185.176.43.22|HC3,Commercial,MedDefense|ACTIONABLE|Stage 1 phishing-LP IP with direct victim telemetry from MedDefense|HIGH|N
ip|164.90.218.73|HC3,Commercial,MedDefense|ACTIONABLE|Stage 1 phishing-LP IP with direct victim telemetry from MedDefense|HIGH|N
ip|51.38.42.191|HC3,Commercial,Researcher|ACTIONABLE|C2/DNS-tunnel IP confirmed via researcher config.php reference and HC3 packet capture|HIGH|N
ip|51.38.42.17|HC3,Commercial|ACTIONABLE|Stage 1 phishing-LP IP, HC3 HIGH, Acme 88/100|HIGH|N
ip|45.77.218.9|HC3,Commercial|ACTIONABLE|Stage 2 second-stage C2 IP; HC3 MEDIUM + Acme 72/100, dedicated infra not shared hosting|MEDIUM|N
ip|167.71.222.30|Commercial,Researcher|CONTEXTUAL|Researcher explicitly rates this LOW confidence ("operator-overlap hypothesis" via VPS image reuse only); Acme confidence only 38, clustered_by_similarity. Worth hunting, not blocking|LOW|Y
ip|23.94.138.222|Commercial|CONTEXTUAL|Acme confidence 55, tagged bulletproof-hosting (a genuine malicious-infra signal) but clustered_by_similarity only, no direct campaign evidence|MEDIUM|Y
ip|159.89.112.45|Commercial|NOISE|Acme confidence 32; Acme'"'"'s own note: "DigitalOcean shared infrastructure...hosts 200+ unrelated websites. BLOCKING would create broad false positive"|LOW|N
ip|104.168.34.58|Commercial|NOISE|Acme confidence 40, tagged healthcare-kw/clustered_by_similarity only -- keyword-match clustering, no infrastructure or telemetry evidence|LOW|N
ip|192.99.207.114|Commercial|NOISE|Acme confidence 25; Acme'"'"'s own note: "OVH shared CDN. LIKELY NOISE"|LOW|N
ip|20.83.144.56|Commercial|NOISE|Acme confidence 22; Acme'"'"'s own note: "Azure CDN. Almost certainly shared hosting. DO NOT BLOCK"|LOW|N
ip|13.107.42.14|Commercial|NOISE|Acme confidence 15; Acme'"'"'s own note: "This is a Microsoft Outlook.com cloud IP. Clustering model noise" -- blocking would break legitimate mail flow|LOW|N
ip|172.67.192.40|Commercial|NOISE|Acme confidence 20; Acme'"'"'s own note: "Cloudflare front IP. Not actionable"|LOW|N
ip|104.21.35.7|Commercial|NOISE|Acme confidence 18, same Cloudflare ASN (AS13335) as the adjacent confirmed-noise entry; shared CDN front IP|LOW|N
hash|a1b2c3d4e5f6789012345678901234567890abcdef1234567890abcdef123456|HC3,Commercial,Researcher|ACTIONABLE|HEALTHBANE_S2_invoice.docm dropper; 3-source corroboration, HC3 HIGH, Acme 96/100|HIGH|N
hash|b9c8a7d6e5f4321098765432109876543210fedcba9876543210fedcba987654|HC3,Commercial|ACTIONABLE|svchost_update.exe persistence trojan; HC3 HIGH, Acme 96/100|HIGH|N
hash|c7d6e5f4a3b291827364554637281900a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6|HC3,Commercial,Researcher|ACTIONABLE|sync_healthdata.ps1 exfil script, pulled directly from kit tools/ dir by researcher; 3-source corroboration|HIGH|N
hash|dd5efb6d1ab4c67890abcdef1234567890abcdef1234567890abcdef12345678|HC3,Commercial|ACTIONABLE|Dropper variant, HC3 MEDIUM (one partner org) + Acme 75/100; specific named variant not a clustering artifact|MEDIUM|N
hash|ee1122334455667788990011223344556677889900aabbccddeeff0011223344|Commercial|ACTIONABLE|update_service_v2.exe; Acme confidence 82/100 with a specific filename_hint and trojan-variant tag, not clustering-only -- single-source but high internal confidence|MEDIUM|Y
hash|2f4a6c8e0b1d3f5a7c9e1b3d5f7a9c1e3b5d7f9a1c3e5b7d9f1a3c5e7b9d1f|HC3,Researcher,MedDefense|CONTEXTUAL|INV-2026-04891.pdf lure hash, 3-source corroboration BUT the value is only 62 hex characters (2 short of a valid SHA-256) across all 3 sources -- cannot be deployed to an EDR/AV blocklist as-is; needs correction/re-acquisition first|MEDIUM|Y
hash|ffaabbccdd0011223344556677889900aabbccddeeff00112233445566778899|Researcher|CONTEXTUAL|Kit ZIP itself; researcher explicitly states "MEDIUM because I do not know if it is operator-signed or shipped by a kit vendor" -- may be a commodity kit artifact shared across unrelated operators, not unique to this actor|MEDIUM|Y
hash|1122aabbccddeeff00112233445566778899aabbccddeeff0011223344556677|Commercial|NOISE|Acme confidence 40; Acme'"'"'s own note: "Tagged by clustering; likely unrelated malware family"|LOW|N
hash|3344556677889900aabbccddeeff00112233445566778899aabbccddeeff0011|Commercial|NOISE|Acme confidence 35, tagged unrelated-cluster with no corroborating detail|LOW|N
hash|5566778899aabbccddeeff00112233445566778899aabbccddeeff0011223344|Commercial|NOISE|Acme confidence 42, tagged healthcare-kw/clustered_by_similarity only|LOW|N
hash|7788990011223344556677aabbccddeeff0011223344556677aabbccddeeff00|Commercial|NOISE|Acme confidence 48, tagged clustered_by_similarity only, no filename hint or corroboration|LOW|N
url|https://meddefense-portal.com/verify/staff?id=<user>&token=<8hex>|HC3,Researcher|ACTIONABLE|Credential-capture endpoint pattern, 2-source corroboration; actionable as a URL-PATH detection rule (path + host), not as a literal block since the token is per-victim|HIGH|N
url|https://medequip-supplies.net/invoices/pay?id=INV-<YYYY-NNNNN>|HC3,Commercial|ACTIONABLE|Credential-capture endpoint pattern, HC3 HIGH; actionable as a URL-path detection rule|HIGH|N
url|https://meddefense-benefits.org/enroll|HC3,Commercial|ACTIONABLE|Credential-capture endpoint, HC3 HIGH, static path with no per-victim token -- directly blockable|HIGH|N
url|https://healthbane-c2.net/update/svchost_update.exe|HC3,Commercial|ACTIONABLE|Stage 2 malware download URL, HC3 HIGH -- directly blockable, static path|HIGH|N
url|https://outlook-protection.com/verify|Commercial|ACTIONABLE|Acme confidence 88/100; consistent with 4x00 F3 finding of this domain as a higher-sophistication, fully SPF/DKIM/DMARC-passing lookalike -- static path, directly blockable|MEDIUM|N
url|https://healthbane-c2.net/api/ingest|Researcher|ACTIONABLE|Exfil ingest endpoint pulled directly from the operator'"'"'s own config.php (EXFIL_ENDPOINT key) -- single-source but primary evidence, not inference|MEDIUM|Y
url|https://meddefense-portal.com/verify/staff?id=<user>&token=<hex>|Commercial|CONTEXTUAL|Same host+path as the already-ACTIONABLE HC3/Researcher entry above; this is a redundant restatement of the same pattern with a differently-worded placeholder, adds no new blocking value on its own|MEDIUM|Y
url|https://meddefense-portal.com/verify/staff?id=dmarsh&token=a8f3e2d1|MedDefense|CONTEXTUAL|Single real victim-session instance, already covered by the host+path pattern above; valuable as forensic/attribution evidence for the dmarsh case specifically, not as a new blocking rule|HIGH|N
email|noreply@meddefense-portal.com|MedDefense|ACTIONABLE|Sender address for Stage 1 lure E2; direct MedDefense telemetry, already deployed in Wazuh rule 100080|HIGH|N
email|invoices@medequip-supplies.net|MedDefense|ACTIONABLE|Sender address for Stage 1 lure E5; direct MedDefense telemetry, already deployed in Wazuh rule 100080|HIGH|N
email|hr-notifications@meddefense-benefits.org|MedDefense|ACTIONABLE|Sender address for Stage 1 lure E7; direct MedDefense telemetry, already deployed in Wazuh rule 100080|HIGH|N
'

echo "================================================================"
echo "   INDICATOR TRIAGE: HEALTHBANE (50 unique indicators)"
echo "================================================================"
echo ""
printf "%-7s| %-45s| %-11s| %-10s| %-6s| %s\n" "Type" "Value" "Category" "Confidence" "Uncrt" "Justification"
printf -- "-------|---------------------------------------------|------------|-----------|-------|-----------------------------------------------\n"

echo "$DATA" | while IFS='|' read -r type value sources category justification confidence uncertain; do
	[ -z "$type" ] && continue
	printf "%-7s| %-45s| %-11s| %-10s| %-6s| %s\n" "$type" "$value" "$category" "$confidence" "$uncertain" "$justification"
	echo "        sources: $sources"
done

echo ""
echo "================================================================"
echo "   SUMMARY STATISTICS"
echo "================================================================"

TOTAL=$(echo "$DATA" | grep -c '|')
ACT=$(echo "$DATA" | awk -F'|' '$4=="ACTIONABLE"' | grep -c '|')
CTX=$(echo "$DATA" | awk -F'|' '$4=="CONTEXTUAL"' | grep -c '|')
NOI=$(echo "$DATA" | awk -F'|' '$4=="NOISE"' | grep -c '|')

echo "Total indicators reviewed: $TOTAL"
awk -v a="$ACT" -v t="$TOTAL" 'BEGIN{printf "ACTIONABLE: %d (%.0f%%)\n", a, 100*a/t}'
awk -v c="$CTX" -v t="$TOTAL" 'BEGIN{printf "CONTEXTUAL: %d (%.0f%%)\n", c, 100*c/t}'
awk -v n="$NOI" -v t="$TOTAL" 'BEGIN{printf "NOISE:      %d (%.0f%%)\n", n, 100*n/t}'
echo ""

echo "Top reasons indicators were downgraded (CONTEXTUAL or NOISE):"
echo "  1. Shared/CDN/cloud hosting explicitly flagged by the source itself"
echo "     (7 IPs: DigitalOcean, OVH CDN, Azure CDN, Cloudflare x2, Microsoft cloud)"
echo "  2. ML-clustering-only association with no human review or corroboration"
echo "     (Acme's own metadata discloses 'SAMPLED, not all items human-reviewed')"
echo "  3. Activity predates or lacks confirmed overlap with the HEALTHBANE window"
echo "     (rx-benefits-portal.com: -16 days; verify-health-portal.net: naming-pattern only)"
echo "  4. Data-quality defect preventing operational deployment"
echo "     (the 62-character malformed SHA-256, corroborated by 3 sources but unusable as-is)"
echo "  5. Single-source claims explicitly hedged by the source's own confidence language"
echo "     (kit ZIP hash: researcher unsure if operator-signed or vendor-shipped)"
echo ""

echo "Top indicators for immediate detection (highest-confidence ACTIONABLE, multi-source):"
echo "$DATA" | awk -F'|' '$4=="ACTIONABLE" && $6=="HIGH"' | while IFS='|' read -r type value _ _ _ _ _; do
	[ -z "$type" ] && continue
	echo "  [$type] $value"
done
echo ""
echo "Not all 50 unique indicators are operationally safe to block: $((CTX + NOI)) of $TOTAL"
echo "($(awk -v c="$CTX" -v n="$NOI" -v t="$TOTAL" 'BEGIN{printf "%.0f", 100*(c+n)/t}')%) fall into CONTEXTUAL or NOISE."

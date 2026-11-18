# MedDefense SOC Playbook Integration Test Results

**Date of run:** 2026-11-18 (UTC)  
**Tester:** Tales Lima  
**Code under test:** `enrich_ioc.py`, `case_manager.py`, `playbook_phishing_triage.py`, `playbook_credential_exposure.py`  
**Fixtures:** the provided alerts in `materials/alerts/`, copied to `alerts/`; expected outcomes from `materials/integration/expected_outcomes.csv`

## Summary

| Test | Alert | Playbook | Expected | Actual | Isolation queue (expected / actual) | Result |
| --- | --- | --- | --- | --- | --- | --- |
| 1 | ALT-20260428-001 | phishing_triage | ESCALATE / Critical / escalated | ESCALATE / Critical / escalated | no / no | PASS |
| 2 | ALT-20260428-002 | phishing_triage | REVIEW / High / open | REVIEW / High / open | no / no | PASS |
| 3 | ALT-20260428-003 | phishing_triage | CLOSE / Low / closed | CLOSE / Low / closed | no / no | PASS |
| 4 | ALT-20260428-007 | credential_exposure | ESCALATE / Critical / escalated | ESCALATE / Critical / escalated | yes / yes | PASS |
| 5 | ALT-20260428-009 | credential_exposure | MANUAL_REVIEW / Medium / open | MANUAL_REVIEW / Medium / open | no / no | PASS |

**Result: 5 of 5 PASS.** All runs exited with code 0. Exactly one host (`WST-WS-031`) was written to the isolation queue, and no host was isolated: the queue entry is `pending_authorization`.

## Environment and Reset

Run on the analyst workstation (Ubuntu, Python 3.14.4) from the project directory, with no internet dependency in the code path: the feed is local and reverse DNS failures return `NXDOMAIN`. The lab specification targets Python 3.8+; the code avoids newer syntax (`from __future__ import annotations`). The reset follows `materials/integration/integration_test_checklist.md`:

```bash
rm -f cases.db playbook_audit.log isolation_queue.json
mkdir -p alerts
cp materials/alerts/phishing/*.json alerts/
cp materials/alerts/credential/*.json alerts/
cp materials/threat_intel/ioc_feed.json ./ioc_feed.json
cp materials/iam/privileged_accounts.json ./privileged_accounts.json
```

Before the integration run, `enrich_ioc.py` was checked against all ten rows of `materials/threat_intel/enrichment_validation_set.csv` (type, IP class, score, verdict): 10 of 10 match, including the five values required by Task 1.

Case IDs use the real run date (`CASE-20261118-NNN`). The alert fixtures are dated 2026-04-28, so the IDs differ from the `CASE-20260428-NNN` examples in the materials; the sequence logic is the same.

## Test 1: ALT-20260428-001

**Scenario:** Known malicious sender: sender IP `198.51.100.42` (Cobalt Strike C2 in feed) and sender domain `meddefense-secure.net` (typosquat). Both URLs in the body point to the same two hosts.

**Command:**

```bash
python3 playbook_phishing_triage.py alerts/ALT-20260428-001.json
```

**Actual stdout** (exit code 0):

```text
[2026-11-18T09:31:53Z] PHISHING TRIAGE PLAYBOOK
Alert      : ALT-20260428-001
Rule       : phishing_email_suspicious_sender
IOCs       : 4 extracted, 2 enriched, 2 dedup skipped
  198.51.100.42          ipv4    BLOCK       score=95  (c2, cobalt_strike)
  meddefense-secure.net  domain  BLOCK       score=97  (typosquat, phishing)
  meddefense-secure.net  [dedup, skipped]
  198.51.100.42          [dedup, skipped]
Verdict    : ESCALATE
Case       : CASE-20261118-001  Severity: Critical  Status: escalated
Action     : SOC notification queued for on-call analyst
```

**Case created** (`python3 case_manager.py get CASE-20261118-001`):

```json
{
  "case_id": "CASE-20261118-001",
  "alert_id": "ALT-20260428-001",
  "severity": "Critical",
  "title": "Phishing: Known C2 IP Escalated",
  "description": "Rule phishing_email_suspicious_sender | From: billing@meddefense-secure.net (198.51.100.42) | To: d.walsh@meddefense.internal | Subject: Urgent: Patient billing system maintenance required | SPF/DKIM/DMARC: pass/pass/none",
  "status": "escalated",
  "created_at": "2026-11-18T09:31:53Z",
  "updated_at": "2026-11-18T09:31:53Z",
  "resolution": null,
  "notes": [
    {
      "note": "Playbook verdict: ESCALATE. IOCs: 198.51.100.42 (BLOCK/95), meddefense-secure.net (BLOCK/97). Escalation triggered by: 198.51.100.42 (c2, cobalt_strike), meddefense-secure.net (typosquat, phishing)",
      "created_at": "2026-11-18T09:31:53Z"
    }
  ],
  "iocs": [
    {
      "ioc_value": "198.51.100.42",
      "ioc_type": "ipv4",
      "verdict": "BLOCK",
      "score": 95
    },
    {
      "ioc_value": "meddefense-secure.net",
      "ioc_type": "domain",
      "verdict": "BLOCK",
      "score": 97
    }
  ]
}
```

| Check | Expected | Actual | Match |
| --- | --- | --- | --- |
| Verdict | ESCALATE | ESCALATE | yes |
| Case severity | Critical | Critical | yes |
| Case status | escalated | escalated | yes |
| Isolation queue entry | no | no | yes |
| Exit code | 0 | 0 | yes |

**Result: PASS**

Escalation is driven by two independent BLOCK IOCs, so it does not depend on a single feed entry. SPF and DKIM pass: the attacker controls `meddefense-secure.net`, so authentication results do not make the email trustworthy. The playbook created the case and the note only; it did not block the sender or quarantine the mailbox.

## Test 2: ALT-20260428-002

**Scenario:** Unknown external sender: newsletter from `external-health-news.com` via `203.0.113.5`; neither is in the feed or the allowlist.

**Command:**

```bash
python3 playbook_phishing_triage.py alerts/ALT-20260428-002.json
```

**Actual stdout** (exit code 0):

```text
[2026-11-18T09:31:53Z] PHISHING TRIAGE PLAYBOOK
Alert      : ALT-20260428-002
Rule       : phishing_email_suspicious_sender
IOCs       : 3 extracted, 2 enriched, 1 dedup skipped
  203.0.113.5               ipv4    INVESTIGATE score=30  (not in feed)
  external-health-news.com  domain  INVESTIGATE score=30  (not in feed)
  external-health-news.com  [dedup, skipped]
Verdict    : REVIEW
Case       : CASE-20261118-002  Severity: High  Status: open
Action     : Queued for analyst manual review
```

**Case created** (`python3 case_manager.py get CASE-20261118-002`):

```json
{
  "case_id": "CASE-20261118-002",
  "alert_id": "ALT-20260428-002",
  "severity": "High",
  "title": "Phishing: Suspicious sender review",
  "description": "Rule phishing_email_suspicious_sender | From: newsletter@external-health-news.com (203.0.113.5) | To: r.osei@meddefense.internal | Subject: Healthcare IT newsletter April 2026 | SPF/DKIM/DMARC: pass/none/none",
  "status": "open",
  "created_at": "2026-11-18T09:31:53Z",
  "updated_at": "2026-11-18T09:31:53Z",
  "resolution": null,
  "notes": [
    {
      "note": "Playbook verdict: REVIEW. IOCs: 203.0.113.5 (INVESTIGATE/30), external-health-news.com (INVESTIGATE/30)",
      "created_at": "2026-11-18T09:31:53Z"
    }
  ],
  "iocs": [
    {
      "ioc_value": "203.0.113.5",
      "ioc_type": "ipv4",
      "verdict": "INVESTIGATE",
      "score": 30
    },
    {
      "ioc_value": "external-health-news.com",
      "ioc_type": "domain",
      "verdict": "INVESTIGATE",
      "score": 30
    }
  ]
}
```

| Check | Expected | Actual | Match |
| --- | --- | --- | --- |
| Verdict | REVIEW | REVIEW | yes |
| Case severity | High | High | yes |
| Case status | open | open | yes |
| Isolation queue entry | no | no | yes |
| Exit code | 0 | 0 | yes |

**Result: PASS**

Both IOCs score 30 (unknown, not malicious). The case stays open for an analyst, who can close it with `python3 case_manager.py close <CASE-ID> "benign; confirmed newsletter sender"`.

## Test 3: ALT-20260428-003

**Scenario:** Internal sender: `it-notices@meddefense.internal` from private IP `10.0.1.25`, SPF/DKIM/DMARC pass, no URLs.

**Command:**

```bash
python3 playbook_phishing_triage.py alerts/ALT-20260428-003.json
```

**Actual stdout** (exit code 0):

```text
[2026-11-18T09:31:53Z] PHISHING TRIAGE PLAYBOOK
Alert      : ALT-20260428-003
Rule       : phishing_email_suspicious_sender
IOCs       : 2 extracted, 2 enriched, 0 dedup skipped
  10.0.1.25            ipv4    ALLOW       score=0   (Private address range; internal network traffic)
  meddefense.internal  domain  ALLOW       score=0   (allowlisted)
Verdict    : CLOSE
Case       : CASE-20261118-003  Severity: Low  Status: closed
Action     : Auto-closed: no_indicators_of_compromise
```

**Case created** (`python3 case_manager.py get CASE-20261118-003`):

```json
{
  "case_id": "CASE-20261118-003",
  "alert_id": "ALT-20260428-003",
  "severity": "Low",
  "title": "Phishing: No indicators, auto-closed",
  "description": "Rule phishing_email_suspicious_sender | From: it-notices@meddefense.internal (10.0.1.25) | To: p.delgado@meddefense.internal | Subject: Scheduled maintenance reminder | SPF/DKIM/DMARC: pass/pass/pass",
  "status": "closed",
  "created_at": "2026-11-18T09:31:53Z",
  "updated_at": "2026-11-18T09:31:53Z",
  "resolution": "no_indicators_of_compromise",
  "notes": [
    {
      "note": "Playbook verdict: CLOSE. IOCs: 10.0.1.25 (ALLOW/0), meddefense.internal (ALLOW/0)",
      "created_at": "2026-11-18T09:31:53Z"
    }
  ],
  "iocs": [
    {
      "ioc_value": "10.0.1.25",
      "ioc_type": "ipv4",
      "verdict": "ALLOW",
      "score": 0
    },
    {
      "ioc_value": "meddefense.internal",
      "ioc_type": "domain",
      "verdict": "ALLOW",
      "score": 0
    }
  ]
}
```

| Check | Expected | Actual | Match |
| --- | --- | --- | --- |
| Verdict | CLOSE | CLOSE | yes |
| Case severity | Low | Low | yes |
| Case status | closed | closed | yes |
| Isolation queue entry | no | no | yes |
| Exit code | 0 | 0 | yes |

**Result: PASS**

This is the only automatic closure. It is allowed in the lab because every IOC is internal or allowlisted. Before production auto-close, `materials/strategy/false_positive_governance.md` requires a measured false-negative rate (below 2 percent for benign auto-close) and monitoring, because an internal sender can also be a compromised internal account.

## Test 4: ALT-20260428-007

**Scenario:** LSASS dump (`T1003.001`) on clinical workstation `WST-WS-031` from known C2 IP `198.51.100.42`, by Domain Admin service account `svc_helpdesk`.

**Command:**

```bash
python3 playbook_credential_exposure.py alerts/ALT-20260428-007.json
```

**Actual stdout** (exit code 0):

```text
[2026-11-18T09:31:53Z] CREDENTIAL EXPOSURE PLAYBOOK
Alert      : ALT-20260428-007
Rule       : credential_access_lsass_dump
Host       : WST-WS-031
User       : svc_helpdesk  Privilege: Domain Admin
Source IP  : 198.51.100.42  Verdict: BLOCK  Score: 95
MITRE      : T1003.001 OS Credential Dumping: LSASS Memory
Verdict    : ESCALATE
Case       : CASE-20261118-004  Severity: Critical  Status: escalated
Action     : Host written to isolation_queue.json for analyst authorization
```

**Case created** (`python3 case_manager.py get CASE-20261118-004`):

```json
{
  "case_id": "CASE-20261118-004",
  "alert_id": "ALT-20260428-007",
  "severity": "Critical",
  "title": "Credential Exposure: LSASS dump on WST-WS-031 by Domain Admin account svc_helpdesk",
  "description": "Rule credential_access_lsass_dump | Host WST-WS-031 (Clinical Workstations) | Process C:\\Windows\\Temp\\svhost32.exe -> lsass.exe | Command: C:\\Windows\\Temp\\svhost32.exe --dump lsass | MITRE T1003.001 OS Credential Dumping: LSASS Memory",
  "status": "escalated",
  "created_at": "2026-11-18T09:31:53Z",
  "updated_at": "2026-11-18T09:31:53Z",
  "resolution": null,
  "notes": [
    {
      "note": "Playbook verdict: ESCALATE. Source IP 198.51.100.42: verdict BLOCK score 95 (ip_class documentation, reverse_dns NXDOMAIN, category c2, tags cobalt_strike,beacon, feed source meddefense-internal). User svc_helpdesk: Domain Admin. MITRE T1003.001 OS Credential Dumping: LSASS Memory. Decision: IP verdict BLOCK + Domain Admin -> Critical / escalated. Reasoning: LSASS dump from known C2 IP 198.51.100.42 by Domain Admin svc_helpdesk. Host queued for isolation pending analyst authorization; no automatic isolation performed.",
      "created_at": "2026-11-18T09:31:53Z"
    }
  ],
  "iocs": [
    {
      "ioc_value": "198.51.100.42",
      "ioc_type": "ipv4",
      "verdict": "BLOCK",
      "score": 95
    }
  ]
}
```

| Check | Expected | Actual | Match |
| --- | --- | --- | --- |
| Verdict | ESCALATE | ESCALATE | yes |
| Case severity | Critical | Critical | yes |
| Case status | escalated | escalated | yes |
| Isolation queue entry | yes | yes | yes |
| Exit code | 0 | 0 | yes |

**Result: PASS**

This is the incident path from 6x02 (`svc_helpdesk`, IAM-003) seen as an alert. The playbook surfaces it as a pre-enriched Critical case in one second instead of the 45 minutes of manual enrichment during the incident. The host goes to the queue; isolation still needs an analyst in the EDR console.

## Test 5: ALT-20260428-009

**Scenario:** Pass the hash (`T1550.002`) from internal IP `192.168.10.55` on radiology workstation `WST-WS-041`, by standard user `k.nguyen`, to `\\WST-WS-044\ADMIN$`.

**Command:**

```bash
python3 playbook_credential_exposure.py alerts/ALT-20260428-009.json
```

**Actual stdout** (exit code 0):

```text
[2026-11-18T09:31:53Z] CREDENTIAL EXPOSURE PLAYBOOK
Alert      : ALT-20260428-009
Rule       : lateral_movement_pass_the_hash
Host       : WST-WS-041
User       : k.nguyen  Privilege: Standard
Source IP  : 192.168.10.55  Verdict: ALLOW  Score: 0
MITRE      : T1550.002 Use Alternate Authentication Material: Pass the Hash
Verdict    : MANUAL_REVIEW
Case       : CASE-20261118-005  Severity: Medium  Status: open
Action     : Queued for analyst manual review; no isolation queued
```

**Case created** (`python3 case_manager.py get CASE-20261118-005`):

```json
{
  "case_id": "CASE-20261118-005",
  "alert_id": "ALT-20260428-009",
  "severity": "Medium",
  "title": "Credential Exposure: Pass the hash on WST-WS-041 by Standard account k.nguyen",
  "description": "Rule lateral_movement_pass_the_hash | Host WST-WS-041 (Radiology Workstations) | Process C:\\Windows\\System32\\cmd.exe -> n/a | Command: cmd.exe /c net use \\\\WST-WS-044\\ADMIN$ | MITRE T1550.002 Use Alternate Authentication Material: Pass the Hash",
  "status": "open",
  "created_at": "2026-11-18T09:31:53Z",
  "updated_at": "2026-11-18T09:31:53Z",
  "resolution": null,
  "notes": [
    {
      "note": "Playbook verdict: MANUAL_REVIEW. Source IP 192.168.10.55: verdict ALLOW score 0 (ip_class private, reverse_dns NXDOMAIN, category none, tags none, feed source none). User k.nguyen: Standard. MITRE T1550.002 Use Alternate Authentication Material: Pass the Hash. Decision: IP verdict ALLOW + Standard -> Medium / open. Reasoning: Pass the hash from internal IP 192.168.10.55 by Standard k.nguyen. No isolation queued; analyst manual review required.",
      "created_at": "2026-11-18T09:31:53Z"
    }
  ],
  "iocs": [
    {
      "ioc_value": "192.168.10.55",
      "ioc_type": "ipv4",
      "verdict": "ALLOW",
      "score": 0
    }
  ]
}
```

| Check | Expected | Actual | Match |
| --- | --- | --- | --- |
| Verdict | MANUAL_REVIEW | MANUAL_REVIEW | yes |
| Case severity | Medium | Medium | yes |
| Case status | open | open | yes |
| Isolation queue entry | no | no | yes |
| Exit code | 0 | 0 | yes |

**Result: PASS**

The outcome matches the decision table. See Observation 2 below: the table rates this scenario lower than its context suggests.

## Defects Found and Fixed

### Defect 1: documentation IPs classified as private (would have allowed the C2 IP)

**Found:** during development of `classify_ip()`, before the integration run.

**Discrepancy:** on Python 3.11 and later, `ipaddress` reports the RFC 5737 documentation ranges as private:

```text
$ python3 -c "import ipaddress; a=ipaddress.ip_address('198.51.100.42'); print(a.is_private, a.is_global)"
True False
```

A `classify_ip()` that tests `is_private` first returns `private` for `198.51.100.42`. `score_ioc()` then returns `(0, "ALLOW")` before the feed is checked. Effect on the tests: in Test 4 the C2 source IP would be ALLOW, so the Domain Admin row of the table gives High / escalated with **no isolation entry** instead of Critical with isolation (FAIL). In Test 1 the IP would also show ALLOW; the case would still escalate only because the sender domain is a separate BLOCK hit. Any phishing email sent from that C2 address with an unknown domain would have been rated as if the address were internal. This is the silent failure James Chen described in the design review: a known malicious indicator treated as safe.

**Fix:** `classify_ip()` checks the three documentation networks (and `2001:db8::/32`) explicitly, before loopback, link-local, multicast and private. Verified by the validation set (`198.51.100.42`, `203.0.113.99` and the URL with an IP host all return `documentation`) and by Tests 1 and 4.

### Defect 2: null `target_process` written as `None` in the case description

**Found:** in the first integration run, in the case for ALT-20260428-009 (`target_process` is `null` in the alert). The description read `Process C:\Windows\System32\cmd.exe -> None`.

**Fix:** `playbook_credential_exposure.py` writes `n/a` for a missing process or target process. The test was reset and rerun from the checklist; the outputs in this document are from the second run. Verdicts and severities were identical in both runs.

### Discrepancy 3: IOC counts in the reference examples

The reference stdout (`materials/integration/sample_stdout_outputs.md`) shows `3 extracted, 2 enriched, 1 dedup skipped` for ALT-20260428-001, and the audit log reference shows `IOCs:3 | BLOCK:2,INVESTIGATE:0,ALLOW:1`. The alert actually yields four candidates: `from_ip`, the sender domain and two URL hostnames, and both URL hostnames duplicate the first two. The playbook therefore reports `4 extracted, 2 enriched, 2 dedup skipped` and `IOCs:2 | BLOCK:2,INVESTIGATE:0,ALLOW:0`. The audit `IOCs` value counts enriched IOCs so that the three verdict counters always add up to it. No code change: the reference examples illustrate the format, and the verdict, severity and status match.

## Observations on the Decision Logic

1. **Credential playbook verdict names.** The decision table gives severity, status and queue, but not a verdict label. The playbook uses `ESCALATE` when the status is `escalated` and `MANUAL_REVIEW` when it is `open`, matching `expected_outcomes.csv`.
2. **Test 5 is rated by the table, not by its context.** Pass the hash to `ADMIN$` on another workstation is lateral movement whatever the source IP. `k.nguyen` is a standard user with no MFA and three phishing failures in 90 days (6x02, IAM-010), which makes a stolen hash plausible. The table gives Medium because the IP is internal and the user is not privileged. Recommendation for the next version: raise `T1550.002` and `T1003.001` alerts to at least High regardless of IP, and add a watchlist input for high-risk users. Isolation stays human-authorized.
3. **Extra fixture ALT-20260428-008** (LSASS dump by Domain Admin `admin.legacy` from internal IP) is not one of the five required tests. It was run once in a separate scratch copy so that `cases.db` here holds only the five required cases. Result: High / escalated / no isolation entry, matching its `expected` block ("Domain Admin anomaly from internal IP").
4. **Error handling** was checked in the same scratch copy: an alert with no `from_ip` and two malformed URLs produced warnings on stderr, one enriched IOC, a REVIEW case and exit code 0; a malformed JSON file and an alert without `raw_log` exited with code 1 and no case.

## Final State

`python3 case_manager.py list` (default filter: every status except closed; the closed case for Test 3 is therefore not listed):

```text
+-------------------+------------------+----------+------------------------------------------------------------------------------------+-----------+
| Case ID           | Alert ID         | Severity | Title                                                                              | Status    |
+-------------------+------------------+----------+------------------------------------------------------------------------------------+-----------+
| CASE-20261118-001 | ALT-20260428-001 | Critical | Phishing: Known C2 IP Escalated                                                    | escalated |
| CASE-20261118-002 | ALT-20260428-002 | High     | Phishing: Suspicious sender review                                                 | open      |
| CASE-20261118-004 | ALT-20260428-007 | Critical | Credential Exposure: LSASS dump on WST-WS-031 by Domain Admin account svc_helpdesk | escalated |
| CASE-20261118-005 | ALT-20260428-009 | Medium   | Credential Exposure: Pass the hash on WST-WS-041 by Standard account k.nguyen      | open      |
+-------------------+------------------+----------+------------------------------------------------------------------------------------+-----------+
4 cases (filter: open + investigating + escalated)
```

`cat isolation_queue.json`:

```json
[
  {
    "queued_at": "2026-11-18T09:31:53Z",
    "host": "WST-WS-031",
    "alert_id": "ALT-20260428-007",
    "case_id": "CASE-20261118-004",
    "reason": "LSASS dump from known C2 IP 198.51.100.42 by Domain Admin svc_helpdesk",
    "action_required": "Analyst must authorize isolation via EDR console before execution",
    "status": "pending_authorization"
  }
]
```

`cat playbook_audit.log`:

```text
2026-11-18T09:31:53Z | PHISHING_TRIAGE | ALT-20260428-001 | IOCs:2 | BLOCK:2,INVESTIGATE:0,ALLOW:0 | Verdict:ESCALATE | Case:CASE-20261118-001 | Severity:Critical
2026-11-18T09:31:53Z | PHISHING_TRIAGE | ALT-20260428-002 | IOCs:2 | BLOCK:0,INVESTIGATE:2,ALLOW:0 | Verdict:REVIEW | Case:CASE-20261118-002 | Severity:High
2026-11-18T09:31:53Z | PHISHING_TRIAGE | ALT-20260428-003 | IOCs:2 | BLOCK:0,INVESTIGATE:0,ALLOW:2 | Verdict:CLOSE | Case:CASE-20261118-003 | Severity:Low
2026-11-18T09:31:53Z | CREDENTIAL_EXPOSURE | ALT-20260428-007 | Host:WST-WS-031 | User:svc_helpdesk | IPVerdict:BLOCK | Privilege:Domain Admin | Case:CASE-20261118-004 | Severity:Critical | IsolationQueued:yes
2026-11-18T09:31:53Z | CREDENTIAL_EXPOSURE | ALT-20260428-009 | Host:WST-WS-041 | User:k.nguyen | IPVerdict:ALLOW | Privilege:Standard | Case:CASE-20261118-005 | Severity:Medium | IsolationQueued:no
```

# Phishing Triage Decision Logic

Extract `raw_log.from_ip`, email domain from `raw_log.from`, and hostnames from `raw_log.body_urls`. Deduplicate before enrichment.

## Decision Ladder

| Condition | Playbook Verdict | Case Severity | Case Status |
|---|---|---|---|
| Any IOC verdict is BLOCK | ESCALATE | Critical | escalated |
| Else any IOC verdict is INVESTIGATE | REVIEW | High | open |
| Else all IOCs are ALLOW | CLOSE | Low | closed |

For CLOSE, use resolution `no_indicators_of_compromise`.

The playbook creates cases for every verdict. It does not quarantine mailboxes or block senders.

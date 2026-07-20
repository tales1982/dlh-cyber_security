# 11. The False Positives — MedDefense Vulnerability Scan

**Analyst:** Threat Intelligence Analyst
**Date:** Current

## Finding 020 — OpenSSH PKCS#11 RCE (`backup-srv-01`)

- **Finding ID:** 020
- **Reported Vulnerability:** CVE-2023-38408, CVSS 9.8 — a critical remote code execution flaw in OpenSSH's `ssh-agent` PKCS#11 provider loading.
- **Why It Is a False Positive:** The vulnerability requires a very specific precondition: `ssh-agent` must be running with PKCS#11 support **and** forwarded to a host the attacker controls. `backup-srv-01` is Veeam backup orchestration infrastructure — a server other systems connect *to* for backup jobs, not a workstation an administrator uses interactively to SSH *out* to third-party or vendor systems with agent forwarding enabled. Without that specific outbound, human-driven usage pattern, the vulnerable code path is never reached, regardless of the OpenSSH version installed. SecurePoint's own note in the report states this directly: "may be a FALSE POSITIVE... requires ssh-agent forwarding to an attacker-controlled system, which is unlikely in this server's operational context."
- **Validation Method:** Check `sshd_config`/`ssh_config` for `AllowAgentForwarding`/`ForwardAgent` settings on this host; review authentication logs for any outbound SSH sessions initiated *from* `backup-srv-01` to external or third-party hosts; interview the systems administrator about how this server is actually used day-to-day (automated backup jobs only, or does anyone log in and SSH elsewhere from it?).
- **Risk of Acting on This FP:** Triggering an emergency, out-of-cycle patch and reboot of the backup orchestration server — precisely the system you least want to destabilize on short notice — to close a path that was never reachable, while a genuinely exploitable Critical finding elsewhere waits for the same limited remediation window.
- **Risk of Not Validating:** If validation is skipped in the other direction — dismissing this without checking — and it turns out an administrator *does* routinely SSH from `backup-srv-01` into an external vendor system with agent forwarding enabled (for support or troubleshooting), the RCE path is real, and the server holding the orchestration logic for every backup job in the environment becomes remotely exploitable.

## Finding 030 — TLS Certificate Common Name Mismatch (`ehr-srv-01`)

- **Finding ID:** 030
- **Reported Vulnerability:** The TLS certificate on `ehr-srv-01` is issued for `ehr.meddefense.local`, but some clients connect via the raw IP address (`10.10.2.10`), triggering certificate validation warnings.
- **Why It Is a False Positive:** The report itself states this outright: "This is an operational issue, not a security vulnerability." A CN mismatch caused by IP-based access does not weaken the encryption in transit, does not indicate a misissued or attacker-controlled certificate, and does not expose any data — it only produces a browser warning that inconveniences whoever connects by IP instead of hostname. The underlying TLS session is still cryptographically sound.
- **Validation Method:** Run `openssl s_client -connect 10.10.2.10:443` and independently inspect the presented certificate — confirm it is issued by a legitimate, trusted CA (not self-signed, not expired, not issued to an unrelated organization), confirm its validity dates, and confirm the mismatch is purely CN-vs-access-method rather than evidence of a substituted or rogue certificate.
- **Risk of Acting on This FP:** Spending change-management effort re-provisioning certificates, or forcing a DNS-only access policy that could break an internal tool or monitoring script that has depended on direct-IP access to `ehr-srv-01` for years, for zero actual security gain.
- **Risk of Not Validating:** The validation step is exactly what distinguishes "harmless CN/IP mismatch" from "someone swapped in a certificate for a domain that isn't ours" — a real certificate-substitution or MITM condition would look identical at a glance. Skipping the check because the report already called it benign would mean trusting the scanner's read of intent rather than confirming the certificate's actual issuer and chain.

## Finding 022 — System Clock Skew Detected (`ehr-srv-01`)

- **Finding ID:** 022
- **Reported Vulnerability:** The scanner reports `ehr-srv-01`'s system clock as 47 seconds ahead of its NTP reference, at Low severity, framed as a risk to certificate validation, Kerberos authentication, and log correlation.
- **Why It Is a False Positive:** 47 seconds of skew is far inside the tolerances of every mechanism the finding claims to threaten. Kerberos' default maximum clock-skew tolerance is 5 minutes (300 seconds) — nearly 400 times larger than this offset. TLS certificate validity windows are measured in months to years, making a 47-second difference irrelevant to `notBefore`/`notAfter` checks. Log-correlation tooling in any real SOC routinely tolerates skew on this order as a matter of course. This reads as a scanner dutifully reporting a real, measured fact (a small clock offset exists) that does not rise to the level of an actual security exposure in this specific context.
- **Validation Method:** Check the host's NTP/chrony sync status and history (`chronyc tracking` or `ntpq -p`) to confirm whether this is a stable, momentary measurement artifact or evidence of an NTP daemon that has stopped syncing entirely; re-check the skew value hours later to see whether it is holding steady or actively drifting; confirm no Kerberos authentication failures or certificate-validation errors correlate with this host in existing logs.
- **Risk of Acting on This FP:** Dispatching an administrator to open a change ticket and "fix" NTP configuration with the same urgency as an actionable finding — a low-value task that dilutes attention that should go toward the report's genuinely Critical items.
- **Risk of Not Validating:** If the skew is not simple drift but a symptom of an NTP client that has silently stopped syncing altogether, the offset will keep growing until it eventually *does* cross a threshold that breaks Kerberos authentication or certificate validation outright — dismissing it without checking the sync history means missing the difference between "harmless today" and "will become a real problem in a few weeks."

## Expected False Positive Rate and Why Validation Matters

SecurePoint's own methodology notes state a typical OpenVAS false-positive rate of **5-10%** for this scan configuration. Applied to 31 findings, that predicts roughly **1.5 to 3 false positives** — and the three identified above (020, 030, and 022) land almost exactly within that expected range, which is itself a useful sanity check: finding zero FPs in a 31-finding report would be more suspicious than finding two or three, and finding ten would suggest something wrong with the scan configuration itself, not the environment. Manual validation before committing remediation resources is essential for a structural reason, not just a cautious one: a vulnerability management program has a fixed amount of attention and change-management capacity in any given week, and every hour spent patching, testing and rebooting a system for a false positive is an hour not spent on a true positive that is actually exploitable right now — as this report's own Critical findings (Ghostcat on the EHR server, the open PostgreSQL database) demonstrate. The cost of skipping validation is not symmetric: acting on a false positive wastes a bounded, recoverable amount of effort, while wrongly dismissing something that only looks like a false positive — without actually checking — can leave a genuine Critical sitting open under the label "already handled."

## Repo

- **GitHub repository:** `dlh-cyber_security`
- **Directory:** `blue_team/1x02_the_weak_links`
- **File:** `11-false_positives.md`

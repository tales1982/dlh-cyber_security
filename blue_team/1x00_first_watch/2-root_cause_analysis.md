
# Root Cause Analysis — billing-srv-01

## 1. Process Identification

`kworker` (PID 8834) is not a real Linux kernel process — real kworker threads run as `root` and appear as `[kworker]`. This one runs as `www-data` from `/var/www/html/.cache/kworker`, named to blend into the process list. `stratum+tcp://pool.monero.org:4443` is the protocol used to talk to a crypto mining pool; `config.json` confirms it, with three Monero pool fallbacks. **This is a cryptojacking payload**, silently mining Monero on the billing server.

## 2. Real Compromise Classification

**The real security problem is not Availability — two other pillars were broken first**, and CPU saturation is only the last, visible event in the chain.

**Confidentiality:** the miner runs from inside the web app's own directory as `www-data`, meaning someone gained unauthorized access to the server through the application itself.

**Integrity:** the attacker then uploaded and ran a binary that was never part of MedDefense's software, disguised to look legitimate — an unauthorized change to the system.

## 3. Why the Sysadmin's Solution Fails

**A hardware upgrade does not fix the security problem.** The miner is configured (`threads: 4`, fixed `cpu-priority`) to use whatever CPU it is given, so a bigger VM just hands the attacker more mining capacity. It also does nothing about how the attacker got in — the same vulnerability carries over to the new VM.

## 4. Connection to the January Incident

**The miner and the January ransomware point to the same underlying weakness.** Two unrelated compromises on the same server after a full rebuild means the rebuild reset the symptom, not the cause. Marcus's notes flag Apache 2.4.29 (known RCE vulnerabilities) as the likely shared entry point. Open question: was Apache patched during the rebuild, or was the same vulnerable version reinstalled?

## Recommendation

1. Confirm the Apache version on `billing-srv-01` against known 2.4.29 RCE advisories.
2. Reject the hardware upgrade — it raises cost without fixing the vulnerability.
3. Audit other servers still running Apache 2.4.29.

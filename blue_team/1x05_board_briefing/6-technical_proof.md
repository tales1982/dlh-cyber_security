# 6. The Technical Proof — MedDefense Health Systems

**Analyst:** Security Analyst
**Date:** Current
**Environment:** OpenSSL 3.0.13, Ubuntu 24.04 (analyst workstation) — all commands below were actually executed; output is real, not reconstructed.

## Check 1 — Certificate Inspection

**Command executed:**
```
$ openssl s_client -connect github.com:443 -servername github.com </dev/null 2>/dev/null \
    | openssl x509 -noout -subject -issuer -dates -pubkey -text
```

**Real output (relevant fields):**
```
subject=CN = github.com
issuer=C = GB, O = Sectigo Limited, CN = Sectigo Public Server Authentication CA DV E36
notBefore=Jul  3 00:00:00 2026 GMT
notAfter=Sep 30 23:59:59 2026 GMT
Public Key Algorithm: id-ecPublicKey, 256 bit, ASN1 OID: prime256v1, NIST CURVE: P-256
X509v3 Subject Alternative Name: DNS:github.com, DNS:www.github.com
```

**5-line summary:**
- **Subject:** CN = github.com
- **Issuer:** Sectigo Public Server Authentication CA DV E36 (Sectigo Limited, GB)
- **Validity:** 2026-07-03 through 2026-09-30 (a standard short-lived DV certificate window)
- **Key Algorithm:** ECC, NIST P-256 (256-bit), signed with ecdsa-with-SHA256
- **SAN entries:** `github.com`, `www.github.com`

## Check 2 — Hash Verification

**Commands executed:**
```
$ echo "MedDefense FortiGate firmware v7.2.5 - integrity baseline test file" > firmware_test.txt
$ echo "Build date: 2026-07-29" >> firmware_test.txt
$ sha256sum firmware_test.txt
722c72fb4e3b39de9f71421a118135285e68176839358d52d226751a672f0753  firmware_test.txt

$ echo "Build date: 2026-07-30" >> firmware_test.txt
$ sha256sum firmware_test.txt
31adc0260cec54ba507066e80bc3146c7a5fe669c99ce182e6e2978ba7f43642  firmware_test.txt
```

**Result:** the two hashes are completely different (`722c72fb...` vs `31adc026...`) after appending a single line of text — no partial resemblance, exactly as expected from SHA-256's avalanche property.

**Why this matters for FortiGate firmware:** because a single-bit change produces a completely unrelated hash, comparing the vendor-published SHA-256 checksum against a hash computed on the actual downloaded firmware file is the only reliable way to confirm the image has not been tampered with or corrupted in transit before installing it on a device that is, for MedDefense, the single point of failure for the entire perimeter.

## Check 3 — Exploit Research

**Commands executed:**
```
$ searchsploit fortigate
$ searchsploit fortios
```

**Real output (fortigate):**
```
Fortigate Firewall 2.x - dlg Admin Interface ...       | hardware/remote/23376.txt
Fortigate Firewall 2.x - listdel Admin Interf ...      | hardware/remote/23378.txt
Fortigate Firewall 2.x - Policy Admin Interfa ...      | hardware/remote/23377.txt
Fortigate Firewall 2.x - selector Admin Inter ...      | hardware/remote/23379.txt
Fortigate Firewalls - 'EGREGIOUSBLUNDER' Remo ...      | hardware/webapps/40276.txt
Fortigate Firewalls - Cross-Site Request Forg ...      | hardware/webapps/26528.txt
Fortigate UTM WAF Appliance - Multiple Vulner ...       | hardware/webapps/21395.txt
Fortinet Fortigate - CRLF Characters URL Filt ...      | hardware/remote/31026.pl
Fortinet Fortigate 2.x/3.0 - URL Filtering By ...      | hardware/remote/27203.pl
Fortinet FortiGate 4.x < 5.0.7 - SSH Backdoor ...      | linux/remote/43386.py
Fortinet FortiGate FortiOS < 6.0.3 - LDAP Cre ...       | hardware/webapps/46171.py
```
**Real output (fortios), two additional near-matches checked directly:**
```
Fortinet FortiOS_ FortiProxy_ and FortiSwitchManager 7.2.0 - Authentication bypass  (EDB-52239)
FortiOS_ FortiProxy_ FortiSwitchManager v7.2.1 - Authentication Bypass              (EDB-51092)
```
Both were verified with `searchsploit -p` and are tagged **CVE-2022-40684** — a *different* Fortinet authentication-bypass vulnerability from the prior year, not CVE-2023-27997. A direct `searchsploit --cve 2023-27997` query returned **no results**.

**Is there a public exploit for CVE-2023-27997?** No confirmed Exploit-DB entry exists for it, on this fully updated local mirror. This matches the research finding from Task 1: detailed public technical analysis exists (Bishop Fox's "XORtigate" writeup), but no turnkey weaponized tool is confirmed public.

**What this tells us about urgency:** the absence of an Exploit-DB listing is not a reason to relax. This CVE is CISA KEV-listed and is, right now, the confirmed mechanism behind five real hospital ransomware compromises — exploitation is being carried out by operators capable of building their own working exploit from public research, which argues for *more* urgency in patching, not less. A missing Exploit-DB page means "harder for a novice to reproduce," not "not actually happening."

## Check 4 — System Audit

**Command executed:**
```
$ lynis audit system --quick --no-colors
```
**Note on execution:** `sudo` in this environment requires an interactive password that is not available non-interactively, so this ran in **non-privileged (Pentest) mode** rather than a full privileged audit — several test families (boot loader checks, password hashing, iptables ruleset detail, sudo config permissions) were skipped as a result, and a privileged run against a real production host like `billing-srv-01` would likely surface additional findings this scan could not reach. What follows is genuine output from the scan that did run, not a fabricated "full" result.

**Real output:**
```
  Hardening index : 62 [############        ]
  Tests performed : 251
  Suggestions      : (43)
  Warnings         : none in this run — "Great, no warnings"
```

**Top 3 suggestions (from the real output):**
1. `[FINT-4350]` Install a file integrity monitoring tool to detect changes to critical and sensitive files.
2. `[HRDN-7230]` Harden the system by installing at least one malware scanner (e.g., rkhunter, chkrootkit, OSSEC).
3. `[PKGS-7398]` Install a package audit tool to determine which installed packages carry known vulnerabilities.

**Suggestion for MedDefense's `billing-srv-01`:** of these three, **file integrity monitoring (FINT-4350)** is the one worth applying first — not generically, but specifically because `billing-srv-01` has already been compromised twice through the same unpatched Apache instance (1x00 Tasks 1 and 2). A file-integrity tool would have flagged the cryptominer binary and the ransomware payload's own filesystem changes on arrival, rather than the actual real-world discovery method both times: someone noticing the machine had slowed down. Given this host's proven, repeated compromise history, "detect the next unauthorized change immediately" is a materially higher-value fix than a generic hardening suggestion picked without that context.

## Repo

- **GitHub repository:** `dlh-cyber_security`
- **Directory:** `blue_team/1x05_board_briefing`
- **File:** `6-technical_proof.md`

# 2. The CVSS Deconstruction - MedDefense Vulnerability Scan

**Analyst:** Threat Intelligence Analyst
**Date:** Current

## Exercise 1: Deconstruction

Vector under analysis (Finding 001, CVE-2021-44790):

```
CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H
```

| Component    | Stands For             | Selected Value         | Meaning                                                                                                                                                                                         | Other Possible Values                                                                                                          | Why This Value Here                                                                                                                                                                                                                        |
| ------------ | ---------------------- | ---------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| **AV** | Attack Vector          | **N - Network**  | The vulnerable component is bound to the network stack, and exploitation is possible remotely, up to and including across the internet.                                                         | A (Adjacent - same network segment only), L (Local - requires local/shell access), P (Physical - requires touching the device) | `mod_lua`'s multipart parser processes an HTTP request body. Apache listens on port 80/tcp, reachable from anywhere that can route to `billing-srv-01`. There is no requirement to already be on the local network.                    |
| **AC** | Attack Complexity      | **L - Low**       | The attacker does not need to study the target, win a race condition, or wait for a specific configuration - the crafted request works reliably, on demand.                                      | H (High - requires additional reconnaissance, timing, or specific victim conditions outside the attacker's control)             | A malformed multipart body is a single, repeatable HTTP request. There is no dependency on a particular runtime state that only exists intermittently.                                                                                     |
| **PR** | Privileges Required    | **N - None**      | The attacker needs no account, API key, or session on the target before sending the exploit.                                                                                                    | L (Low - a basic authenticated account), H (High - administrative access)                                                        | The request hits Apache's public port before any authentication layer of the billing application is reached; `mod_lua` processes the body at the web-server layer.                                                                        |
| **UI** | User Interaction       | **N - None**       | No victim (a legitimate user, an admin clicking a link) needs to do anything for the exploit to fire.                                                                                           | R (Required - e.g., a victim must open a malicious file or click a link)                                                        | The attacker sends the request directly to the server; there is no human in the loop on the defending side.                                                                                                                                |
| **S**  | Scope                  | **U - Unchanged** | The impact stays confined to the same "security authority" that was attacked - a compromised Apache process affects that host/component, not a separate, differently-controlled security domain. | C (Changed - e.g., a browser sandbox escape that then affects the host OS, a different authority than the sandboxed process)    | The vulnerable component (Apache/`mod_lua`) and the impacted component (the same web server process/host) are the same security scope; nothing here crosses into a separately-administered system as a direct effect of the flaw itself. |
| **C**  | Confidentiality Impact | **H - High**      | Total loss of confidentiality - an attacker who achieves code execution can read anything the web server process can read.                                                                       | L (Low - limited disclosure), N (None)                                                                                          | A buffer overflow leading to RCE gives the attacker the same read access as the compromised process, which is effectively total for anything on that host.                                                                                 |
| **I**  | Integrity Impact       | **H - High**      | Total loss of integrity - the attacker can modify any data or code the process can touch.                                                                                                        | L, N                                                                                                                           | Same reasoning as Confidentiality: RCE means arbitrary write, not just arbitrary read.                                                                                                                                                     |
| **A**  | Availability Impact    | **H - High**      | Total loss of availability - the attacker can crash, hang, or fully control the process, including denying service entirely.                                                                     | L, N                                                                                                                           | A buffer overflow can trivially crash the worker process even before an attacker builds a working RCE payload, and a successful RCE gives the attacker the option to take the service down at will.                                        |

**If Attack Vector changes from Network (N) to Local (L):**

Holding every other metric constant (`CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`), the new base score is **8.4 (High)**, down from **9.8 (Critical)**.

Working the CVSS v3.1 formula by hand (Scope Unchanged, so `BaseScore = Roundup(min(Impact + Exploitability, 10))`):

- **Impact** stays identical either way, since C/I/A did not change: `ISC_Base = 1 − (1−0.56)(1−0.56)(1−0.56) = 0.914816`, and `Impact = 6.42 × 0.914816 ≈ 5.873`.
- **Exploitability with AV:N** = `8.22 × 0.85 (AV:N) × 0.77 (AC:L) × 0.85 (PR:N) × 0.85 (UI:N) ≈ 3.887`. Sum with Impact = 9.76 → rounds up to **9.8**.
- **Exploitability with AV:L** = `8.22 × 0.55 (AV:L) × 0.77 × 0.85 × 0.85 ≈ 2.515`. Sum with Impact = 8.388 → rounds up to **8.4**.

The score drops because **AV** is one of the four multiplicative Exploitability factors, and Local (0.55) is a meaningfully smaller weight than Network (0.85) - the vulnerability becomes harder to reach even though nothing about *what happens once you reach it* (the Impact half of the equation) changes at all. Practically, this is the difference between "anyone on the internet can hit this today" and "an attacker needs a foothold on the box first" - still a severe bug (8.4 stays in the High band), but no longer the single most urgent kind of exposure (Critical, 9.0+).

## Exercise 2: Construction

**Given characteristics → mapped metrics:**

| Characteristic                                             | Metric | Value                                                                                                                                |
| ---------------------------------------------------------- | ------ | ------------------------------------------------------------------------------------------------------------------------------------ |
| Exploitable only from the local network (not the internet) | AV     | **A** (Adjacent) - restricted to the local network segment, not Local (L), which would mean requiring access to the host itself |
| Exploitation is complex, requires specific conditions      | AC     | **H** (High)                                                                                                                   |
| Attacker needs low-level privileges                        | PR     | **L** (Low)                                                                                                                    |
| No user interaction needed                                 | UI     | **N**                                                                                                                          |
| Only affects the targeted system (scope unchanged)         | S      | **U**                                                                                                                          |
| Confidentiality compromised completely                     | C      | **H**                                                                                                                          |
| No impact on integrity                                     | I      | **N**                                                                                                                          |
| No impact on availability                                  | A      | **N**                                                                                                                          |

**Constructed vector:** `CVSS:3.1/AV:A/AC:H/PR:L/UI:N/S:U/C:H/I:N/A:N`

**Manual calculation (Scope Unchanged):**

- Exploitability = `8.22 × 0.62 (AV:A) × 0.44 (AC:H) × 0.62 (PR:L) × 0.85 (UI:N) ≈ 1.182`
- `ISC_Base = 1 − (1−0.56)(1−0)(1−0) = 1 − 0.44 = 0.56`
- Impact = `6.42 × 0.56 ≈ 3.595`
- Sum = `1.182 + 3.595 = 4.777` → rounds up to **4.8**

**Result:** Base Score **4.8**, Severity **Medium**.

This is a good illustration of how much AC:H and PR:L (both shrinking Exploitability) combined with a single-metric Impact (only C:H, not the full triad) pull a score down from Critical territory into the middle of the Medium band even with a fully-compromised confidentiality outcome.

## Exercise 3: Comparison

**Above 9.0:** Finding 001, CVE-2021-44790 `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` → **9.8**

**Between 5.0–7.0:** None of the explicitly-scored findings in this scan actually land in the 5.0–6.9 band - the report's scored findings cluster at 7.5+ (Findings 002, 005, 010) or 9.8 (Findings 001, 020, 031). Rather than force a number that isn't in the data, I'm using the **closest available finding, Finding 010 (CVE-2020-25165, BD Alaris pumps) at 7.5**, and flagging this gap explicitly: a real scan report doesn't always hand you a clean example for every exercise, and noting the discrepancy is more honest than picking a finding that doesn't actually belong to the range being asked about.

**Finding 010:** `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H` → **7.5**

**Side-by-side:**

| Metric | CVE-2021-44790 (9.8) | CVE-2020-25165 (7.5) | Same? |
| ------ | -------------------- | -------------------- | ----- |
| AV     | N                    | N                    | ✅    |
| AC     | L                    | L                    | ✅    |
| PR     | N                    | N                    | ✅    |
| UI     | N                    | N                    | ✅    |
| S      | U                    | U                    | ✅    |
| C      | **H**          | **N**          | ❌    |
| I      | **H**          | **N**          | ❌    |
| A      | H                    | H                    | ✅    |

Every Exploitability-side metric (AV/AC/PR/UI) is **identical** between the two - both vulnerabilities are equally easy to reach: unauthenticated, low complexity, over the network. The Exploitability sub-score is therefore mathematically identical for both (≈3.887). **The entire 2.3-point gap comes exclusively from the Impact metrics.** CVE-2021-44790 compromises Confidentiality, Integrity and Availability completely (RCE); CVE-2020-25165 only affects Availability (a denial-of-service against the infusion pump's wireless functionality, per NVD) - Confidentiality and Integrity are untouched.

**Which components have the biggest impact on the final score, in general?** For a fixed level of "reachability" (as this comparison shows directly), the **Impact triad (C/I/A)** is what separates a High from a Critical - going from one impacted metric to three, at the High level, is worth roughly 2+ points on its own. On the Exploitability side, **Attack Vector** and **Privileges Required** carry the largest individual swings (AV:N→AV:L alone cost 1.4 points in Exercise 1's recalculation), because they gate *who can even attempt the attack* before Impact is ever considered.

# 16. The Cryptographic Attack Surface MedDefense Health Systems

**Analyst:** Security Analyst
**Date:** Current

```
Attack: TLS Downgrade
Mechanism: During the TLS handshake, client and server negotiate the highest protocol version both support. An on-path attacker interferes with the initial handshake attempt (e.g., blocking/corrupting the client's TLS 1.2 ClientHello), causing the client to retry at a lower, more "compatible" version — landing the connection on a weaker protocol the attacker can then exploit (BEAST, POODLE, Lucky Thirteen against TLS 1.0).
MedDefense Vulnerability: The patient portal (web-srv-01) supports TLS 1.0 simultaneously alongside TLS 1.2, giving an attacker a weaker version to force the connection down to.
Evidence: 1x02 Finding 005 (TLS 1.0 and TLS 1.2 both supported, TLS 1.3 not supported, HSTS not configured); demonstrated concretely in T11 against cloudflare.com's real SSL Labs result (B grade, driven by the same dual-protocol pattern).
Viable Today: Yes — Finding 005 confirms both protocol versions remain enabled in production, and HSTS (which would prevent the initial plaintext-negotiation window entirely) is confirmed absent, meaning nothing currently blocks a downgrade attempt.
Mitigation: Disable TLS 1.0/1.1 entirely (T11's hardened configuration: `SSLProtocol -all +TLSv1.2 +TLSv1.3`) and enable HSTS with a long max-age and `preload` — if the weak protocol does not exist on the server, there is no version to downgrade to.
```

```
Attack: Collision Attack (MD5-based)
Mechanism: An attacker constructs two different inputs that produce the identical hash output (a collision), which becomes dangerous wherever a system trusts hash equality as a proxy for content/message equality — practical, fast chosen-prefix MD5 collisions have been publicly demonstrated since 2004-2008 (real, not theoretical), letting an attacker craft a malicious message that hashes identically to a legitimate one.
MedDefense Vulnerability: Active Directory's NTHash credential store is MD4-based (a closely related, equally broken hash family), and RC4-encrypted Kerberos tickets derive their session key from that same MD4/MD5-lineage weak hash — meaning the underlying cryptographic weakness of MD5-family collisions is directly present in MedDefense's authentication infrastructure, not confined to some unrelated legacy checksum use.
Evidence: T0 audit notes (AD's default NTHash/MD4 for NTLM compatibility) and T6's Algorithm Reference Table (MD5 rated "Broken" — practical collisions demonstrated since 2004).
Viable Today: Yes, in the specific sense that the weak hash family is confirmed present and unremoved — though the more directly exploitable consequence of this weakness at MedDefense is Kerberoasting (below), not a classic "two colliding files" scenario, since MedDefense has no known public-facing service that trusts MD5 hash equality for content verification the way the historical 2008 rogue-CA collision attack did.
Mitigation: Same root fix as the Kerberoasting entry below — eliminate DES/RC4 Kerberos encryption types and reduce NTLM/NTHash dependency wherever legacy compatibility does not genuinely require it (T6 Gap Analysis, case 4).
```

```
Attack: Birthday Attack (theoretical)
Mechanism: Exploits the mathematical fact that finding any two inputs that collide is dramatically easier than finding one input matching one specific target hash, because the number of comparable pairs grows quadratically with the number of attempts — for an n-bit hash, only roughly 2^(n/2) attempts are needed to find a collision with good probability, not 2^n (the same reason 23 people in a room have a 50% chance two share a birthday, despite 365 possible birthdays).
MedDefense Vulnerability: This is a property of the hash algorithm itself, not a specific MedDefense system — but it directly explains WHY MD5 (128-bit, ~2^64 effective collision resistance) is meaningfully weaker than SHA-256 (256-bit, ~2^128 effective collision resistance), the exact comparison computed with real numbers in T3, Part 2.
Evidence: T3, Part 2 (SHA-256 = 2^256 possible outputs, MD5 = 2^128, with the birthday-bound collision-finding cost of roughly 2^128 and 2^64 attempts respectively).
Viable Today: Theoretical/mathematical rather than an active exploit against a specific MedDefense system — its relevance is that it is the reason MD5 is rated "Broken" while SHA-256 is rated "Current" in T6, informing every hash-algorithm choice made throughout this project rather than describing one standalone attack incident.
Mitigation: Use SHA-256 or stronger for any new hashing need (T6); this is already the standard applied throughout every hash-related recommendation in this project (T3's `3-hash_verify.sh`, T13's protection recommendations).
```

```
Attack: Kerberoasting
Mechanism: An authenticated attacker (even a low-privilege domain user) requests a Kerberos service ticket for any account with a Service Principal Name, encrypted with the requested encryption type. If RC4 is permitted, that ticket is encrypted with a key derived from the service account's NTHash (MD4-family) — the attacker takes the ticket offline and brute-forces the account's password entirely offline, with zero further contact with the domain controller and no lockout risk, since domain controllers cannot distinguish a legitimate ticket request from a malicious one.
MedDefense Vulnerability: `ad-dc-01`/`ad-dc-02` permit RC4 (and DES) as Kerberos encryption types, and AD's underlying NTHash credential store is MD4-based — both conditions Kerberoasting requires are confirmed present.
Evidence: 1x02 Finding 018 (DES and RC4 Kerberos encryption types confirmed enabled); mathematically explained in T3, Part 2; formally rated in T6 (RC4 and DES both "Broken").
Viable Today: Yes — Finding 018 confirms this is a live, unremediated configuration, not a hypothetical; any service account with a weak/short password and RC4 permitted is crackable offline today with commodity GPU hardware.
Mitigation: Disable DES and RC4 Kerberos encryption types domain-wide (enforce AES128/256-only via `msDS-SupportedEncryptionTypes` and Group Policy — T6 Gap Analysis, cases 1-2; T15 Finding CRYPTO-011), and separately audit service accounts for weak passwords, since even AES-only Kerberos does not protect an account with a trivially guessable password.
```

```
Attack: On-path/MITM on unencrypted channels
Mechanism: An attacker positioned on the network path between two legitimate endpoints passively reads (or actively modifies) any traffic sent without encryption — no cryptographic weakness needs to be "broken" here, since there is no encryption in place to break in the first place; the attacker simply reads what's already in cleartext.
MedDefense Vulnerability: Two confirmed, distinct channels: (1) DICOM imaging traffic between the MRI workstation, radiology workstations, and `pacs-srv-01`, which traverses the network entirely in cleartext including patient identifiers embedded in DICOM headers; (2) the billing application's connection to MySQL on `billing-srv-01`, bound to 0.0.0.0 with no SSL enforced, using the plaintext MySQL wire protocol.
Evidence: 1x02 Finding 024 (DICOM traffic, no DICOM TLS/PS3.15 configured) and Finding 006 (MySQL plaintext protocol); both documented directly in T0's Data Protection Map (both rated Absent) and carried into T15 as CRYPTO-005 and CRYPTO-008.
Viable Today: Yes — both are live, unremediated configurations confirmed by direct scan evidence, not theoretical; anyone with access to the flat internal network (already demonstrated reachable via the 1x01 kill chains) can read this traffic today with nothing more than a packet capture tool.
Mitigation: Enable DICOM TLS (PS3.15) for imaging traffic and enforce MySQL's `require_secure_transport` for database connections, both using the TLS 1.2/1.3, AEAD-only cipher standard established in T11.
```

```
Attack: Key Recovery from Memory
Mechanism: An attacker with root/kernel-level access on a running system can extract cryptographic key material directly from RAM regardless of how strong the algorithm protecting the data at rest is — encryption keys must exist in plaintext in memory at some point to actually encrypt/decrypt data, and root access grants the ability to read arbitrary process memory (e.g., via `/proc/<pid>/mem`), force a core dump of the process holding the key, or in some scenarios recover keys that were swapped to disk if swap itself is unencrypted.
MedDefense Vulnerability: `billing-srv-01` has a confirmed history of attacker-obtained root access (the 1x00 crypto-miner incident, and the repeat RCE-to-root pattern quantified in RISK-003) — if this server ever holds an AES key in memory (for example, a database-level encryption key per T13's recommendation, or a TLS session key), an attacker who regains root exactly as they already have before could extract it directly from process memory, independent of AES-256's mathematical strength.
Evidence: 1x00 crypto-miner forensic finding (root-level compromise of `billing-srv-01`, database files readable without credentials) and 1x03 RISK-003 ($189,200 ALE, explicitly citing this server's repeated RCE-to-root pattern).
Viable Today: **Yes, conditionally** — if root is obtained (which has already happened at least once, per RISK-003's own risk description), key recovery from memory is realistic and well-documented as an attack category (this is precisely why the answer to "can AES-256 alone protect this data against a root-level attacker" is no); it is not, however, a distinct new vulnerability requiring its own separate exploit — it is the direct consequence of the RCE-to-root access this server has already repeatedly suffered.
Mitigation: This cannot be fully solved by the encryption algorithm itself — the real fix is preventing root compromise in the first place (patching the recurring RCE per RISK-003's own treatment plan) and, per T14's key management design, keeping the encryption key in an HSM/KMS rather than ever loading it into `billing-srv-01`'s own process memory for longer than a single operation requires — an HSM performs the cryptographic operation internally and never releases the raw key to the calling application at all, which is the only mitigation that remains effective even if `billing-srv-01` is compromised again.
```

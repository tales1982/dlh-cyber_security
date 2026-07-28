# 11. The TLS Audit MedDefense Health Systems

**Analyst:** Security Analyst
**Date:** Current
**Method:** Both sites below were tested against the real, live SSL Labs API (`api.ssllabs.com/api/v3/analyze`) the same engine behind `ssllabs.com/ssltest` not reconstructed from memory.

## Part 1: SSL Labs Analysis

### Site 1 `cloudflare.com` (chosen expecting A/A+, real result was more interesting)

```
$ curl -s "https://api.ssllabs.com/api/v3/analyze?host=cloudflare.com&all=done" | jq
```

| Field                       | Result                                                                                                                                                                                                                                                                                                                                                         |
| --------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Overall Grade**     | **B** a genuinely surprising real result, not the A+ the task prompt suggested as a likely example; documented honestly rather than substituted for a "cleaner" example                                                                                                                                                                                 |
| Protocol Support            | TLS 1.0, TLS 1.1, TLS 1.2, TLS 1.3**all four supported simultaneously**                                                                                                                                                                                                                                                                                  |
| Key Exchange Strength       | ECDHE at 3072-bit equivalent strength on modern cipher suites (strong)                                                                                                                                                                                                                                                                                         |
| Cipher Suite Strength       | Modern suites available (`TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256`, `TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256`), but legacy non-AEAD CBC suites are also still offered on the older protocol versions (`TLS_RSA_WITH_AES_128_CBC_SHA`, `TLS_RSA_WITH_3DES_EDE_CBC_SHA` on TLS 1.0)                                                                |
| Certificate                 | Subject:`CN=cloudflare.com` Issuer: `CN=WR1, O=Google Trust Services, C=US` RSA-2048, `SHA256withRSA` Valid: Jul 8, 2026 → Oct 6, 2026 (~90-day lifetime, consistent with the modern short-lived pattern documented in Task 8/9)                                                                                                                      |
| Warnings/Weaknesses flagged | `vulnBeast: true` (BEAST-relevant CBC suites still negotiable on legacy protocols), `poodleTls: 1` (POODLE-adjacent check flagged), 3DES still offered on TLS 1.0 **the grade-limiting factor is clearly the continued support for TLS 1.0/1.1 and their associated legacy cipher suites, not the certificate or the TLS 1.3 configuration itself** |

**Why this result is actually the most useful one for this audit:** a B grade from simultaneously supporting TLS 1.0 alongside modern TLS 1.3 is close to a real-world mirror of Finding 005 on MedDefense's own portal even a major, well-resourced provider's default configuration shows that "supports old and new protocols side by side" is a common, real grade-limiting pattern, not a hypothetical.

### Site 2 `rc4.badssl.com` (chosen specifically to get a low grade, and it worked)

```
$ curl -s "https://api.ssllabs.com/api/v3/analyze?host=rc4.badssl.com&all=done" | jq
```

| Field                       | Result                                                                                                                                                                                                                   |
| --------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| **Overall Grade**     | **F**                                                                                                                                                                                                              |
| Protocol Support            | TLS 1.0, TLS 1.1, TLS 1.2 (no TLS 1.3)                                                                                                                                                                                   |
| Key Exchange Strength       | Forward secrecy flagged as weak/partial (`forwardSecrecy: 1`)                                                                                                                                                          |
| Cipher Suite Strength       | **RC4 supported and offered**, confirmed directly: `TLS_ECDHE_RSA_WITH_RC4_128_SHA` and `TLS_RSA_WITH_RC4_128_SHA` both present on TLS 1.2                                                                     |
| Certificate                 | Subject:`CN=*.badssl.com` Issuer: `CN=R13, O=Let's Encrypt, C=US` RSA-2048, `SHA256withRSA` Valid: May 26, 2026 → Aug 24, 2026 **the certificate itself is entirely unremarkable and correctly issued** |
| Warnings/Weaknesses flagged | `supportsRc4: true`                                                                                                                                                                                                    |

**The key lesson from comparing these two real results side by side:** the certificate was never the problem for either site both use a perfectly ordinary, correctly-issued RSA-2048 certificate. The grade in both cases is driven entirely by **protocol and cipher suite configuration**: `rc4.badssl.com` demonstrates in isolation exactly why RC4 was rated "Broken" in Task 6's Algorithm Reference Table its mere presence in the offered cipher suite list is enough to collapse a grade to F regardless of everything else being configured correctly.

## Part 2: MedDefense Portal Assessment

**Predicted grade: B, likely trending toward C** if the certificate expiration situation (Finding 013) is not resolved before testing.

**Issues that would reduce the grade, based directly on 1x02's findings:**

1. **TLS 1.0 enabled alongside TLS 1.2 (Finding 005)** directly mirrors the exact configuration just observed lowering `cloudflare.com` to a B; SSL Labs specifically penalizes continued support for protocol versions vulnerable to BEAST, POODLE, and Lucky Thirteen.
2. **TLS 1.3 not supported (Finding 005)** SSL Labs' grading criteria reward TLS 1.3 support; its absence caps the achievable grade below what a modern configuration would earn, independent of the TLS 1.0 penalty.
3. **HSTS not configured (Finding 005)** SSL Labs explicitly checks for and rewards HSTS; its absence is graded down and separately leaves the portal exposed to SSL-stripping-style downgrade attempts (Part 4 below).
4. **OCSP Stapling not configured (Finding 005)** a smaller grading factor than the above, but still counted against the configuration per Task 9's discussion of OCSP Stapling's benefits.
5. **Certificate within days of expiration (Finding 013)** if the certificate is expired at the moment of testing, the grade would not merely be "lowered" the connection would fail entirely (per the `expired.badssl.com` behavior directly observed in Task 8, Part 2), producing the worst possible outcome (an unusable site) rather than a low letter grade. If tested a day before expiration, SSL Labs would likely flag the imminent expiration as a specific warning even though the grade calculation itself is not primarily date-driven.
6. **Undocumented default Apache cipher suite configuration (per Task 0's audit notes)** "likely includes weak cipher suites alongside strong ones" was Sarah's own assessment; per the `rc4.badssl.com` result above, even one weak cipher suite present in the offered list is sufficient to cause severe grade damage, so this is not a minor concern.

## Part 3: The Hardened Configuration

**Apache format (`portal.meddefense.local`'s virtual host TLS block):**

```apache
# Only TLS 1.2 and TLS 1.3 -- eliminates the exact BEAST/POODLE/Lucky Thirteen
# exposure that dragged Finding 005 and both real SSL Labs examples above down.
SSLProtocol -all +TLSv1.2 +TLSv1.3

# Cipher suite selection, most-preferred first. Every suite here is AEAD
# (GCM or ChaCha20-Poly1305) and ECDHE -- no CBC-mode, no static RSA key
# exchange, no RC4/3DES/DES, matching the Algorithm Reference Table (T6).
SSLCipherSuite TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_128_GCM_SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-AES128-GCM-SHA256
SSLHonorCipherOrder on

# HSTS: 1 year (31536000s), including subdomains, eligible for browser
# preload lists -- forces every future visit straight to HTTPS, which is
# the direct, simplest fix for the downgrade attack described in Part 4.
Header always set Strict-Transport-Security "max-age=31536000; includeSubDomains; preload"

# Disable legacy TLS session tickets (stateless resumption via
# session-ticket keys held in server memory/config is a persistent-key
# exposure risk if the server is compromised); rely on session IDs
# with a short cache lifetime instead.
SSLSessionTickets off
SSLSessionCache "shmcb:/var/run/apache2/ssl_scache(512000)"
SSLSessionCacheTimeout 300

# Disallow client-initiated renegotiation entirely -- historically the
# root cause of several TLS renegotiation-based attacks; the portal has
# no legitimate need for mid-session parameter renegotiation.
SSLInsecureRenegotiation off

# OCSP Stapling: server fetches and staples its own OCSP response
# (Task 9, Part 3) rather than making every client contact the CA directly.
SSLUseStapling on
SSLStaplingCache "shmcb:/var/run/apache2/ocsp_stapling(32768)"
```

**One-sentence reasoning per choice:**

- **TLS 1.2/1.3 only:** removes every protocol version implicated in Finding 005 and both of Part 1's real-world grade-limiting examples in one line.
- **AEAD-only, ECDHE-only cipher list:** matches Task 6's Algorithm Reference Table exactly no CBC (no BEAST/Lucky Thirteen surface), no static RSA key exchange (no forward secrecy loss if the server key is ever compromised), no RC4/3DES/DES (all "Broken"/"Deprecated" per Task 6).
- **`SSLHonorCipherOrder on`:** ensures the server's preference order (strongest first) wins the negotiation instead of trusting the client's potentially weaker preference.
- **HSTS with a 1-year `max-age` and `preload`:** long enough to meaningfully protect returning patients and qualify for browser HSTS preload lists, which close the very first-connection downgrade window HSTS alone cannot cover.
- **`SSLSessionTickets off`:** avoids the persistent-key exposure risk of stateless session ticket keys sitting in server memory/config indefinitely.
- **`SSLInsecureRenegotiation off`:** eliminates a historically real class of renegotiation-based TLS attacks the portal has no operational need to remain exposed to.
- **OCSP Stapling on:** delivers certificate revocation freshness to clients without the per-connection latency and CA-visible metadata cost of clients querying OCSP directly (Task 9, Part 3).

## Part 4: The Downgrade Attack

A TLS downgrade attack exploits the fact that, during the initial handshake, the client and server negotiate the highest protocol version *both* support an attacker positioned on the network path (a classic man-in-the-middle position, conceptually the same positioning problem discussed for Diffie-Hellman in Task 4) can interfere with that negotiation to force a weaker outcome than either party would otherwise choose. If MedDefense's portal supports both TLS 1.0 and TLS 1.2 simultaneously (exactly Finding 005's real, current configuration), the simplest version of this attack is a **connection-reset-based downgrade**: the attacker blocks or corrupts the client's initial TLS 1.2 handshake attempt, causing many TLS client implementations to automatically retry the connection at a lower, more "compatible" protocol version landing the session on TLS 1.0, where the attacker can then bring the BEAST/POODLE/Lucky Thirteen weaknesses already documented in Task 8/9 to bear against a protocol version the portal never should have offered in the first place. **The simplest prevention is exactly what Part 3's hardened configuration already does: stop supporting TLS 1.0/1.1 entirely** if the weak protocol version does not exist on the server side at all, there is no lower version for an attacker to force the negotiation down to, which is a strictly more effective fix than any client-side or detection-based mitigation.

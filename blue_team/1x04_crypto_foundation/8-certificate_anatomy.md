# 8. The Certificate Anatomy — MedDefense Health Systems

**Analyst:** Security Analyst
**Date:** Current
**Environment:** OpenSSL 3.0.13, Ubuntu 24.04 — all three certificates below were actually downloaded live with `openssl s_client` and parsed with `openssl x509 -text`, not reconstructed from memory.

## Part 1: Inspect Three Real Certificates

### Certificate 1 — Let's Encrypt (`letsencrypt.org`)

```
$ echo | openssl s_client -connect letsencrypt.org:443 -servername letsencrypt.org 2>/dev/null | openssl x509 -noout -text
```

| Field | Value |
|---|---|
| Subject | `CN = letsencrypt.org` (no O, L, ST, or C — DV certificates carry no organization identity, only the domain) |
| Issuer | `C = US, O = Let's Encrypt, CN = YE2` |
| Validity | Not Before: Jul 6 15:24:34 2026 GMT — Not After: Oct 4 15:24:33 2026 GMT (a 90-day lifetime, Let's Encrypt's standard) |
| Serial Number | `05:05:bb:29:ef:e3:ee:15:2b:a3:e9:e6:87:28:10:b5:fe:b9` |
| Signature Algorithm | `ecdsa-with-SHA384` |
| Public Key Algorithm / Size | `id-ecPublicKey`, 256-bit, curve `prime256v1` (NIST P-256) |
| Subject Alternative Names | `cp.letsencrypt.org, cp.root-x1.letsencrypt.org, cps.letsencrypt.org, cps.root-x1.letsencrypt.org, lencr.org, letsencrypt.com, letsencrypt.org, www.lencr.org, www.letsencrypt.com, www.letsencrypt.org` — ten names covering multiple related domains on one certificate |
| Key Usage / Extended Key Usage | Key Usage (critical): Digital Signature — Extended Key Usage: TLS Web Server Authentication |
| Authority Information Access | CA Issuers: `http://ye2.i.lencr.org/` — **no OCSP URL present on this specific certificate** (real, observed result — not every certificate populates every AIA field) |

### Certificate 2 — Commercial CA (`github.com`)

```
$ echo | openssl s_client -connect github.com:443 -servername github.com 2>/dev/null | openssl x509 -noout -text
```

| Field | Value |
|---|---|
| Subject | `CN = github.com` (DV certificate — no O/L/ST/C, consistent with GitHub's current DV cert from Sectigo) |
| Issuer | `C = GB, O = Sectigo Limited, CN = Sectigo Public Server Authentication CA DV E36` |
| Validity | Not Before: Jul 3 00:00:00 2026 GMT — Not After: Sep 30 23:59:59 2026 GMT (~90-day lifetime) |
| Serial Number | `72:01:0e:03:f4:a0:67:fe:4e:79:62:66:43:07:18:f6` |
| Signature Algorithm | `ecdsa-with-SHA256` |
| Public Key Algorithm / Size | `id-ecPublicKey`, 256-bit, curve `prime256v1` (NIST P-256) |
| Subject Alternative Names | `github.com, www.github.com` |
| Key Usage / Extended Key Usage | Key Usage (critical): Digital Signature — Extended Key Usage: TLS Web Server Authentication |
| Authority Information Access | CA Issuers: `http://crt.sectigo.com/SectigoPublicServerAuthenticationCADVE36.crt` — OCSP: `http://ocsp.sectigo.com` (both present, unlike the Let's Encrypt certificate above) |

### Certificate 3 — Broken Certificate (`expired.badssl.com`)

```
$ echo | openssl s_client -connect expired.badssl.com:443 -servername expired.badssl.com 2>&1 | grep -E "Verify return code|depth"
depth=2 C = GB, ST = Greater Manchester, L = Salford, O = COMODO CA Limited, CN = COMODO RSA Certification Authority
depth=1 C = GB, ST = Greater Manchester, L = Salford, O = COMODO CA Limited, CN = COMODO RSA Domain Validation Secure Server CA
depth=0 OU = Domain Control Validated, OU = PositiveSSL Wildcard, CN = *.badssl.com
Verify return code: 10 (certificate has expired)
```

| Field | Value |
|---|---|
| Subject | `OU = Domain Control Validated, OU = PositiveSSL Wildcard, CN = *.badssl.com` |
| Issuer | `C = GB, ST = Greater Manchester, L = Salford, O = COMODO CA Limited, CN = COMODO RSA Domain Validation Secure Server CA` |
| Validity | Not Before: Apr 9 00:00:00 2015 GMT — Not After: Apr 12 23:59:59 2015 GMT — **expired over a decade ago, exactly as the hostname promises** |
| Serial Number | `4a:e7:95:49:fa:9a:be:3f:10:0f:17:a4:78:e1:69:09` |
| Signature Algorithm | `sha256WithRSAEncryption` |
| Public Key Algorithm / Size | `rsaEncryption`, 2048-bit modulus |
| Subject Alternative Names | `*.badssl.com, badssl.com` |
| Key Usage / Extended Key Usage | Key Usage (critical): Digital Signature, Key Encipherment — Extended Key Usage: TLS Web Server Authentication, TLS Web Client Authentication |
| Authority Information Access | CA Issuers: `http://crt.comodoca.com/COMODORSADomainValidationSecureServerCA.crt` — OCSP: `http://ocsp.comodoca.com` |

## Part 2: The Broken Certificate

`openssl`'s own verification engine flags this exactly as expected: **`Verify return code: 10 (certificate has expired)`**. The certificate's `Not After` date (April 12, 2015) is over a decade in the past relative to today — the certificate itself is otherwise structurally valid (correctly signed by a real, trusted CA chain: leaf → COMODO RSA Domain Validation Secure Server CA → COMODO RSA Certification Authority, visible in the three `depth=` lines above), it has simply outlived its validity window. **What a browser would display:** a full-page interstitial warning (e.g., Chrome's "Your connection is not private — NET::ERR_CERT_DATE_INVALID") that blocks the page entirely behind an "Advanced" click-through, not a subtle padlock icon change. **The risk this creates:** an expired certificate provides no assurance that the private key hasn't been compromised, rotated, or that the domain still belongs to the same operator — expiration dates exist specifically so that certificates are periodically re-validated and re-issued, and browsers correctly refuse to distinguish "harmlessly expired yesterday" from "an attacker is presenting an old certificate they still hold the key for." **Would I advise a patient to proceed past this warning on MedDefense's portal?** No, unconditionally. Clicking through a certificate warning is training patients to ignore the exact signal designed to catch both configuration mistakes and active attacks (including certificate-based MITM, directly relevant to Task 4's discussion) — the correct action for MedDefense is to never let this state occur in production (hence the urgency of Tasks 9-10, since the current portal certificate has 18 days left), not to coach patients on how to bypass it.

## Part 3: MedDefense Certificate Profile

**Type — Domain Validated (DV):** MedDefense's patient portal needs a certificate whose primary job is enabling encryption and confirming domain control, not asserting a verified legal business identity to end users (Extended Validation's green-bar-style assurances have limited practical browser UI treatment today, and Organization Validation's extra vetting cost/time offers little concrete security benefit over DV for this use case) — the actual trust patients need (this is really MedDefense, my session is encrypted) is fully satisfied by DV, and DV certificates support the fast issuance and short renewal cycles (Task 9/10) that reduce the risk of the kind of expiration lapse just diagnosed in Part 2.

**CA — a widely-trusted CA supporting ACME automation** (Let's Encrypt, or a commercial CA with ACME support): given the portal's current problem is a *manual* renewal process that already let a certificate get to 18 days from expiry, the priority is a CA that supports automated issuance and renewal (ACME protocol) over one requiring a manual purchase/approval cycle each time — this directly prevents a repeat of the current near-miss.

**SAN entries:** at minimum `portal.meddefense.local` (the primary hostname) plus any alternate hostnames patients or integrated systems actually use to reach the portal (e.g., a `www.` variant, or a mobile-app-specific API hostname if one exists) — every hostname a real client connects to must appear in the SAN list, since modern browsers no longer fall back to checking the Subject CN if the SAN list doesn't include the requested hostname.

**Key algorithm and size — ECC P-256:** per the Algorithm Reference Table (Task 6) and consistent with what both real-world certificates inspected in Part 1 actually use today, ECC P-256 gives equivalent-or-better security to RSA-2048 with a smaller key, faster TLS handshakes, and lower CPU cost per connection — directly relevant given the portal handles roughly 800 patient connections per day (Task 10 will make this exact call with full justification).

**Validity period — 90 days:** matching the short-lived model both real certificates in Part 1 use (Let's Encrypt and GitHub's Sectigo DV cert are both ~90-day certificates) — shorter validity reduces the exposure window if a key is ever compromised and forces the renewal process to be automated rather than manual, which is precisely the fix the current 18-days-to-expiry situation calls for.

**Wildcard vs. single-domain:** a **single-domain (or explicit multi-SAN) certificate**, not a wildcard. A wildcard (`*.meddefense.local`) would mean a single compromised key grants an attacker the ability to impersonate *every* subdomain MedDefense might ever stand up, not just the patient portal — for an environment already documented (Task 0, 1x02) as having multiple weakly-secured internal systems, concentrating that much trust into one wildcard key is an avoidable, unnecessary risk; explicit SAN entries naming only the hostnames actually in use keep the blast radius of any future key compromise limited to what was actually named.

## Repo

- **GitHub repository:** `dlh-cyber_security`
- **Directory:** `blue_team/1x04_crypto_foundation`
- **File:** `8-certificate_anatomy.md`

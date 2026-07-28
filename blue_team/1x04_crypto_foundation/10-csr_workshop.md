# 10. The CSR Workshop — MedDefense Health Systems

**Analyst:** Security Analyst
**Date:** Current
**Environment:** OpenSSL 3.0.13, Ubuntu 24.04 — key, CSR, and inspection below were all actually generated and executed.

## Part 1: Key Generation Decision

**Decision: ECC P-256.** RSA-2048 and RSA-4096 both remain acceptable per the Algorithm Reference Table (Task 6), but ECC P-256 is the better fit specifically for this server: it delivers security equivalent to RSA-3072 (comfortably above RSA-2048) while requiring dramatically less CPU per TLS handshake, which matters directly for a server handling roughly 800 patient connections per day — each handshake's asymmetric operation is cheaper, so the server spends less CPU time per connection and can handle traffic spikes (e.g., after an appointment-reminder email blast) with more headroom. Compatibility is not a practical concern here: ECC P-256 has been supported by every browser and OS TLS stack in mainstream use since the early 2010s, and MedDefense's own Task 8 inspection confirmed that both Let's Encrypt and GitHub's commercial Sectigo certificate already use exactly this algorithm and curve today — this is not a bleeding-edge choice, it is the current default for modern web TLS. RSA-4096 was considered but rejected for this specific certificate because its larger signature/key size adds handshake overhead for no practical security benefit over P-256 at this trust level; RSA-4096 remains the right choice elsewhere in this project (Task 6) for long-lived internal CA root material, which is a different risk/performance trade-off than a high-traffic, frequently-renewed leaf certificate.

**Key generation, executed:**
```
$ openssl ecparam -genkey -name prime256v1 -out portal_key.pem
```
Result: a 302-byte private key file (`portal_key.pem`), matching the same P-256 key size observed and documented in Task 2's ECC lab.

## Part 2: CSR Generation

**Configuration file used (`openssl.cnf`):**
```
[ req ]
default_bits       = 256
prompt             = no
default_md         = sha256
distinguished_name = dn
req_extensions     = req_ext

[ dn ]
CN = portal.meddefense.local
O  = MedDefense Health Systems
OU = Information Technology
L  = Springfield
ST = Illinois
C  = US

[ req_ext ]
subjectAltName = @alt_names

[ alt_names ]
DNS.1 = portal.meddefense.local
DNS.2 = www.portal.meddefense.local
DNS.3 = patientportal.meddefense.local
```

*Note on the fields:* Locality/State were set to a representative MedDefense headquarters location (Springfield, Illinois, US) for this exercise since the audit notes and prior projects establish MedDefense as a US healthcare organization but do not specify an exact registered address — in a real submission this would be the organization's actual legally registered address, since CAs performing Organization Validation would check it against public records. Two additional SAN entries beyond the primary CN were included: a `www.` variant (common browser habit of typing the prefix) and `patientportal.meddefense.local` (a plausible alternate hostname patients or a mobile app might use) — per Task 8's finding, any hostname a real client connects to must be present in the SAN list or modern browsers will reject the certificate outright regardless of what the CN says.

**Command executed:**
```
$ openssl req -new -key portal_key.pem -out portal.csr -config openssl.cnf
```
Result: a 700-byte CSR file (`portal.csr`).

## Part 3: CSR Inspection

```
$ openssl req -text -noout -in portal.csr
```
**Actual output:**
```
Certificate Request:
    Data:
        Version: 1 (0x0)
        Subject: CN = portal.meddefense.local, O = MedDefense Health Systems, OU = Information Technology, L = Springfield, ST = Illinois, C = US
        Subject Public Key Info:
            Public Key Algorithm: id-ecPublicKey
                Public-Key: (256 bit)
                ASN1 OID: prime256v1
                NIST CURVE: P-256
        Attributes:
            Requested Extensions:
                X509v3 Subject Alternative Name:
                    DNS:portal.meddefense.local, DNS:www.portal.meddefense.local, DNS:patientportal.meddefense.local
    Signature Algorithm: ecdsa-with-SHA256
```
Every field is confirmed correct: Common Name matches the portal's actual hostname, Organization/OU/Locality/State/Country match the intended MedDefense identity fields, the public key is confirmed as a 256-bit P-256 EC key (matching the Part 1 decision), and — critically — **all three SAN entries are present and correctly formatted as DNS names**, satisfying the requirement that broke wildcard-vs-explicit reasoning in Task 8, Part 3.

## Part 4: The Full Lifecycle

1. **CSR generated** (done above) — the CSR contains the public key and identity fields but not the private key itself, which never leaves `web-srv-01`.
2. **Submission to CA:** submit to a CA supporting **ACME automation** (Let's Encrypt, or a commercial CA offering an ACME-compatible endpoint) rather than a manual-approval commercial CA — directly motivated by Task 9 Part 3's finding that MedDefense's current manual renewal process is what let the existing certificate reach 18 days from expiry in the first place.
3. **Validation process:** for a Domain Validated certificate (the type recommended in Task 8, Part 3), the CA verifies **domain control only** — typically via an HTTP-01 challenge (placing a CA-specified file at a well-known path on `web-srv-01`) or a DNS-01 challenge (publishing a CA-specified TXT record on `meddefense.local`'s DNS zone) — no organizational/legal identity vetting occurs for DV, which is why issuance is fast and automatable.
4. **Certificate issuance:** upon successful challenge validation, the CA signs the CSR's public key and identity fields, returning a signed certificate chained to its intermediate (per the chain structure demonstrated in Task 9, Part 1).
5. **Installation on the web server:** deploy the new leaf certificate **and** the CA's intermediate certificate together on `web-srv-01`'s Apache TLS configuration (Task 9, Part 2 demonstrated concretely why omitting the intermediate breaks verification for any client that doesn't already independently hold it) alongside the existing `portal_key.pem` private key, then reload (not just restart, to avoid a connection-dropping outage) the web server process.
6. **Verification that the new certificate is serving correctly:** repeat the exact `openssl s_client -connect portal.meddefense.local:443 -servername portal.meddefense.local -showcerts` inspection technique from Tasks 8-9 against the live production endpoint, confirming the new certificate (not the old one) is being served, the full chain is present, the SAN list matches what was requested, and `openssl verify` returns `OK` against the system/CA trust store.
7. **Decommission of the old certificate:** once the new certificate is confirmed live and functioning for real patient traffic, request revocation of the old certificate from its original issuing CA (even though it would otherwise simply expire soon) — this closes the window during which both the old and new certificates would technically validate, minimizing the exposure if the old private key was ever handled insecurely. Securely delete the old private key from `web-srv-01` once confirmed no longer needed.
8. **Monitoring for the next renewal:** configure automated expiration monitoring (an alert well before the ~90-day validity period elapses — e.g., at the 60-day and 75-day marks) tied to the SIEM/monitoring capability referenced in the 1x03 strategy, and — since an ACME-compatible CA was chosen in step 2 — configure automated renewal (e.g., via `certbot` or an equivalent ACME client) so this entire lifecycle repeats without manual intervention, directly preventing a repeat of the near-miss that made this task urgent in the first place.

## Repo

- **GitHub repository:** `dlh-cyber_security`
- **Directory:** `blue_team/1x04_crypto_foundation`
- **File:** `10-generate_csr.sh`, `10-csr_workshop.md`

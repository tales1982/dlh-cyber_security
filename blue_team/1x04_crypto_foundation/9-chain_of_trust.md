# 9. The Chain of Trust MedDefense Health Systems

**Analyst:** Security Analyst
**Date:** Current
**Environment:** OpenSSL 3.0.13, Ubuntu 24.04 all commands and outputs below were actually executed against the live `github.com` TLS endpoint and this machine's real trust store.

## Part 1: Capture the Full Chain

```
$ echo | openssl s_client -connect github.com:443 -servername github.com -showcerts 2>/dev/null > github_chain_raw.txt
$ grep -c "BEGIN CERTIFICATE" github_chain_raw.txt
3
```

**The chain contains 3 certificates**, split into separate files (`github_leaf.pem`, `github_intermediate.pem`, `github_root.pem`):

| Position             | Role                                                                      | Subject                                                                              | Issuer                                                                                                              |
| -------------------- | ------------------------------------------------------------------------- | ------------------------------------------------------------------------------------ | ------------------------------------------------------------------------------------------------------------------- |
| 0 (leaf)             | End-entity certificate the one presented for`github.com` itself        | `CN = github.com`                                                                  | `C = GB, O = Sectigo Limited, CN = Sectigo Public Server Authentication CA DV E36`                                |
| 1 (intermediate)     | Intermediate CA signs end-entity certificates on behalf of the root      | `C = GB, O = Sectigo Limited, CN = Sectigo Public Server Authentication CA DV E36` | `C = GB, O = Sectigo Limited, CN = Sectigo Public Server Authentication Root E46`                                 |
| 2 (served as "root") | A further CA certificate the server sends to help clients build the chain | `C = GB, O = Sectigo Limited, CN = Sectigo Public Server Authentication Root E46`  | `C = US, ST = New Jersey, L = Jersey City, O = The USERTRUST Network, CN = USERTrust ECC Certification Authority` |

**Each Issuer matches the next Subject exactly** the leaf's Issuer (`Sectigo Public Server Authentication CA DV E36`) is precisely the Subject of certificate 1; certificate 1's Issuer (`Sectigo Public Server Authentication Root E46`) is precisely the Subject of certificate 2. This is the mechanical link that lets a client walk the chain upward one certificate at a time.

**An honest observation worth documenting rather than glossing over:** certificate 2, despite being the last one the server sends, is **not actually self-signed** its own Issuer is `USERTrust ECC Certification Authority`, a separate CA not included in what the server sent. Checking it directly confirms this:

```
$ openssl x509 -in github_root.pem -noout -subject -issuer
subject=C = GB, O = Sectigo Limited, CN = Sectigo Public Server Authentication Root E46
issuer=C = US, ST = New Jersey, L = Jersey City, O = The USERTRUST Network, CN = USERTrust ECC Certification Authority
```

This is a real, common real-world pattern: servers frequently send a cross-signed intermediate/root bundle rather than the true self-signed trust anchor, relying on the client's own trust store to already hold whichever certificate closes the chain (in this case, `USERTrust ECC Certification Authority`, confirmed present in this system's trust store in Part 4 below).

## Part 2: Manual Chain Verification

**Full chain, verified successfully:**

```
$ cat github_intermediate.pem github_root.pem > github_chain.pem
$ openssl verify -untrusted github_chain.pem github_leaf.pem
github_leaf.pem: OK
```

**Now with the intermediate removed, using only the served "root" certificate:**

```
$ openssl verify -untrusted github_root.pem github_leaf.pem
CN = github.com
error 20 at 0 depth lookup: unable to get local issuer certificate
error github_leaf.pem: verification failed
```

**What this demonstrates:** removing the intermediate certificate breaks verification even though a further certificate up the chain (`github_root.pem`) was still supplied `openssl verify` needs the *direct* issuer of the leaf certificate to build a continuous, unbroken path, and skipping straight to a certificate further up the chain does not substitute for it, no matter how legitimate that further certificate is. This is exactly why web servers must be configured to send the intermediate certificate(s) alongside the leaf: a client's local trust store holds root CAs, not the countless intermediate CAs issued beneath them, so if the server omits the intermediate, most real-world browsers and clients (which are considerably less forgiving than manually retrying with different files, as done here) will simply fail the connection with an incomplete-chain error a common, real misconfiguration distinct from every other certificate problem covered in Task 8.

## Part 3: Revocation Mechanisms

**CRL (Certificate Revocation List):** a CRL is a periodically-published, digitally-signed list of every certificate a CA has revoked before its natural expiration, identified by serial number, along with a revocation timestamp and reason. A client checking a certificate's status downloads the CA's current CRL (from the URL in the certificate's `CRL Distribution Points` extension visible in both the Let's Encrypt and badssl.com certificates inspected in Task 8) and checks whether the presented certificate's serial number appears on it. **Main limitation:** CRLs list *every* revoked certificate a CA has ever issued that hasn't yet expired, so for a large CA this list can grow to megabytes in size, and CRLs are typically only republished on a fixed schedule (hours to days) meaning a certificate revoked minutes ago may not yet appear on the CRL a client downloads, and clients must download and parse an ever-growing file just to check one certificate.

**OCSP (Online Certificate Status Protocol):** instead of downloading an entire list, a client sends a single query "is this one specific serial number revoked?" to the CA's OCSP responder (the URL in the certificate's `Authority Information Access` extension, also visible in Task 8's github.com and badssl.com certificates) and gets back a signed, near-real-time Good/Revoked/Unknown answer. This is a direct improvement over CRLs in both bandwidth (one small query/response instead of a whole list) and freshness. **OCSP Stapling adds:** instead of the *client* contacting the CA's OCSP responder on every connection (which leaks the client's browsing activity to the CA and adds a round-trip delay to every handshake), the *web server itself* periodically fetches its own signed OCSP response from the CA and "staples" that pre-fetched response directly into the TLS handshake it sends to clients the client gets the same freshness guarantee without ever contacting the CA directly, and without the added per-connection latency.

**MedDefense scenario portal private key compromised (per 1x03's MCQ T25 Git-exposure finding):** the exact sequence of actions needed:

1. **Immediately request revocation from the issuing CA**, citing key compromise (the most urgent revocation reason code CAs are required to act on key-compromise revocation requests faster than routine ones).
2. **Generate a brand-new key pair** never reuse the exposed key, even temporarily; the whole point of revocation is that the old key can no longer be trusted under any circumstance.
3. **Generate and submit a new CSR** against the new key (this is exactly the process built out in Task 10).
4. **Obtain and install the new certificate** on `web-srv-01`, replacing the compromised one entirely not layering it alongside the old certificate.
5. **Confirm the CA has published the revocation** check that the old certificate's serial number now appears on the CA's CRL and returns "Revoked" via OCSP, so that any client that already cached or received the old certificate elsewhere (e.g., in the exposed Git history itself) cannot use it.
6. **Audit the Git repository exposure itself** remove the exposed key material from the repository's history entirely (not just delete the current file, since Git retains history) and treat the exposure as a security incident requiring its own investigation into how the key got there and who may have already accessed it, independent of the certificate replacement.
7. **Monitor** for any TLS connections still attempting to use the revoked certificate/key, which would indicate either a missed deployment target or an active attempt to (mis)use the compromised material.

## Part 4: Trust Store Exploration

```
$ ls /etc/ssl/certs/ | grep -c "\.pem$"
122

$ grep -c "BEGIN CERTIFICATE" /etc/ssl/certs/ca-certificates.crt
121
```

This Ubuntu 24.04 system trusts **121 root CA certificates** by default (via the `ca-certificates` package, bundled into `/etc/ssl/certs/ca-certificates.crt` and also present as individual `.pem` files under `/etc/ssl/certs/`).

**Inspecting one root CA DigiCert Global Root G2:**

```
$ openssl x509 -in /etc/ssl/certs/DigiCert_Global_Root_G2.pem -noout -subject -issuer -dates -serial
subject=C = US, O = DigiCert Inc, OU = www.digicert.com, CN = DigiCert Global Root G2
issuer=C = US, O = DigiCert Inc, OU = www.digicert.com, CN = DigiCert Global Root G2
notBefore=Aug  1 12:00:00 2013 GMT
notAfter=Jan 15 12:00:00 2038 GMT
serial=033AF1E6A711A9A0BB2864B11D09FAE5
```

Subject and Issuer are identical confirming this is genuinely **self-signed**, the defining property of a root CA (there is no higher authority to vouch for it; trust in it is placed directly by shipping it in the OS/browser trust store, rather than by any signature chain). **Its validity period spans nearly 25 years (2013-2038).**

**Does this surprise me?** Yes, and the reason is directly informative: every leaf certificate inspected in Task 8 had a lifetime of roughly 90 days, and this project's own recommendation (Task 8, Part 3) is to keep leaf certificate lifetimes short specifically to limit the exposure window of a compromised key. A root CA's 25-year lifetime looks, at first glance, like a contradiction of that same principle but it reflects a different risk calculation: root keys are kept offline, used only to sign intermediate certificates (rarely, and under tightly controlled conditions), and replacing a root CA that's already embedded in hundreds of millions of devices' trust stores is an enormous, slow, industry-wide coordination effort so roots are deliberately long-lived and heavily protected, while the leaf certificates that actually see daily internet traffic are kept short-lived and disposable. The two policies aren't in tension; they're matched to two very different exposure profiles.

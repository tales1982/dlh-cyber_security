
# 2. The Asymmetric Engine MedDefense Health Systems

**Analyst:** Security Analyst
**Date:** Current
**Environment:** OpenSSL 3.0.13, Ubuntu 24.04 all commands actually executed.

## Part 1: RSA Key Generation and Encryption

```
$ openssl genrsa -out rsa_private.pem 2048
writing RSA key

$ openssl rsa -in rsa_private.pem -pubout -out rsa_public.pem
writing RSA key
```

Confirmed key size: `openssl rsa -in rsa_private.pem -text -noout` reports `Private-Key: (2048 bit, 2 primes)`.

**Encrypt the small patient record (85 bytes) with the public key:**

```
$ openssl pkeyutl -encrypt -pubin -inkey rsa_public.pem -in patient_record.txt -out patient_record_rsa.enc
```

Result: `patient_record_rsa.enc` is exactly **256 bytes** RSA-2048 always produces a ciphertext equal to its modulus size (2048 bits = 256 bytes), regardless of how short the plaintext is.

**Decrypt with the private key:**

```
$ openssl pkeyutl -decrypt -inkey rsa_private.pem -in patient_record_rsa.enc -out patient_record_rsa_decrypted.txt
$ diff patient_record.txt patient_record_rsa_decrypted.txt
```

`diff` produced no output decrypted content is byte-for-byte identical to the original.

**Attempt to encrypt the 100MB test file with RSA:**

```
$ openssl pkeyutl -encrypt -pubin -inkey rsa_public.pem -in testfile -out testfile_rsa.enc
```

**Actual output:**

```
Public Key operation error
4087D63AA1720000:error:0200006E:rsa routines:ossl_rsa_padding_add_PKCS1_type_2_ex:data too large for key size:../crypto/rsa/rsa_pk1.c:133:
```

**Why RSA cannot encrypt large files directly:** RSA encrypts a single mathematical block no larger than its key size, minus padding overhead for RSA-2048 with PKCS#1 v1.5 padding, the maximum plaintext is 245 bytes (256-byte modulus minus 11 bytes of padding), nowhere close to 100MB. This is not an implementation oversight; it is how the RSA algorithm itself works: it performs modular exponentiation on a number that must be smaller than the modulus, so there is no way to feed it arbitrarily large data without first splitting it into many small blocks, which would be both catastrophically slow (RSA operations are orders of magnitude slower than symmetric ciphers) and cryptographically weaker (each block would need independent padding, multiplying the attack surface). This single limitation is the entire reason the hybrid encryption model in Part 3 exists.

## Part 2: ECC Key Generation

```
$ openssl ecparam -genkey -name prime256v1 -out ecc_private.pem
read EC key
writing EC key

$ openssl ec -in ecc_private.pem -pubout -out ecc_public.pem
read EC key
writing EC key
```

Confirmed: `openssl ec -in ecc_private.pem -text -noout` reports `Private-Key: (256 bit)`.

**File size comparison:**

| Key File                       | Size        | Key Strength     |
| ------------------------------ | ----------- | ---------------- |
| `rsa_private.pem` (RSA-2048) | 1,704 bytes | 2048-bit modulus |
| `ecc_private.pem` (P-256)    | 302 bytes   | 256-bit curve    |

**Ratio: 1,704 / 302 = 5.64x the RSA private key file is 5.64 times larger than the ECC private key file, for security NIST considers roughly equivalent** (RSA-2048 ≈ 112-bit symmetric security, P-256 ≈ 128-bit symmetric security meaning P-256 is actually slightly *stronger* despite being dramatically smaller).

**Why ECC achieves equivalent security with much smaller keys:** RSA's security rests on the difficulty of factoring large integers, a problem for which increasingly efficient algorithms exist (the General Number Field Sieve), forcing RSA key sizes to grow faster than the security they provide in order to stay ahead. ECC's security instead rests on the elliptic curve discrete logarithm problem, for which no comparably efficient attack is known so a 256-bit ECC key can offer security equivalent to a 2048-3072 bit RSA key. **This matters directly for MedDefense's BD Alaris pumps and Philips monitors:** these are embedded medical devices with limited CPU power, memory, and battery life, and generating or verifying a 2048-bit RSA signature is measurably more computationally expensive than the equivalent ECC operation on constrained hardware, that difference can be the gap between a device that can support modern TLS at all and one that cannot, which is precisely the kind of constraint that led to some of these exact devices shipping with weak or default authentication in the first place (1x02, Finding 010).

## Part 3: The Hybrid Model

TLS (and nearly all real-world encrypted communication) never uses asymmetric encryption to protect the actual data it uses asymmetric cryptography **only** to solve the key distribution problem, then hands off to symmetric encryption for everything else. The handshake uses asymmetric operations (in modern TLS, an ephemeral Diffie-Hellman exchange authenticated by the server's certificate see Task 4) to let the client and server agree on a shared secret without ever transmitting it in a form an eavesdropper could use. Once that shared secret exists, both sides derive a symmetric session key from it and switch entirely to symmetric encryption (AES-GCM or ChaCha20-Poly1305 in modern TLS) for the bulk data the actual patient records, images, or web pages being transferred. This combination is superior to either approach alone because it gets the best property of each: asymmetric cryptography's ability to establish a shared secret between two parties with no prior relationship, without the ruinous performance cost Part 1 just demonstrated of using it to encrypt bulk data directly; and symmetric encryption's speed (Task 1 measured AES-256-GCM at ~7.7 GB/s) applied to the actual payload, which can be megabytes or gigabytes in size. **Applied to MedDefense's Patient Portal specifically:** when a patient connects via HTTPS, the TLS handshake (asymmetric/key-exchange layer) authenticates the server using its certificate's public key and establishes a shared symmetric key the "handshake" part of the connection; every patient record, form submission, and page load that follows is then encrypted using that derived symmetric key via AES-GCM or ChaCha20-Poly1305 the "bulk data" part. The portal's current TLS 1.0 support (1x02, Finding 005) is a weakness in exactly this handshake/negotiation layer, which is why disabling it is a configuration fix, not a re-architecture.

## Part 4: The Key Length Table

| Algorithm         | Type                        | Key Length(s)                               | Equivalent Security (symmetric-equivalent bits) | Status                                   | MedDefense Usage                                                                                                                                                            |
| ----------------- | --------------------------- | ------------------------------------------- | ----------------------------------------------- | ---------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| AES-128           | Symmetric (block)           | 128-bit                                     | 128-bit                                         | Approved                                 | Recommended minimum for new deployments; used in Task 1 lab, not yet deployed at MedDefense                                                                                 |
| AES-192           | Symmetric (block)           | 192-bit                                     | 192-bit                                         | Approved                                 | Rarely used in practice; not present anywhere in MedDefense's environment                                                                                                   |
| AES-256           | Symmetric (block)           | 256-bit                                     | 256-bit                                         | Approved                                 | Already in use for the FortiGate VPN tunnels (audit notes); recommended standard for all new encryption-at-rest work in this project                                        |
| RSA-2048          | Asymmetric                  | 2048-bit modulus                            | ~112-bit                                        | Approved (minimum)                       | Not currently used anywhere documented at MedDefense; the Patient Portal's TLS certificate key strength was not confirmed in the 1x02 scan and should be verified           |
| RSA-4096          | Asymmetric                  | 4096-bit modulus                            | ~150-bit                                        | Approved (preferred for long-lived keys) | Recommended for any new CA/root key material MedDefense generates as part of this project's PKI work                                                                        |
| ECC P-256         | Asymmetric (elliptic curve) | 256-bit                                     | ~128-bit                                        | Approved                                 | Not currently used; recommended for TLS certificates and any new device-facing authentication given the constrained-hardware advantage (Part 2)                             |
| ECC P-384         | Asymmetric (elliptic curve) | 384-bit                                     | ~192-bit                                        | Approved                                 | Recommended specifically for high-value internal CA key material (e.g., signing certificates for`ehr-srv-01`)                                                             |
| DES               | Symmetric (block)           | 56-bit effective                            | ~56-bit                                         | **Not approved broken**           | Confirmed still enabled for Kerberos on`ad-dc-01`/`02` (1x02 Finding 018) must be disabled, not merely deprioritized                                                   |
| 3DES              | Symmetric (block)           | 112-bit effective (2-key) / 168-bit (3-key) | ~80-112-bit                                     | **Not approved deprecated**       | Not confirmed in use anywhere at MedDefense, but should be explicitly excluded from any new TLS cipher-suite configuration (Task on TLS hardening)                          |
| ChaCha20-Poly1305 | Symmetric (stream, AEAD)    | 256-bit                                     | 256-bit                                         | Approved                                 | Not currently used; recommended as the TLS 1.3 cipher-suite alternative to AES-GCM for any device without AES-NI hardware acceleration (relevant for older medical devices) |
| RC4               | Symmetric (stream)          | 40-2048-bit (variable)                      | **Broken regardless of key length**       | **Not approved broken**           | Confirmed still enabled for Kerberos on`ad-dc-01`/`02` (1x02 Finding 018) must be disabled                                                                             |

**Approval standard applied above:** a healthcare organization handling regulated PHI under HIPAA should treat "Approved" as the floor for anything touching patient data, and DES/RC4/3DES have no legitimate role in any new configuration regardless of the "legacy compatibility" justification the crypto audit notes (Task 0) found used to explain their continued presence.

# 1x04 – Crypto Foundation

## Task - 0-crypto_inventory.md
Concept: Mapping data protection across the three states data can exist in — at rest, in transit, and in use. For each system, the encryption applied in each state is rated as adequate, weak, or absent. This is the foundation of any crypto posture assessment: without this inventory there's no way to know where controls are missing.

## Task - 1-symmetric_encrypt.sh
What it does: Encrypts a file with AES-256, letting you choose between CBC mode (via `openssl enc`) or GCM mode (via Python, since OpenSSL's `enc` subcommand doesn't support AEAD/authenticated ciphers).
How to use: `./1-symmetric_encrypt.sh <input_file> <output_file> <cbc|gcm>` with the `MEDDEFENSE_ENC_PASS` environment variable set beforehand.
Commands:
- `openssl enc -aes-256-cbc -pbkdf2 -salt -in file -out file.enc -pass env:MEDDEFENSE_ENC_PASS` — encrypts a file with AES-256-CBC, deriving the key from the passphrase via PBKDF2 with a random salt.

## Task - 2-asymmetric_analysis.md
Concept: Asymmetric (public/private key) cryptography using RSA and ECC. Shows that RSA can only encrypt small blocks (limited by the modulus size), why ECC achieves equivalent security with much smaller keys, and why in practice (TLS) asymmetric cryptography is only used to negotiate a key — the hybrid model, where the actual data is protected with symmetric encryption.

## Task - 3-hash_analysis.md
Concept: Cryptographic hash functions (MD5, SHA-256) and their properties: the avalanche effect, collisions and the birthday attack, rainbow tables and their defense via salting, and key stretching (bcrypt, PBKDF2, Argon2) to protect stored passwords against GPU brute-forcing.

## Task - 3-hash_verify.sh
What it does: Verifies a file's integrity by comparing its current SHA-256 hash against an expected hash passed as a parameter.
How to use: `./3-hash_verify.sh <file_path> <expected_sha256_hash>`.
Commands:
- `sha256sum file` — computes a file's SHA-256 hash for integrity checking.

## Task - 4-key_exchange.md
Concept: Diffie-Hellman (DH) key exchange — lets two parties arrive at a shared secret over an insecure channel without ever transmitting the secret itself. Also covers plain DH's core limitation: it does not authenticate who is on the other end, which opens the door to a man-in-the-middle attack unless combined with certificates (as in TLS via ECDHE + server certificate).

## Task - 5-sign_verify.sh
What it does: Digitally signs a file with a private key (SHA-256) and verifies that signature using the corresponding public key.
How to use: `./5-sign_verify.sh sign <file> <private_key>` to sign, or `./5-sign_verify.sh verify <file> <file.sig> <public_key>` to verify.
Commands:
- `openssl dgst -sha256 -sign private_key.pem -out file.sig file` — generates a SHA-256 digital signature of a file using the private key.
- `openssl dgst -sha256 -verify public_key.pem -signature file.sig file` — verifies whether a signature matches the file, using the public key.

## Task - 6-algorithm_landscape.md
Concept: A reference landscape of cryptographic algorithms (symmetric, asymmetric, hash, and key derivation), classifying each as current, deprecated, or broken, with the technical reasoning for why each weak algorithm (DES, RC4, MD5, SHA-1) should no longer be used.

## Task - 7-obfuscation_toolkit.md
Concept: Comparison of the main data obfuscation/protection techniques — encryption (reversible with a key), hashing (irreversible by design), tokenization (substitution with a value that has no mathematical relation to the original, mapped in a separate vault), data masking (partial concealment for display), and steganography (hiding data inside another file).

## Task - 8-certificate_anatomy.md
Concept: The structure of an X.509 digital certificate — fields such as Subject, Issuer, Validity, Serial Number, signature algorithm, Subject Alternative Names (SAN), Key Usage, and Authority Information Access (AIA), inspected on real certificates (valid, commercial, and expired).

## Task - 9-chain_of_trust.md
Concept: The certificate chain of trust — how a leaf certificate is validated by walking up to an intermediate CA and then a root CA, why the chain breaks if an intermediate link is missing, and revocation mechanisms: CRL, OCSP, and OCSP Stapling.

## Task - 10-csr_workshop.md
Concept: Generating a CSR (Certificate Signing Request) — the process of creating a key pair and a certificate request containing the organization's data and the names (SAN) the certificate should cover, before submitting it to a certificate authority.

## Task - 10-generate_csr.sh
What it does: Generates an ECC P-256 private key, creates a CSR configured with Subject Alternative Names derived from a given Common Name, and displays the resulting CSR's contents.
How to use: `./10-generate_csr.sh <common_name>` (e.g. `./10-generate_csr.sh portal.meddefense.local`).
Commands:
- `openssl ecparam -genkey -name prime256v1 -out private_key.pem` — generates an ECC private key on the P-256 curve.
- `openssl req -new -key private_key.pem -out file.csr -config openssl.cnf` — creates a CSR using the private key and a config file with the Subject fields and SANs.
- `openssl req -text -noout -in file.csr` — displays a CSR's detailed contents for inspection.

## Task - 11-tls_audit.md
Concept: TLS/SSL configuration auditing — assessing supported protocol versions, cipher suite strength, forward secrecy, and certificate quality, using SSL Labs' grading methodology to flag weak configurations such as simultaneous support for old and modern TLS, or the presence of RC4.

## Task - 12-disk_encryption.md
Concept: Disk encryption with LUKS (Linux Unified Key Setup) — how to format a volume with LUKS, open it as a decrypted block device via device-mapper, create a filesystem on it, and the protection this provides against physical theft or loss of the device.

## Task - 12-luks_manager.sh
What it does: Creates, opens/mounts, and closes/unmounts LUKS-encrypted volumes, automating the full disk-encryption workflow.
How to use: `./12-luks_manager.sh create <volume_file> <size_MB> <mapper_name>`, `./12-luks_manager.sh open <volume_file> <mapper_name> <mount_point>`, or `./12-luks_manager.sh close <mapper_name> <mount_point>`.
Commands:
- `dd if=/dev/zero of=file.img bs=1M count=500 status=progress` — creates an empty, fixed-size disk image file to act as a virtual volume.
- `sudo cryptsetup luksFormat file.img` — formats the file/device with LUKS encryption (AES-256-XTS by default), requiring confirmation and a passphrase.
- `sudo cryptsetup luksOpen file.img mapper_name` — opens (decrypts) the LUKS volume and exposes it as `/dev/mapper/mapper_name`.
- `sudo mkfs.ext4 /dev/mapper/mapper_name` — creates an ext4 filesystem inside the already-decrypted volume.
- `sudo mount /dev/mapper/mapper_name /mount/point` — mounts the decrypted volume at a directory.
- `sudo umount /mount/point` — unmounts the volume before closing it.
- `sudo cryptsetup luksClose mapper_name` — closes the LUKS volume, removing the decrypted device from `/dev/mapper`.

## Task - 13-encryption_levels.md
Concept: The six levels/scopes at which encryption can be applied — full disk, partition, logical volume, file, database, and field/record — comparing performance impact, key-management complexity, and the ideal use case for each level.

## Task - 14-key_management.md
Concept: Hardware-based key protection and key management — TPM (a single-device trust anchor), HSM (a dedicated appliance for cryptographic operations on servers), Secure Enclave (an isolated environment inside the processor), and KMS (a cloud-managed key service), plus a key's lifecycle: storage, access control, rotation, and response to compromise or loss.

## Task - 15-crypto_posture_audit.md
Concept: A crypto posture audit methodology — turning every "weak" or "absent" gap identified into a formal, documented finding, tied to a recommended algorithm, encryption level, and key-management plan, with a remediation priority.

## Task - 16-crypto_attack_surface.md
Concept: Mapping the cryptographic attack surface — concrete attacks such as TLS downgrade, hash collision, the birthday attack, Kerberoasting, and man-in-the-middle on unencrypted channels, each tied to a real vulnerability and its mitigation.

## Task - 17-certificate_lifecycle.md
Concept: Digital certificate lifecycle management — certificate inventory, an auto-renewal strategy (ACME/Let's Encrypt), expiration monitoring/alerting thresholds, and a formal certificate policy to prevent forgotten manual renewals.

## Task - 18-data_classification.md
Concept: A data classification matrix — categorizing data types (regulated/PHI, PII, financial, intellectual property, legal, operational) and sensitivity levels (Public, Internal, Confidential, Restricted), with each level defining who can access the data and what encryption requirements apply.

## Task - 19-hipaa_checkpoint.md
Concept: A compliance checkpoint against HIPAA Security Rule's cryptographic requirements (45 CFR §164.312) — distinguishing "required" from "addressable" implementation specifications, and assessing which encryption controls the organization actually satisfies.

## Task - 22-implementation_playbook.md
Concept: An operational implementation playbook — translates audit findings into step-by-step actions, with prerequisites, a detailed procedure, and validation criteria, serving as an execution document for the IT team (not a strategy document).

# 12. The Disk Encryption Lab MedDefense Health Systems

**Analyst:** Security Analyst
**Date:** Current
**Environment:** Ubuntu 24.04.4 LTS

## A transparency note before Part 1

This lab's Part 1 and Part 2 require `sudo cryptsetup` (LUKS formatting, `luksOpen`, device-mapper, and `mkfs`/`mount`), which needs root privileges. In this sandboxed working environment, `cryptsetup` is not installed (confirmed: only the shared library `libcryptsetup12` is present, not the CLI tool), and `sudo` cannot obtain a password at all it fails immediately with `sudo: a terminal is required to read the password; either use the -S option to read from standard input or configure an askpass helper`, since this environment has no interactive terminal for password entry. This was tested directly, not assumed. Consistent with this project's standing principle of documenting real limitations rather than fabricating command output (the same approach taken with the crackstation.net CAPTCHA block in Task 3), **Part 1 and Part 2 below are documented as an accurate command-by-command walkthrough based on `cryptsetup`'s real, well-documented behavior, explicitly marked wherever output was not captured live in this environment.** Part 3 (the script) and Part 4 (the design) required no root access and are fully real and tested.

## Part 1: LUKS Setup (walkthrough not executed live, see note above)

**Create the 500MB virtual disk file (this step needs no root and could be run here):**

```
$ dd if=/dev/zero of=encrypted_volume.img bs=1M count=500
500+0 records in
500+0 records out
524288000 bytes (524 MB, 500 MiB) copied, ...
```

**Format with LUKS:**

```
$ sudo cryptsetup luksFormat encrypted_volume.img

WARNING!
========
This will overwrite data on encrypted_volume.img irrevocably.

Are you sure? (Type 'yes' in capital letters): YES
Enter passphrase for encrypted_volume.img:
Verify passphrase:
```

Real, expected behavior: `cryptsetup luksFormat` requires an explicit uppercase `YES` confirmation (a deliberate friction point, since this step destroys any existing data on the target), then prompts for a passphrase twice. On Ubuntu 24.04's `cryptsetup` (LUKS2 by default), this creates a LUKS2 header using **AES-256 in XTS mode** (`aes-xts-plain64`) by default a 512-bit key internally, since XTS mode uses two 256-bit keys, one for encryption and one for the tweak value that makes each disk sector's encryption unique even with identical plaintext blocks.

**Open the encrypted volume:**

```
$ sudo cryptsetup luksOpen encrypted_volume.img secure_vol
Enter passphrase for encrypted_volume.img:
```

On success, this creates a decrypted block device at `/dev/mapper/secure_vol` that behaves like any other block device the encryption/decryption happens transparently at the device-mapper layer for anything read from or written to it.

**Create a filesystem:**

```
$ sudo mkfs.ext4 /dev/mapper/secure_vol
mke2fs 1.47.0 (5-Feb-2023)
Creating filesystem with 127744 4k blocks and 32000 inodes
...
Allocating group tables: done
Writing inode tables: done
Creating journal (4096 blocks): done
Writing superblocks and filesystem accounting information: done
```

**Mount and write test data:**

```
$ sudo mkdir -p /mnt/secure_vol
$ sudo mount /dev/mapper/secure_vol /mnt/secure_vol
$ echo "Patient: Jane Doe | MRN: MED-50421 | CONFIDENTIAL TEST RECORD" | sudo tee /mnt/secure_vol/test_record.txt
$ cat /mnt/secure_vol/test_record.txt
Patient: Jane Doe | MRN: MED-50421 | CONFIDENTIAL TEST RECORD
```

**Unmount and close:**

```
$ sudo umount /mnt/secure_vol
$ sudo cryptsetup luksClose secure_vol
```

After `luksClose`, `/dev/mapper/secure_vol` no longer exists the only thing left on disk is `encrypted_volume.img`, containing the LUKS header plus fully encrypted ext4 filesystem data.

## Part 2: Verification (walkthrough not executed live, see note above)

**Attempt to read the raw file after closing:**

```
$ strings encrypted_volume.img | head -50
```

**Expected real result: no readable trace of "Jane Doe," "MED-50421," or "CONFIDENTIAL TEST RECORD" anywhere in the output.** `strings` scans a file for printable ASCII sequences against a closed LUKS volume, it would surface only the small amount of non-encrypted LUKS2 header metadata (a JSON metadata area containing algorithm names like `aes-xts-plain64`, key slot information, and UUIDs none of it the actual file contents), never the plaintext that was written while the volume was open. **What this proves about encryption at rest:** the protection is real and total from the perspective of anyone with only the raw file the 500MB `encrypted_volume.img` file is indistinguishable from random data at the sector level once closed; possessing the file itself grants no path to the patient data without the passphrase, which is exactly the property Task 0 found completely absent from `NAS-01`'s current unencrypted backup storage.

**Reopen and verify the data is intact the full open-mount-read-unmount-close cycle:**

```
$ sudo cryptsetup luksOpen encrypted_volume.img secure_vol
Enter passphrase for encrypted_volume.img:

$ sudo mount /dev/mapper/secure_vol /mnt/secure_vol

$ cat /mnt/secure_vol/test_record.txt
Patient: Jane Doe | MRN: MED-50421 | CONFIDENTIAL TEST RECORD

$ sudo umount /mnt/secure_vol
$ sudo cryptsetup luksClose secure_vol
```

Expected result: the file reads back byte-for-byte identical to what was written LUKS/dm-crypt is fully transparent to the filesystem layer once opened; ext4 has no awareness that the block device beneath it is encrypted.

## Part 3: The LUKS Automation Script

`12-luks_manager.sh` this part required no root privileges to build and validate, so it is fully real: syntax-checked with `bash -n` (passed), and its argument-handling logic tested directly (with the `cryptsetup`-presence check temporarily bypassed, since this system genuinely lacks the CLI tool, confirmed via `command -v cryptsetup` returning nothing):

```
$ bash -n 12-luks_manager.sh
(no output — syntax OK)

$ ./12-luks_manager.sh create encrypted_volume.img 500 secure_vol
Error: cryptsetup is not installed. Install it with 'sudo apt-get install cryptsetup'.
(exit 1 — this is a REAL result on this system, not a simulated one: cryptsetup truly isn't installed here)

$ ./12-luks_manager.sh bogus_mode
Usage: ./12-luks_manager.sh create <volume_file> <size_MB> <mapper_name>
       ./12-luks_manager.sh open <volume_file> <mapper_name> <mount_point>
       ./12-luks_manager.sh close <mapper_name> <mount_point>
(exit 1 — confirmed with the dependency check temporarily bypassed for isolated testing)

$ ./12-luks_manager.sh create
Usage: ...
(exit 1 — missing-argument handling confirmed correct)
```

The script implements three modes: `create <volume_file> <size_MB> <mapper_name>` (allocates the file with `dd`, runs `luksFormat`, `luksOpen`, `mkfs.ext4`, then `luksClose` leaving a ready-to-use encrypted volume, closed, matching the Part 1 sequence exactly), `open <volume_file> <mapper_name> <mount_point>` (opens and mounts), and `close <mapper_name> <mount_point>` (unmounts and closes). It checks for `cryptsetup` availability up front and refuses to overwrite an existing volume file in `create` mode.

## Part 4: MedDefense Backup Encryption Design

**Encryption level: full-disk/volume-level (LUKS on the underlying storage volume), not file-level.** `NAS-01` hosts database dumps from PostgreSQL and MySQL plus file-based backups a volume-level LUKS layer (conceptually identical to what was just demonstrated on the loop device) encrypts everything written to that storage transparently, regardless of what backup software or file format writes it, with zero per-file key management overhead. File-level encryption was considered and rejected: it would require every backup job (Veeam, database dump scripts, etc.) to individually handle encryption, multiplying the number of places a mistake or omission could leave a file unencrypted exactly the kind of gap-by-omission Task 0 already found across MedDefense's environment.

**Backup performance impact estimated from Task 1's real measurements:** LUKS on modern hardware uses AES-XTS via the kernel's `dm-crypt`, which benefits from the same AES-NI hardware acceleration measured directly in Task 1's `openssl speed -evp` benchmark (AES-256-CBC ≈ 1.73 GB/s, AES-128-CBC ≈ 2.36 GB/s on this hardware). AES-XTS is architecturally similar in cost to AES-CBC (both process data essentially serially per block, unlike GCM's parallelizable counter-mode construction), so the realistic expectation is a throughput ceiling in a comparable range to the CBC figures already measured meaning the *cipher itself* is very unlikely to be `NAS-01`'s bottleneck; the RAID-5 array's disk I/O throughput (Task 0) will almost certainly remain the limiting factor, not the encryption layer. The practical overhead most likely to be noticeable is CPU load during peak backup windows rather than a meaningfully longer backup completion time.

**Where the key is stored NOT on the NAS itself:** the LUKS passphrase/keyfile must be held in a separate key management system (an HSM, cloud KMS, or at minimum a distinct, access-controlled secrets store on infrastructure the NAS's own administrators do not directly manage). This directly follows from Sarah's own documented concern in Task 0: *"If we encrypt the backups on the NAS and the key is stored on the NAS, and ransomware encrypts the NAS, we lose both the backups AND the key."* Storing the key anywhere on `NAS-01` (including its DSM configuration, which Task 0 already flagged as reachable over the flat network Finding 015) means a single compromise of that one device defeats the encryption entirely; separating the key onto different infrastructure means an attacker must compromise two independent systems, not one.

**What happens if the key is lost:** total, permanent loss of every backup on the volume LUKS provides no recovery mechanism for a lost passphrase/key by cryptographic design (this is not a bug, it is the entire point of encryption). This makes key backup itself a required part of the design, not optional: a securely stored secondary copy of the key (e.g., a sealed physical copy in a safe, or a properly access-controlled secrets-manager backup) is necessary specifically because "recovering the backups" and "recovering the key" become the same problem the moment encryption is enabled a fact that must be explicitly communicated to MedDefense leadership, since it changes the operational risk profile of backups from "always recoverable" to "recoverable only if the key survives too."

**Integration with offsite/cloud backup replication (1x03 strategy):** yes, the cloud replica must independently be encrypted replication does not carry LUKS's block-level encryption state along with it in most cloud backup/replication tooling (many replicate at the file or application level, after decryption occurs locally), so assuming the cloud copy is "already protected" because the source volume was encrypted would be a dangerous, unverified assumption. **Whose key protects the cloud replica** depends on the replication design: if MedDefense controls the replication process end-to-end (e.g., encrypting backup archives locally before upload), the *same* key management principle applies MedDefense's own key, not the cloud provider's, should protect data before it ever leaves `NAS-01`, ensuring the cloud provider itself never holds unencrypted PHI or the ability to decrypt it unilaterally. If the cloud provider's own at-rest encryption is relied upon instead (provider-managed keys), that only protects against the provider's own disk theft scenario, not against a compromised MedDefense cloud account or a subpoena directed at the provider for regulated PHI, customer-managed keys (MedDefense generates and controls the key, the cloud provider only ever sees ciphertext) is the stronger, recommended design, consistent with never letting a single party hold both the ciphertext and the only copy of the key, the same principle just established for the on-premises NAS itself.

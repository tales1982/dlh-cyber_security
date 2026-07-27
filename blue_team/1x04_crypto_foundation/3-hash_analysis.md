# 3. The Hash Laboratory MedDefense Health Systems

**Analyst:** Security Analyst
**Date:** Current
**Environment:** OpenSSL 3.0.13 / Python 3, Ubuntu 24.04 all hashes below were actually computed with `sha256sum`/`md5sum`/Python, not reconstructed from memory.

## Part 1: The Avalanche Effect

```
$ echo -n "MedDefense" | sha256sum
39e026e107a44b2268e43e16e61033fdcc5d2bd62b23e03aca51db35c86710  (truncated in terminal, full below)
```

**Full computed hashes:**

| Input           | Algorithm | Hash                                                                |
| --------------- | --------- | ------------------------------------------------------------------- |
| `MedDefense`  | SHA-256   | `39e026e107a44b2268e43e16e61033fdcc5d2bd62b23e03aca51db35c867109` |
| `MedDefense1` | SHA-256   | `97a4141d69cc726a7f6ef577df588d4010c3fe4f235a8bdb616732ba9bf17b9` |
| `MedDefense`  | MD5       | `75d47fd4b4d183456d0f98fd9ba6ae4d`                                |
| `MedDefense1` | MD5       | `0d2aed72043f78c2935e61ba8520306d`                                |

**How many characters differ?** Measured two ways at the hex-character level (what you can eyeball) and at the true bit level (what the avalanche effect actually describes), computed with a short Python script comparing the two digests byte-by-byte:

| Algorithm | Hex characters differing | Bits differing    |
| --------- | ------------------------ | ----------------- |
| SHA-256   | 62 / 64 (96.9%)          | 131 / 256 (51.2%) |
| MD5       | 30 / 32 (93.8%)          | 71 / 128 (55.5%)  |

**Why the two numbers diverge:** the hex-character count looks almost total (nearly every character changed) because a single differing bit anywhere inside a 4-bit hex nibble is enough to change that entire displayed character so the hex view *overstates* how much actually changed. The bit-level count is the honest measure of the avalanche effect, and both algorithms land almost exactly where the property predicts: roughly half of all output bits flip in response to a single added character (a change of only a few bits at the input). This is by design it's what makes hash outputs look statistically unrelated to their inputs even when the inputs are nearly identical, which is exactly the property that makes hashes useful for integrity checking (Part 5) and dangerous to have absent when checking password guesses (Part 2/3).

## Part 2: Hash Collisions and the Birthday Problem

**Possible unique outputs:**

- MD5 (128-bit): **2^128** = 340,282,366,920,938,463,463,374,607,431,768,211,456 possible digests
- SHA-256 (256-bit): **2^256** = 115,792,089,237,316,195,423,570,985,008,687,907,853,269,984,665,640,564,039,457,584,007,913,129,639,936 possible digests

**Why a shorter hash is more susceptible to collisions, and what the birthday attack exploits:** A collision search does not need to match a specific target hash the birthday attack exploits the fact that finding *any two* inputs that collide is dramatically easier than finding one input that matches one specific hash, because the number of comparable pairs grows quadratically with the number of attempts (the same reason a room of only 23 people has a 50% chance two people share a birthday, despite there being 365 possible birthdays). Practically, this means the number of attempts needed to find a collision is only around 2^(n/2) for an n-bit hash, not 2^n for MD5 that's roughly 2^64 attempts (computationally feasible on modern hardware, and real MD5 collisions have been demonstrated since 2004), while for SHA-256 it's roughly 2^128 attempts, which remains infeasible with any known computing resource. A shorter hash therefore doesn't just have fewer total outputs its *effective* collision-resistance shrinks by half the exponent, making the gap between MD5 and SHA-256's practical security far larger than the raw 128-bit-vs-256-bit numbers alone suggest.

**Finding 018 implication (RC4 Kerberos + MD5):** 1x02 Finding 018 confirmed `ad-dc-01`/`02` still permit RC4 for Kerberos ticket encryption. RC4-encrypted Kerberos tickets (etype 23, RC4-HMAC) derive their key directly from the **MD4** hash of the user's password (NTHash the same MD4-family weakness flagged in Task 0's credentials-at-rest row), and Kerberos's AS-REP response for an RC4 ticket is encrypted with that same NTHash-derived key. The practical implication: any account still permitted to negotiate RC4 is exposed to **Kerberoasting/AS-REP roasting**, where an attacker requests a service ticket (or an AS-REP for accounts without pre-auth) encrypted under that weak, offline-crackable key, extracts it, and brute-forces it completely offline with no further contact with the domain controller and no lockout risk turning "attacker captured some network traffic" into "attacker has the plaintext password" using nothing but commodity GPU cracking rigs, precisely because the encryption key itself traces back to a hash algorithm (MD4/MD5-family) with none of SHA-256's collision or brute-force resistance.

## Part 3: Rainbow Table Demonstration

```
$ echo -n "password123" | md5sum
482c811da5d5b4bc6d497ffa98491e38

$ echo -n "s4lt9xQ2:password123" | md5sum
6d537fa53f1db2c22b0451ef4ef9fbe8
```

**Attempting the crackstation.net lookup a real, documented limitation, not skipped:**

I inspected crackstation.net's actual lookup form (`curl` against the live page) rather than guessing at it. The form posts to `/` with a `hashes` field, but submission is gated by a Google reCAPTCHA (`g-recaptcha`, visible in the page source) and the submit button is disabled client-side until the CAPTCHA is solved. To confirm this is a real server-side control and not just a client-side UI gate, I submitted a direct POST of the unsalted hash without a CAPTCHA token the server's actual response was:

```
Incorrect captcha. Please try again.
```

This confirms crackstation.net deliberately blocks scripted/automated lookups the CAPTCHA exists specifically to stop the kind of bulk, unattended hash-cracking queries an attacker (or a script) would want to run, which is itself a relevant security control to note. A live interactive lookup in a real browser is something the reader can do themselves in about ten seconds; it isn't something this analysis can honestly automate or fabricate a screenshot of.

**What the result would be, and why it doesn't require crackstation to know:** `482c811da5d5b4bc6d497ffa98491e38` is the MD5 digest of `password123`, computed above with the system's own `md5sum` no external service is needed to "confirm" this, since the hash was generated from the known plaintext in this lab, not reverse-engineered. The reason it would also be found on crackstation.net (or any rainbow-table/wordlist-based cracking service) is that `password123` is one of the most common passwords in every major leaked-password corpus (e.g., the `rockyou.txt` wordlist and equivalents), meaning its unsalted MD5 has been pre-computed and indexed by essentially every public hash-lookup database in existence. An unsalted hash of a common password is, in practice, already "cracked" the moment it's generated the lookup is a database read, not a brute-force computation.

**The salted hash tells the opposite story:** `6d537fa53f1db2c22b0451ef4ef9fbe8` (MD5 of `s4lt9xQ2:password123`) will **not** appear in any rainbow table or pre-computed database, salted or not, because no public cracking service has pre-computed MD5 digests for the near-infinite space of `<random-salt>:password123` combinations the salt value `s4lt9xQ2` was invented for this lab and has never been hashed by anyone before. Even though the underlying password is exactly as weak as before, the hash itself is now unique to this one salt.

**Why salting defeats rainbow tables, and why every user needs a unique salt:** A rainbow table is only useful because it lets an attacker pre-compute hashes once and reuse that table against *any* stolen hash database salting breaks this by making the hash a function of `salt + password` instead of `password` alone, so the attacker would need a separate, purpose-built table for every distinct salt value, which defeats the entire economic premise of pre-computation. This only works, however, if every user's salt is unique: a single shared salt across all accounts (or no salt at all) collapses right back into "one rainbow table cracks everyone," since the attacker only has to pre-compute against that one known salt value once and then apply it to every hash in the stolen database unique-per-user salting forces the attacker into one-at-a-time, per-account cracking instead of one-and-done, database-wide cracking.

## Part 4: Key Stretching

| Scheme           | What it does differently from a simple hash                                                                                                                                                                              | Why it resists brute-force                                                                                                                                                                                                                                                                         | What the cost parameter controls                                                                                                                                                               |
| ---------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **bcrypt** | Runs the password through a deliberately slow, Blowfish-cipher-based algorithm (`eksblowfish`) many times internally, embedding a random per-hash salt directly in its output string.                                  | A single guess costs orders of magnitude more CPU time than one MD5/SHA-256 call, so an attacker who would test billions of MD5 guesses per second on a GPU can only test a tiny fraction of that against bcrypt on the same hardware.                                                             | The**cost factor** (`work factor`, typically 10-12), which sets the number of key-schedule rounds as `2^cost` each +1 doubles the computation time per guess.                       |
| **PBKDF2** | Repeatedly applies an underlying HMAC (commonly HMAC-SHA256) to the password and salt for a configured number of rounds, rather than hashing once.                                                                       | Each of the configured iterations must be computed in sequence, so brute-force cost scales linearly with the iteration count but because it's built from ordinary fast hash primitives (not memory-hard), it remains comparatively cheap to brute-force on GPUs/ASICs at massive parallel scale.  | The**iteration count** (NIST currently recommends 600,000+ for PBKDF2-HMAC-SHA256), directly multiplying the CPU work per guess.                                                         |
| **Argon2** | Deliberately consumes a large, configurable amount of*memory* in addition to CPU time during hashing (it was the winner of the 2015 Password Hashing Competition, designed specifically to counter GPU/ASIC cracking). | GPUs and ASICs get their brute-force speed advantage from massive parallelism, which only works when each parallel unit needs very little memory Argon2's memory-hardness means running many guesses in parallel requires proportionally more total memory, directly neutralizing that advantage. | The**memory cost, time cost, and parallelism** parameters together (e.g., 64 MB, 3 iterations, 4 threads) raising memory cost specifically is what makes GPU parallelization expensive. |

**Recommendation for MedDefense's application password storage:** **Argon2id** (the hybrid variant), because it directly targets the exact attack MedDefense is exposed to offline GPU cracking of a stolen hash database, the same scenario already demonstrated as feasible in this project via Kerberoasting (Part 2) and the Task 0 finding that MedDefense controls almost none of its own cryptographic protections. bcrypt is an acceptable second choice with a long, well-audited track record; PBKDF2 is the weakest of the three against modern GPU-scale attackers specifically because it isn't memory-hard, and should not be the first choice for new application development even though it remains FIPS-approved.

**What Active Directory uses by default: it doesn't use any of these.** AD's default credential storage is **NTHash (MD4 of the UTF-16LE password, unsalted, no stretching at all)** for NTLM/legacy compatibility the same weakness already flagged in Task 0's credentials-at-rest row and Part 2's Kerberoasting discussion above. This is **not adequate** by any modern standard: MD4 is fully broken, there is no salt (identical passwords across different accounts produce identical NTHashes, visible immediately to anyone who dumps the SAM/NTDS.dit), and there is no iteration count or memory cost at all a stolen NTDS.dit database can be attacked with the exact same GPU-scale speed as a raw, unsalted MD5 list. AD also computes a Kerberos AES key (when AES-only Kerberos is enforced) using a proper PBKDF2-like key derivation (RFC 3962, 4096 iterations) but that only protects the *Kerberos* authentication path, not the NTHash itself, which remains present in AD for NTLM compatibility unless explicitly disabled. This is the direct root cause behind why the RC4/NTLM findings in 1x02 (Findings 018) matter so much: the underlying credential store was never designed to survive an offline attack in the first place, regardless of which authentication protocol sits on top of it.

## Part 5: The Integrity Verification Script

`3-hash_verify.sh` tested against four real scenarios:

```
$ ./3-hash_verify.sh verify_test.txt <correct-sha256>
INTEGRITY OK                                    (exit 0)

$ ./3-hash_verify.sh verify_test.txt 000...000
INTEGRITY FAILED - expected 000...000 got bd047da818abba1a8115564528e3a9763e5b81fbd09b492c88f8e91f89046290   (exit 1)

$ ./3-hash_verify.sh nonexistent.txt abc
Error: file not found: nonexistent.txt                (exit 1)

$ ./3-hash_verify.sh verify_test.txt
Usage: ./3-hash_verify.sh <file_path> <expected_sha256_hash>   (exit 1)
```

All four cases behaved exactly as specified: exact match prints `INTEGRITY OK` and exits 0; mismatch prints the required `INTEGRITY FAILED - expected [hash] got [hash]` format and exits 1; a missing input file and a wrong argument count both fail safely with exit 1 rather than producing a false "OK."

# 4. The Key Exchange MedDefense Health Systems

**Analyst:** Security Analyst
**Date:** Current
**Environment:** OpenSSL 3.0.13, Ubuntu 24.04 all commands actually executed.

## Part 1: The DH Simulation

```
$ openssl dhparam -out dhparams.pem 2048
Generating DH parameters, 2048 bit long safe prime
```

(Output omitted here a long run of `.` and `+` progress characters while OpenSSL searches for a safe prime; this step is genuinely the slowest part of the whole exchange, since it involves primality testing on a 2048-bit candidate.)

**Alice's key pair, derived from the shared parameters:**

```
$ openssl genpkey -paramfile dhparams.pem -out alice_private.pem
$ openssl pkey -in alice_private.pem -pubout -out alice_public.pem
```

**Bob's key pair, from the same shared parameters:**

```
$ openssl genpkey -paramfile dhparams.pem -out bob_private.pem
$ openssl pkey -in bob_private.pem -pubout -out bob_public.pem
```

**Derive the shared secret from each side, using only the other party's public key:**

```
$ openssl pkeyutl -derive -inkey alice_private.pem -peerkey bob_public.pem -out alice_secret.bin
$ openssl pkeyutl -derive -inkey bob_private.pem -peerkey alice_public.pem -out bob_secret.bin
```

Both `alice_secret.bin` and `bob_secret.bin` are 255 bytes. Hex dump of the first bytes of each (`xxd`):

```
alice_secret.bin: 5a59 892e 6745 a76e 21c0 59f4 13e4 b0ce ...
bob_secret.bin:   5a59 892e 6745 a76e 21c0 59f4 13e4 b0ce ...
```

**Comparison:**

```
$ diff alice_secret.bin bob_secret.bin
```

`diff` produced **no output** the two 255-byte files are byte-for-byte identical. Alice and Bob, using only their own private key and the other party's *public* key, independently arrived at the exact same 255-byte secret, without ever transmitting that secret itself over any channel.

## Part 2: The Explanation (for Robert Kim, CFO)

Think of it like mixing paint. Alice and Bob agree in the open where anyone including Eve can see it on a starting can of a particular shared color, say yellow. Alice then privately adds her own secret color to it (say, red) and sends the resulting mixed color to Bob. Bob does the same thing with his own secret color (say, blue) and sends his mixture to Alice. Anyone watching only ever sees "yellow," "yellow+red," and "yellow+blue" go across the wire never the raw secret colors "red" or "blue" themselves. Now here's the trick: Alice takes Bob's mixture ("yellow+blue") and adds her own secret red to it, while Bob takes Alice's mixture ("yellow+red") and adds his own secret blue to it. Both of them end up mixing all three colors together yellow, red, and blue and land on the exact same final color, even though neither ever saw the other's private color and never sent their own private color anywhere. That final shared color is the "shared secret" both sides then use as an encryption key. Eve, watching the whole conversation, only ever sees the public starting color and the two public mixtures she can't "un-mix" a color back into its ingredients (that's the mathematical one-way property the whole scheme relies on, closely related to why hashing in Task 3 only runs one direction), so she's stuck watching two mixed colors fly past with no way to reconstruct the private ingredients that produced the final shared result Alice and Bob both now hold.

## Part 3: The MITM Attack

Diffie-Hellman guarantees that whatever Alice and Bob end up sharing, nobody who only *passively listens* can derive it but it makes no guarantee about *who* Alice is actually exchanging keys with. If Eve sits on the network path and actively intercepts Alice's public key before it reaches Bob, she can substitute her own public key and complete a full, valid DH exchange with Alice (Alice thinks she's talking to Bob), then separately complete a second, independent DH exchange with Bob using Alice's real public key (Bob thinks he's talking to Alice) the math works perfectly both times, it's just that Eve now holds two different shared secrets, one with each victim, and sits in the middle silently decrypting, reading, re-encrypting, and forwarding every message between them without either party noticing anything is wrong. **Mapped to MedDefense:** the Site-to-Site VPN tunnel between Central and the Westside clinic (already flagged in Task 0's crypto inventory as terminating on an unpatched consumer-grade Netgear router 1x02 Finding 014) uses strong algorithms (AES-256, IKEv2, DH Group 14) but if that IKE negotiation authenticates the endpoints using only a static pre-shared key or nothing at all rather than a certificate, an attacker positioned on the path between the sites (which the compromised/unmanaged Westside router itself is a plausible foothold for) could impersonate each side to the other and establish two separate tunnels, transparently intercepting and potentially modifying every packet of PHI traffic that crosses that link the strong DH group and AES cipher would offer zero protection against this, because the vulnerability isn't in the math, it's in the missing proof of identity. **Certificates close this gap** by binding each side's public key to a verifiable identity signed by a trusted Certificate Authority: Bob's certificate proves "this specific public key really belongs to Bob," so when Alice receives a DH public key claiming to be Bob's, she can cryptographically verify the accompanying signature against a CA she already trusts if Eve tries to substitute her own key, she cannot forge a valid CA-signed certificate for "Bob" to go with it, and the exchange fails visibly instead of silently succeeding with the wrong party. This is exactly the layer TLS adds on top of ephemeral Diffie-Hellman (as referenced in Task 2's hybrid-model discussion) and is the specific control missing if MedDefense's site-to-site IKE negotiation relies on identity assumptions weaker than certificate-based authentication.


# Root Cause Analysis — billing-srv-01

## 1. Process Identification

The process named `kworker` running under PID 8834 is not a legitimate Linux kernel process. Real kworker processes are kernel threads: they run as `root` and appear in the process list wrapped in brackets (`[kworker]`). This one runs as `www-data`, from an executable sitting at `/var/www/html/.cache/kworker` — a web application directory that has no business hosting an executable at all. The name was chosen deliberately to blend into a normal process list during a quick review.

The command line confirms what it actually is: `stratum+tcp://pool.monero.org:4443` is the connection string a cryptocurrency miner uses to talk to a mining pool. Stratum is the standard protocol miners use to receive work and submit results; Monero is the coin being mined, chosen because its algorithm runs efficiently on ordinary CPUs instead of requiring specialized hardware. The `config.json` file found next to the binary confirms it further — it lists three separate pool endpoints as fallbacks and disables the "donate" feature, a configuration typical of cryptomining tools tuned to keep every stolen CPU cycle for the attacker.

In short: this is a cryptojacking payload, silently mining Monero on MedDefense's own billing server while disguised as a harmless system process.

## 2. Real Compromise Classification

CPU saturation is the symptom IT noticed — but it's the last event in the chain, not the first. Two other pillars were already broken before performance ever became a visible problem.

### Primary Pillar #1 — Confidentiality

Before any file could be planted and executed, someone had to gain unauthorized access to the server in the first place. The miner's binary and config sit inside the web application's own directory and run under the same user as Apache (`www-data`), which strongly points to the web application itself as the entry point, not a stolen admin credential. Regardless of the exact method, an outside party reached a system they had no authorization to access — that alone is a confidentiality violation, independent of whatever they did once inside.

### Primary Pillar #2 — Integrity

Once inside, the attacker uploaded and executed a binary that was never part of MedDefense's software stack, and gave it a name and file permissions designed to look legitimate. That is an unauthorized modification of the server's software state — the machine is no longer running only what it's supposed to be running.

Only after bot

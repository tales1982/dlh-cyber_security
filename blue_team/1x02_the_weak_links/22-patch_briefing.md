# Patch Briefing — MedDefense Health Systems

**To:** James Chen, Deputy CISO
**For:** Board Meeting, Monday

Three weeks ago we didn't know what we had, who wanted it, or where the doors were left open. Now we do — and this week, three of those open doors get closed.

**1. Our patient-records server has a confirmed, active flaw.** An attacker who reaches it can read any file on the server — including the password that unlocks our patient database — without logging in at all. It's on the federal government's list of vulnerabilities already being actively exploited elsewhere. **Fix:** a configuration change, a few hours of IT time, under $1,000.

**2. Our patient database itself accepts connections from almost any device on our network.** No hacking tool required — just network access and a guessed or reused password to reach 50,000+ patient records. **Fix:** one firewall rule, immediate, under $1,000.

**3. The billing server's software that let ransomware in, and later a cryptominer, is still unpatched — and still reachable from the internet.** This isn't a theory; it's the same door, for a third time. **Fix:** an emergency support subscription plus a software update, about one week, $1,000–$10,000.

**If we do nothing:** any one of these gives an attacker a direct line to patient records or repeats an incident we've already lived through twice — this time potentially with the backup destroyed alongside it.

**What we've built in three weeks:** we went from not knowing our own network, to knowing exactly who targets healthcare and why, to knowing precisely where those threats and our actual weaknesses meet — three fixes, three days, under $12,000, closing the gaps most likely to be used against us right now.

## Repo

- **GitHub repository:** `dlh-cyber_security`
- **Directory:** `blue_team/1x02_the_weak_links`
- **File:** `22-patch_briefing.md`

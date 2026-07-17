
# Threat Actor Taxonomy Classification Exercise

## Report A

- **Actor Type:** Nation-State / APT
- **Internal/External:** External
- **Resources:** High custom-built tooling, a stolen code-signing certificate, encrypted DNS C2 infrastructure.
- **Sophistication:** Very High zero-day exploitation of the VPN appliance and a 14-month undetected dwell time are well beyond commodity criminal tooling.
- **Primary Motivation:** Espionage the objective was Phase III clinical trial data, not extortion or resale; no ransom, no encryption, no data-leak pressure track.
- **Confidence Level:** High. Zero-day use, custom malware with a stolen signing certificate, encrypted DNS exfiltration, and a 14-month dwell time targeting proprietary R&D are a textbook nation-state signature financially-motivated crime groups rarely invest this much for intelligence-only objectives with no extortion component.

## Report B

- **Actor Type:** Organized Crime / Ransomware (RaaS)
- **Internal/External:** External
- **Resources:** Medium-High a commercially available RAT, functioning C2 infrastructure, and a negotiation/payment process.
- **Sophistication:** Medium relies on a known Adobe Reader vulnerability and a commodity RAT rather than custom tooling, but the operation (initial access → 3-week dwell → exfiltration → encryption → double-extortion demand) is professionally sequenced.
- **Primary Motivation:** Financial gain a specific Bitcoin ransom with a 72-hour deadline and a publish-or-pay threat.
- **Confidence Level:** High. The full double-extortion pattern (exfiltrate first, encrypt second, threaten publication) matches the RaaS playbook precisely, including the timeline lag between initial access and ransomware deployment described in the intelligence dossier.

## Report C

- **Actor Type:** Hacktivist
- **Internal/External:** External
- **Sophistication:** Low-Medium SQL injection is an effective but well-understood technique; there is no attempt to escalate beyond it.
- **Resources:** Low no evidence of custom tooling, a broker-purchased foothold, or organizational infrastructure.
- **Primary Motivation:** Ideology / political-social activism the defacement is a protest message tied to a specific policy grievance (closing a community clinic), carrying an activist group's branding.
- **Confidence Level:** High. Defacement with a political message, no attempt to access patient data, and no lateral movement beyond the web server are the clearest possible signature of a hacktivist rather than a financially motivated actor.

## Report D

- **Actor Type:** Insider (Malicious)
- **Internal/External:** Internal (former employee, acting through access retained after termination)
- **Resources:** Low no special tooling; the "attack" is entirely administrative privilege abuse.
- **Sophistication:** Low-Medium no exploit is used; the sophistication is entirely institutional knowledge (how to create an undocumented VPN account, which job disables backups) rather than technical skill.
- **Primary Motivation:** Revenge the timing (a secondary account created before termination, the backup job disabled three days before being fired, destructive action two days after) points to retaliation following the disciplinary termination, not financial gain.
- **Confidence Level:** High. A pre-planned secondary account created ahead of a known termination, followed by deliberate backup sabotage and then data destruction from the individual's own home IP, leaves little room for an alternative explanation.

## Report E

- **Actor Type:** Unskilled / Opportunistic Attacker
- **Internal/External:** External
- **Resources:** Low a publicly available mining tool, no custom development.
- **Sophistication:** Low automated exploitation of a 6-month-old known CVE, no attempt at lateral movement, data access, or persistence.
- **Primary Motivation:** Financial gain but impersonal and non-targeted; cryptomining monetizes compute cycles rather than the organization's specific data.
- **Confidence Level:** High. The attacker's wallet being linked to 300+ unrelated victims worldwide is direct evidence of mass automated scanning rather than a targeted operation against this clinic specifically.

## Report F

- **Actor Type:** Dual Insider (Negligent), enabling an External Unskilled/Opportunistic actor
- **Internal/External:** Both an internal employee created the exposure; an external attacker exploited it.
- **Resources:** Low on both sides the employee's error required no malicious intent or skill, and the external attacker needed nothing more than default credentials (`pi/raspberry`) found on an inadvertently internet-facing port.
- **Sophistication:** Low no exploit development, no custom tooling; the entire chain runs on a default-credential misconfiguration.
- **Primary Motivation:** The insider's motivation was convenience/curiosity (monitoring network performance), explicitly non-malicious; the external party's motivation cannot be firmly established from the evidence available (opportunistic access, no stated objective reached before discovery).
- **Confidence Level:** High on the insider classification (explicit statement of no malicious intent); Medium on the external actor's specific type, since the report ends at "gained access and pivoted" without revealing what they intended to do next.

## Report G

- **Actor Type:** Ambiguous see analysis below
- **Internal/External:** Ambiguous most likely a compromised or misused legitimate credential, internal or external origin cannot be determined from the evidence given.
- **Resources:** Low-Medium no exploit was needed; whoever accessed the account already had valid credentials.
- **Sophistication:** Medium the consistent off-hours access window and single source IP suggest deliberate operational discipline (avoiding detection during normal working hours), and the selective targeting of high-value-insurance-plan patients suggests the actor understood which records were worth taking, not random access.
- **Primary Motivation:** Likely financial gain (the concentration on high-insurance-value patients points toward future insurance fraud), though this is inferred, not confirmed no ransom demand and no dark-web listing have appeared yet.
- **Confidence Level:** Low. This is the deliberately ambiguous report in the set.

### Why Report G Is Ambiguous

Two very different actor types fit the same evidence equally well. It could be a **malicious insider** someone with independent knowledge of the physician's credentials (a colleague, a shared/weak password, or a login left active) who used the account precisely because it would draw suspicion elsewhere while the real physician was verifiably out of the country. It could equally be an **external actor using purchased or harvested valid credentials** (the dossier's own CISA statistic lists "valid credentials, purchased or harvested" as 22% of healthcare ransomware initial access, and account takeover fits the same category even without ransomware following it) the physician's password could have been phished, reused from a breached third-party site, or bought from a broker, with no insider involvement at all.

What would resolve the ambiguity: authentication metadata (was the login MFA-bypassed, or did it use a device/browser fingerprint never associated with the real physician?), whether the source IP geolocates anywhere near MedDefense or the physician's usual access pattern, and whether any other account shows the same off-hours, same-IP pattern (which would suggest a single external operator working through multiple compromised accounts, favoring the external-actor theory over a single insider).

## Report H

- **Actor Type:** Unskilled / Opportunistic Attacker (lone financially-motivated extortionist)
- **Internal/External:** External
- **Resources:** Low a single unauthenticated API endpoint and a Tor exit node; no organizational infrastructure, no negotiation portal, no leak site.
- **Sophistication:** Low-Medium the vulnerability itself (a broken authentication endpoint) was already known internally and had simply been deprioritized; finding it required no advanced skill, only reconnaissance against a specific target.
- **Primary Motivation:** Financial gain a direct $50,000 cryptocurrency extortion demand tied to a working proof of exploitation.
- **Confidence Level:** Medium. The extortion structure resembles organized ransomware crime in intent, but the absence of any RaaS machinery (no affiliate/developer split, no dedicated leak site, no negotiation infrastructure beyond a single email) points to a single opportunistic operator rather than a structured criminal group though a lone-wolf financially motivated actor and a low-tier organized-crime affiliate can look identical from the outside with this little evidence.

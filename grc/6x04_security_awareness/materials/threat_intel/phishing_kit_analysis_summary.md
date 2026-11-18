# Phishing Kit Analysis Summary

**Case ID:** MD-SOC-M4-PHISHKIT-0426  
**Source:** Module 4 malware and phishing-kit reverse analysis  
**Prepared by:** SOC Engineering  
**Classification:** Internal Training / Defensive Use  
**Purpose:** Provide simulation-design realism without publishing operational attacker infrastructure.

## Executive Summary

The phishing kit analyzed in Module 4 was designed to mimic a healthcare identity workflow rather than a generic webmail login. Its design depended on three factors that made the lure credible to MedDefense staff:

1. It used healthcare workflow language, including "clinical portal verification," "patient record access," and "secure message review."
2. It presented urgency as an operational consequence: interruption to patient-chart access rather than simple account expiration.
3. It reduced friction by pre-filling a user identifier and visually copying the organization's authentication flow.

This kit should be treated as the primary realism reference for 6x04. Templates should imitate the *pressure patterns* and workflow timing of the kit, not the credential-harvesting mechanics. Simulation links must route only to approved training infrastructure.

## Kit Components Observed

| Component | Defensive Observation | Simulation Design Implication |
|---|---|---|
| Landing page | Copied clinical portal sign-in layout with familiar header and badge colors | Employees respond to visual familiarity; simulation pages should teach visual verification, not shame |
| Pre-filled username | Link contained a user-like token that filled the username field | Attackers reduce friction; training should teach not to trust prefilled identity |
| Countdown language | "Access verification required before next shift" | Clinical timing pressure is more convincing than generic password-expiry language |
| Mobile rendering | Page rendered cleanly on phone screens | Staff may click from mobile during shift transition or break periods |
| Tracking pixel | Kit marked message opens separately from credential submissions | Campaign metrics should distinguish delivery, open, click, report and training completion |
| Fake help link | "Contact IT" link looped back to same page | Teach employees to use known internal contact paths, not links inside suspicious messages |
| Brand impersonation | Used non-MedDefense domain resembling a healthcare vendor | Template review must include domain-lookalike risk cues |

## Lure Language Patterns

The kit avoided exaggerated errors and obvious scam phrasing. It used neutral operational language:

- "verification required"
- "patient record access"
- "secure clinical portal"
- "next scheduled shift"
- "manual review"
- "security update"
- "temporary access hold"

This is important. Realistic simulations should not contain spelling mistakes or cartoonish threats. The learning objective is not "spot bad grammar"; it is "verify unexpected workflow-impacting requests."

## Targeting Assumptions Extracted

| Assumption | Evidence from Kit | Relevance to MedDefense |
|---|---|---|
| Clinical staff fear blocked EHR access | Lure threatened portal hold | Nurses and physicians rely on Epic at shift start |
| Administrative staff respond to compliance framing | Alternate page copy referenced "policy review" | Billing and HR process compliance tasks routinely |
| IT staff require more specific lures | Kit included fake internal ticket number field | IT templates should include ticket/change references |
| Executives require authority/social proof | No generic executive lure in kit | BEC templates should use names and workflow context |

## What Not To Copy Into Training

The training program must **not** recreate or distribute operational credential-harvesting details. Do not include:

- attacker hosting instructions
- bypass or evasion language
- real credential collection fields
- real external phishing domains
- instructions for defeating email security
- tracking beyond approved simulation telemetry

## Safe Simulation Translation

| Real Kit Behavior | Safe Training Equivalent |
|---|---|
| Credential page copies login UI | Landing page explains how login-page visual familiarity is abused |
| Username prefill | Template notes "pre-filled identity is not proof of legitimacy" |
| Countdown pressure | Training highlights urgency as a decision-pressure cue |
| Fake IT contact link | Guidance instructs users to use Outlook report button or ext. 4-SECURITY |
| Open tracking | Campaign metrics track only approved simulation events |

## Design Takeaways for Tasks

Task 1 should describe healthcare-specific lures instead of generic phishing categories.  
Task 2 should schedule templates around workflow pressure windows.  
Task 3 should include credible operational consequences, not exaggerated threats.  
Task 4 should teach from exact lure signals.  
Task 6 should include caller verification behavior, because the kit relied on trust in apparent internal process.

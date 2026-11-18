# Social Engineering Threat Profile: MedDefense Health Systems

**Prepared by:** Tales Lima, IT Security
**Date:** 2026-11-18
**Distribution:** Security Team, CISO, HR (Section 5 only)
**Approval required:** CISO (`materials/campaign_design/simulation_ethics_guidelines.md`)

---

This profile describes how social engineering attacks reach MedDefense staff, based on the campaign that started the Cobalt Strike incident (MD-PHISH-Q1-2026) and on the healthcare patterns in the provided threat intelligence. It is the design brief for the phishing templates (`phishing_templates.md`) and the campaign plan (`phishing_campaign_plan.md`).

**What happened in March 2026.** The attacker delivered 41 emails in 36 hours. 23 people clicked (56%), 6 submitted credentials and only 6 reported (15%). The first click came 9 minutes after delivery, at 07:07, before a clinical shift handoff. Mean time to first click was 11 minutes; mean time to report was 74 minutes. No report arrived before the first click, and only 2 reports came in before the SOC alert (`campaign_reconstruction.md`, `module5_incident_summary.md`). The SIEM caught the beacon, but credentials were already exposed.

## 1. Target Analysis

Ranked by how many lures each population received in MD-PHISH-Q1-2026 (`post_incident_click_rate_review.md`) and by the sector patterns in `healthcare_social_engineering_patterns.md`.

### Population A: Clinical Staff (Nurses, Patient Care Technicians, Clinical Assistants, Nursing Supervisors)

**Targeting frequency:** Highest. 20 of 41 lures (49%) went to clinical floor staff and nursing supervisors, in two waves (06:58 and 19:05). Click rate 67% for floor staff and 60% for supervisors; report rate 7% and 20%. Segments SEG-B (860) and SEG-A (115).
**Susceptibility factors:** Every task depends on Epic: orders, medication administration, handoff notes. Staff work rotating 24x7 shifts on shared kiosks and phones, and "everything in clinical work feels urgent," so urgency does not stand out. Several said that losing Epic access means they cannot do their job.
**Attacker access objective:** Epic credentials, which give access to ePHI and a foothold on clinical workstations. In March this led to credential exposure, a beacon and later service-account misuse (`cobalt_strike_phishing_path.md`).
**Exploitation timing:** Shift start and handoff (07:00-08:30 and 19:00-20:30), when staff sign in to Epic and read handoff notes. The first click came at 07:07, before handoff; the evening wave produced multiple clicks within 16 minutes. The phishing kit was built for phone screens because staff click from mobile during transitions (`phishing_kit_analysis_summary.md`).

### Population B: Finance, Procurement and Executives (with Executive Assistants)

**Targeting frequency:** Second. 9 of 41 lures (finance 5, executives and assistants 4) in a 13:15 "document review and payment approval" wave. Click rate 40% (finance) and 50% (executives and assistants); executives reported none. Segments SEG-E (75) and SEG-F (35).
**Susceptibility factors:** Finance staff open more than they click, but they are more likely to reply or act offline. Requests from executives are time-sensitive and confidential, and staff are reluctant to slow down a director. The finance sample routed replies to an unrelated mailbox (Reply-To mismatch, `email_header_inspection_results.md`).
**Attacker access objective:** A high-impact action, not a password: payment approval, a vendor banking change, release of a confidential document or board packet. One successful action can cost more than many clinical clicks.
**Exploitation timing:** Late Friday morning before vendor payment runs, and around month-end close and board dates. Mid-day (13:15) for the March executive wave.

### Population C: Administrative, Billing and Registration Staff (including HR and remote admin staff)

**Targeting frequency:** Third. 8 of 41 lures, delivered at 09:44 with a compliance/MFA theme. Click rate 63% and report rate 25%. The first billing report came at 10:02, after two coworkers had already clicked. Segment SEG-C (420, including 84 remote administrative staff).
**Susceptibility factors:** Billing, registration and HR staff complete compliance tasks, portal requests and benefits forms routinely and want to clear them quickly. Remote staff depend on VPN and email for every task.
**Attacker access objective:** Billing portal, HRIS and email credentials, which lead to payroll and banking data, patient demographic and billing records, and a mailbox to send internal phishing from. Remote access credentials if the lure targets VPN or MFA enrollment.
**Exploitation timing:** Tuesday to Thursday mid-morning (the March wave arrived at 09:44), around compliance deadlines, open enrollment and payroll close.

IT staff (SEG-D) received 4 lures and clicked least (25%), but they respond to vendor-support and change-window lures, and their risk is the privileged action that follows, not the click (Vector 3).

## 2. Attack Vector Inventory

### Vector 1: EHR System Impersonation (Email)

**Description:** An email that copies an Epic account notification and threatens an access hold on patient records. It links to a mobile-friendly copy of the clinical portal sign-in with the username already filled in. The "Contact IT" link loops back to the same page.
**Example lure:** MSG-001, display name "Epic Account Services" from `epic-healthsystems.net`, link text "Complete Epic verification", countdown "Access verification required before next shift" (`email_header_inspection_results.md`, `phishing_kit_analysis_summary.md`). A variant used "Review secure message" from `clinical-message-center.net` against a nursing supervisor (MSG-004, clicked).
**Attacker objective:** Epic credential capture and session access at shift start.
**Targeted asset:** Epic EHR and the ePHI behind it, the clinical workstation, and the path to privileged service accounts used later in the incident.

### Vector 2: MFA and Compliance Enrollment (Email)

**Description:** An email that looks like a routine MedDefense IT compliance task: mandatory MFA enrollment, a remote-access review or a policy acknowledgement, with a deadline. Staff expect these messages after the 6x02 identity program.
**Example lure:** MSG-002, display name "MedDefense IT Compliance" from `meddefense-it-support.org`, link text "Open compliance task". This sample was reported by a billing user, but only after two coworkers had clicked.
**Attacker objective:** Capture the password and enroll the attacker's own MFA device, or get a push approval, so that the attacker owns a fully trusted account.
**Targeted asset:** Microsoft 365 mailbox and SSO session, VPN for remote staff, billing portal and HRIS.

### Vector 3: Vendor Support Impersonation (Email and Phone)

**Description:** An urgent request that looks like it comes from a trusted vendor: an emergency Epic patch, medical device support, or a remote support session during a maintenance window. It often includes a ticket or change number. It may arrive as an email followed by a phone call.
**Example scenario:** MSG-005, "Vendor Patch Coordination" from `nexus-updates-support.net` to the IT helpdesk during a planned maintenance window, link text "Join vendor support queue". It was reported late. In clinical areas the same pattern is a "vendor" calling during an equipment issue and asking for remote access.
**Attacker objective:** A remote support session, an account or a broad admin privilege granted "per vendor." `svc_helpdesk` received Domain Admin exactly this way, and it was never reviewed (`privileged_account_findings.md`).
**Targeted asset:** IAM and admin consoles, remote support tools, the medical device gateway and service accounts.

### Vector 4: Executive Impersonation and Business Email Compromise (Email)

**Description:** A message that appears to come from the CFO office and asks for an urgent document review or a payment approval. It contains no malware and no suspicious link, only authority, confidentiality and a deadline. Replies go to a different mailbox.
**Example scenario:** MSG-003, display name "CFO Office" from `meddefense-exec-mail.com`, link text "Approve document request", with a Reply-To mismatch. The finance recipient opened it but did not click; the risk is that the next one gets a reply or an offline payment.
**Attacker objective:** A fraudulent payment, a vendor banking change or confidential documents, or credentials for the board portal.
**Targeted asset:** ERP and banking portal payment workflows, executive mailboxes and the board portal.

## 3. Lure Effectiveness Analysis

Click-rate ranges are planning ranges from `lure_effectiveness_benchmarks.md`, checked against the March incident.

| Rank | Lure Category | Mechanism | Healthcare Factor | Click Rate Range |
| --- | --- | --- | --- | --- |
| 1 | Epic account suspension or verification | Authority + urgency | Blocked Epic access stops orders, medication documentation and handoff; arriving at shift start it feels like a patient-safety problem, not an IT problem. March: 67% of floor staff clicked | 40-62% |
| 2 | Secure patient message | Familiarity + urgency | Clinicians receive patient-context alerts all day; "Review secure message" looks like normal work. March: supervisor sample MSG-004 clicked | 34-50% |
| 3 | MFA or compliance enrollment | Familiarity + authority | After the IAM audit, staff expect MFA and compliance tasks from IT; billing staff clear tasks quickly. March: 63% of billing and admin clicked | 25-42% |
| 4 | HR benefits deadline | Urgency + scarcity | Losing benefits or pay is a personal, immediate consequence and drives action even in cautious staff | 22-38% |
| 5 | Vendor emergency support | Authority + urgency | Clinical and IT operations depend on vendors, and support during an outage or maintenance window is expected | 18-35% |

Executive and BEC requests (authority + social proof) have the lowest click rate (8-22%) but the highest impact. A single reply or payment matters more than the click rate, so BEC is measured by verification behavior, not clicks.

## 4. Detection and Disruption Opportunities

| Vector | Where the user can break the chain | What to notice | What to do | Why it is hard in practice |
| --- | --- | --- | --- | --- |
| 1. Epic impersonation | Before clicking the link, and again at the sign-in page | Sender domain is not MedDefense or Epic's real domain; an unexpected "verification"; a deadline tied to the next shift; username already filled in | Do not use the link. Open Epic from the usual shortcut. Press the Outlook Report Phishing button. If already clicked, report anyway | Arrives at 07:00-08:30 under handoff load, often on a phone where the domain is hidden; staff fear losing access; the page looks exactly like the real sign-in |
| 2. MFA and compliance | When asked to sign in or approve MFA from an email | MedDefense IT does not send login tasks from new external domains; process link text ("Open compliance task"); any MFA prompt you did not start | Open the known portal bookmark or call the IT helpdesk on the known number. Deny unexpected MFA prompts and report them | The lure matches a real ongoing MFA rollout; display name was more memorable than the domain; some messages passed SPF and DKIM |
| 3. Vendor support | When asked to grant access, run a tool or join a support session | Request comes in during a maintenance window or outage; scope is broader than the approved change; ticket number cannot be found in the ticketing system | Call the vendor back on the number in the approved vendor contact list; check the ticket or change reference; refuse broad admin "per vendor" | The request appears to restore patient care; vendor calls are normal; the person has a believable ticket number and technical vocabulary |
| 4. Executive BEC | Before replying, paying or sending a document | Unusual request for money, banking changes or confidential documents; Reply-To differs from sender; pressure for secrecy and speed | Verify by phone or in person through a known number, never by replying to the thread. Apply the payment verification step every time | No technical indicator; reluctance to challenge a director; deadlines before payment runs; the request may be partly legitimate |

The same lesson applies to all four vectors: verify through a channel you already know, not one the message gives you. Report even after clicking. In March, staff who suspected a problem told coworkers verbally instead of reporting, and several feared that reporting would get someone in trouble.

## 5. Simulation Design Requirements

1. **Use MedDefense systems and workflow language by name.** Templates must reference Epic, MFA enrollment, the HR benefits portal or the CFO office, and use process link text ("Complete Epic verification", "Open compliance task"). They must not rely on spelling errors or exaggerated threats as the teaching cue, because the real kit used neutral operational language.
2. **Time each segment's lures to its real pressure window, inside the safe limits.** Clinical baseline lures go out weekdays 07:15-08:30 or 19:15-20:30. ICU and OR are excluded from broad sends, ED gets a limited sample, and no clinical waves run from November to January or during the Joint Commission window. Billing gets Tuesday-Thursday 09:00-11:00, finance Tuesday-Thursday 10:00-14:00, and executives only after coordination with their assistants (`clinical_schedule_constraints.md`).
3. **Give every template exactly one clear reportable cue and make known-channel verification the scored safe behavior.** The cue must match the vector: an external sender domain for Epic and MFA lures, a callback number that is not on the approved list for vendor lures, a Reply-To mismatch for BEC. For BEC, the success metric is independent verification, not "did not click."
4. **Measure reporting, not only clicking.** Every wave records delivery, click, report and time to report separately, because March showed a 74-minute mean time to report and no report before the first click. The Outlook Report Phishing button must be live and taught before Wave 1, and reporting after a click counts as a positive outcome.
5. **Increase difficulty by wave, without shaming or harmful themes.** Baseline system-impersonation lures come first, then intermediate personal-pressure lures (HR benefits), and only then advanced BEC for SEG-E and SEG-F. Every click leads to immediate microtraining, not another lure, and the same population waits at least 21 days between simulations. Themes prohibited by `simulation_ethics_guidelines.md` are never used (real patient names, disciplinary or termination threats, personal medical emergencies).

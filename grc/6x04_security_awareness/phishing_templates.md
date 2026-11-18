# Phishing Email Templates: MedDefense Health Systems

**Inventory:** T-EPIC-01 (Baseline), T-MFA-02 (Baseline), T-HR-03 (Intermediate), T-BEC-04 (Advanced)
**Prepared by:** Tales Lima, IT Security
**Date:** 2026-11-18
**Ethics review:** Pending. Required before deployment: CISO + HR Director for every template; Clinical Operations Representative for T-EPIC-01; Finance Representative for T-HR-03 (SEG-E) and T-BEC-04
**Approved by:** _________________________ (CISO) Date: _________ | _________________________ (HR Director) Date: _________

Do not deploy without campaign plan sign-off. See `phishing_campaign_plan.md`, Section 6.

## Rules for Simulation Operators (apply to every template)

- **Internal simulation only.** These templates are for the approved MedDefense simulation platform and the waves in `phishing_campaign_plan.md`. They are not to be sent outside an approved wave.
- **Links:** the only link is `[SIMULATION_LINK]`, which the platform replaces with its tracked training URL. The landing page is the post-click training page (`post_click_intervention.md`). It has **no input fields** and collects no password, MFA code or personal data.
- **Sender domains:** `[SIM_DOMAIN_...]` placeholders are replaced with training-only domains owned by the simulation platform and registered for MedDefense training. Never use the real attacker domains from the March incident, real vendor domains (Epic or others), or any domain controlled by a third party.
- **Placeholders** in square brackets (`[First Name]`, `[DATE+2]`, `[CFO_NAME]`) are filled by the platform from the HRIS send list. No real patient names or conditions are ever used.
- **Replies** go to the platform's training mailbox. No human answers them, and they are recorded only as "engaged."
- **Each template has one clear reportable cue** (listed in its header). Do not remove it to make the template harder.

---

## T-EPIC-01: Epic EHR Account Management (Baseline)

**Target segment:** SEG-B (general clinical floor staff); also SEG-A in Wave 1 and the SEG-C registration variant in Wave 3
**Tier:** Baseline
**Mechanism:** Authority + Urgency
**Expected click rate (first exposure):** 40-62% (EHR account suspension benchmark; March floor staff 67%)
**Deployment:** Tuesdays 07:15-08:30 (day cohort) or 19:15-20:30 (evening and night cohort). Exclude ICU and OR during critical coverage windows, ED beyond a 25% sample, any unit under staffing shortage, and November to January.
**Targeting rationale:** Reproduces the pressure pattern of the lure that opened the incident (MSG-001): Epic account verification, a deadline tied to the next shift, process link text, sent at shift start.
**Reportable cue:** the sender domain is external and is neither MedDefense nor Epic; MedDefense IT never asks staff to verify Epic accounts by email link.

---

```text
From: Epic Account Services <notifications@[SIM_DOMAIN_EPIC]>
To: [First Name Last Name] <[employee]@meddefense.org>
Subject: Action required: Epic account verification before your next shift
```

Dear [First Name],

Our records show that a security verification on your Epic account could not be completed.

To protect patient information, MedDefense places a temporary access hold on Epic accounts that remain unverified after 48 hours. During an access hold you will not be able to open patient records, document medication administration or review handoff notes.

Please complete verification before **11:59 PM on [DATE+2]** to avoid an interruption to patient record access:

**[Complete Epic verification]([SIMULATION_LINK])**

Verification takes about one minute and can be completed from a workstation or your phone.

If you believe this message was sent in error, you may request a manual review through the link above.

Epic Account Services | Clinical Portal Security
Sent on behalf of MedDefense Health Systems Information Security

---

**Attacker notes:** A real attacker registers a lookalike vendor domain a few days before the campaign and signs the mail so it passes SPF and DKIM, as the March sample did. The link leads to a copy of the clinical portal sign-in that renders cleanly on phones and pre-fills the target's username, removing one moment of hesitation. The "manual review" option loops back to the same page instead of reaching IT. Open tracking tells the attacker who read it, and the evening wave catches the night shift with the same lure.

**Operator safety note:** No real patient names, units or conditions. If a real Epic outage, downtime or verification campaign is announced, cancel the send.

---

## T-MFA-02: IT Helpdesk MFA Enrollment (Baseline)

**Target segment:** SEG-C (administrative and billing staff); also SEG-D, SEG-E, SEG-F in Wave 1 and SEG-B in Wave 2
**Tier:** Baseline
**Mechanism:** Familiarity + Authority
**Expected click rate (first exposure):** 25-42% (MFA/compliance benchmark; March billing and admin 63%)
**Deployment:** Wednesdays 09:00-11:00 for SEG-C. Not during payroll close or month-end. Remote administrative staff are included.
**Targeting rationale:** After the 6x02 identity audit, MedDefense is enrolling staff in MFA and tightening remote access. Staff expect compliance tasks from IT, so the lure copies a routine task (MSG-002, "Open compliance task").
**Reportable cue:** the message comes from an external domain while claiming to be MedDefense IT, and the link does not lead to the known MedDefense portal bookmark.

---

```text
From: MedDefense IT Compliance <it-compliance@[SIM_DOMAIN_IT]>
To: [First Name Last Name] <[employee]@meddefense.org>
Subject: Required: complete MFA enrollment by [DATE+5] (Identity Security Program)
```

Hello [First Name],

As part of the MedDefense Identity Security Program, multi-factor authentication (MFA) is now required for all staff who access email, the billing portal, HR systems or remote access.

Our records show your account has **not yet completed MFA enrollment**. Accounts that are not enrolled by **[DATE+5]** will be limited to on-site access until enrollment is completed, in line with the updated access policy.

Enrollment takes about three minutes:

1. Open your compliance task: **[Open compliance task]([SIMULATION_LINK])**
2. Confirm your MedDefense account.
3. Register your phone for sign-in approvals.

Thank you for helping protect patient and employee information.

MedDefense IT Service Desk
Identity Security Program | Ticket reference: [TICKET_ID]

---

**Attacker notes:** A real attacker times this to match a real MFA rollout and copies the wording of actual IT notices, so it is indistinguishable from legitimate change communication. The sign-in page captures the password and then asks the victim to approve the attacker's MFA registration, so the attacker owns a fully enrolled account. A real ticket-number format and an internal-looking sender name make it pass a quick glance. Remote staff are prioritized because their VPN access is the most valuable.

**Operator safety note:** Coordinate with IT so this does not overlap a real MFA enrollment notice to the same people in the same week. Landing page must not ask for any MFA code or phone number.

---

## T-HR-03: HR Open Enrollment Benefits Deadline (Intermediate)

**Target segment:** SEG-C and SEG-E (administrative and finance staff); also SEG-F in Wave 2 and SEG-A, SEG-D in Wave 3
**Tier:** Intermediate
**Mechanism:** Urgency + Scarcity
**Expected click rate (first exposure):** 22-38% (HR benefits deadline benchmark)
**Deployment:** Wednesdays 09:00-11:00 (SEG-C) or 10:00-14:00 (SEG-E). Not during real open enrollment, payroll close, month-end close or audit submission days. HR department staff only with HR Director approval.
**Targeting rationale:** Every employee goes through benefits enrollment, and a lost benefit is a personal financial consequence, which drives action even in cautious staff. It adds personal pressure on top of a trusted process (intermediate tier).
**Reportable cue:** benefits are always accessed through the known intranet path to the HR portal; HR does not send personal enrollment links from external senders.

---

```text
From: MedDefense Benefits Center <benefits@[SIM_DOMAIN_HR]>
To: [First Name Last Name] <[employee]@meddefense.org>
Subject: Your benefits elections are incomplete: enrollment closes [DATE+3]
```

Hi [First Name],

Our records show that your benefits elections for the upcoming plan year are **incomplete**. One or more required confirmations (dependent verification or plan selection) have not been submitted.

If elections are not completed by **5:00 PM on [DATE+3]**, your current selections cannot be carried forward and you will be enrolled in the default plan. Changes after the deadline are only possible after a qualifying life event.

Review and confirm your elections here:

**[Review my benefits elections]([SIMULATION_LINK])**

The review takes less than five minutes. Please have your dependent information available.

Questions? Reply to this email and a benefits specialist will respond within one business day.

MedDefense Human Resources | Benefits Center

---

**Attacker notes:** A real attacker sends this during the real open-enrollment period, when HR communications are frequent, and copies the HR portal's look. The goal is HRIS and payroll credentials, which allow direct-deposit changes and theft of employee and dependent personal data. "Reply to this email" moves the conversation to an attacker mailbox where a person can ask for more data. Sending near a payday increases the sense of financial consequence.

**Operator safety note:** No reference to termination, pay loss, medical conditions or named dependents. Default-plan enrollment is the only consequence mentioned. Do not send in the weeks of a real enrollment window.

---

## T-BEC-04: Executive Wire Fraud (Advanced)

**Target segment:** SEG-F and SEG-E (executive assistants, executives, finance and procurement staff)
**Tier:** Advanced
**Mechanism:** Authority + Social proof
**Expected click rate (first exposure):** 8-22% (executive/BEC benchmark). The primary measure is **verification**: the safe outcome is calling the CFO office on a known number or reporting the message, not just "did not click."
**Deployment:** Wednesday (SEG-E) 10:00-14:00 and Thursday (SEG-F) at a time agreed with each executive assistant. Never on board meeting days, month-end close day, audit submission day or before a real payment run. Wave 3 and Wave 4 only, after baseline and intermediate exposure.
**Targeting rationale:** Executive and finance staff click less but are exposed to high-impact actions. The March sample (MSG-003, "CFO Office", Reply-To mismatch, "Approve document request") was opened. Peer finance executives were targeted with near-identical wire fraud attempts in Q1 2026.
**Reportable cue:** the reply address is different from the sender, and the request asks for urgent, confidential financial action by email. The required MedDefense practice is independent verification through a known phone number.

---

```text
From: [CFO_NAME], Chief Financial Officer <[cfo.firstname.lastname]@[SIM_DOMAIN_EXEC]>
Reply-To: [cfo.office]@[SIM_DOMAIN_EXEC_ALT]
To: [First Name Last Name] <[employee]@meddefense.org>
Subject: Confidential: vendor settlement approval needed before 3 PM today
```

[First Name],

I need your help with something time-sensitive. We are closing a confidential vendor settlement related to the imaging services contract, and [CEO_NAME] and the finance committee have already signed off. Legal has asked that we keep this off the general distribution list until it is announced.

The settlement document and the updated remittance details are here:

**[Review settlement document]([SIMULATION_LINK])**

Please review and confirm the payment can be released in today's run. I am in back-to-back meetings until this afternoon, so email is the best way to reach me. Just reply here once it is done.

Thanks for handling this quickly. I know I can count on you.

[CFO_NAME]
Chief Financial Officer, MedDefense Health Systems
Sent from my phone

---

**Attacker notes:** A real attacker researches the organization first: real executive names from public sources, the real vendor and contract names, the board and payment calendar. It may not include a link at all, only a request to change a vendor's bank details or release a payment, which leaves no technical indicator for the mail gateway. "Sent from my phone" and "in meetings" explain the short style and block a phone check. The Reply-To sends every answer to the attacker, who continues the conversation and can follow with a phone call that "confirms" the request. If the attacker has compromised a real executive mailbox, even the sender address is genuine.

**Operator safety note:** The landing page contains no payment form, bank details or document. No real vendor, contract value or account number is used; `[CFO_NAME]` and `[CEO_NAME]` are used only with the named executives' prior agreement. Notify the CFO office and Finance Representative before each send so a real payment is never delayed or released because of the simulation. If a recipient phones the CFO office to verify, the office confirms it is a training exercise and thanks them; this is recorded as the correct behavior.

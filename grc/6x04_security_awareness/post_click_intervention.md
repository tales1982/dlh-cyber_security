# Post-Click Intervention Design: MedDefense Health Systems

**Prepared by:** Tales Lima, IT Security
**Date:** 2026-11-18
**Owner:** IT Security Awareness Lead
**Approval required:** HR Director + Communications Lead (content); CISO (launch)
**Sources:** `phishing_templates.md`, `phishing_campaign_plan.md`, `materials/templates/post_click_microtraining_reference.md`, `materials/campaign_design/hr_privacy_rules.md`, `materials/campaign_design/simulation_ethics_guidelines.md`, `materials/program_governance/metrics_baseline.csv`

## Design Principles

The moment after a click is when an employee is most ready to learn. In the March incident several employees did not report after clicking because they feared blame (`post_incident_click_rate_review.md`). The post-click experience must therefore do three things in under 5 minutes: remove the fear, show exactly what in that email was the warning, and make reporting the obvious next step.

- **Same session:** the landing page opens directly from `[SIMULATION_LINK]`; no login, no input fields, nothing collected except the platform's click event.
- **Non-shaming language only.** Use: "This message was designed to feel realistic", "You are not in trouble; this is a training moment", "Reporting after a click still helps." Never use: "You failed", "You were fooled", "This was obvious", "You should have known."
- **Teach from the actual email.** Each page shows a thumbnail of the template the employee received with the cues highlighted.
- **Works on a phone and a clinical kiosk.** Clinical staff click from phones at shift start (`phishing_kit_analysis_summary.md`). Pages are single-column, readable in one scroll per section, and the module can be paused and resumed within 72 hours.
- **Private.** Completion is recorded for the program manager only (`hr_privacy_rules.md`). Target: 90% completion within 72 hours at Day 90 (`metrics_baseline.csv`).

Every landing page follows the same order: (1) this was a simulation, (2) why it was convincing, (3) what to notice next time, (4) what a real attacker could gain, (5) what to do now, (6) how to report, followed by the microtraining.

## 1. Landing Page Variants

### LPV-01: Epic Account Verification (T-EPIC-01)

> **This was a MedDefense training simulation. You are not in trouble.**
>
> The email you just opened, "Action required: Epic account verification before your next shift", was sent by the MedDefense security team to help staff practice spotting messages like the one that started the March 2026 security incident. Nothing was collected and your Epic account is fine.
>
> **Why it was convincing.** It used the name Epic, talked about patient records and handoff notes, and arrived right before your shift, when you most need access. It was designed to feel realistic, because the real one did: in March, two out of three floor staff who received a similar email clicked it.
>
> **What gave it away:**
>
> 1. **The sender address.** The name said "Epic Account Services", but the address after the @ was not MedDefense and not Epic. Anyone can type a display name.
> 2. **An unexpected verification.** MedDefense IT never asks you to verify your Epic account through an email link.
> 3. **The deadline.** "Before your next shift" and "48 hours" are there to make you rush. Urgency about patient care is exactly when to slow down for 10 seconds.
>
> **What to do now:** nothing is wrong with your account. Take the 5-minute walkthrough below. If you ever enter your password after a link like this in real life, report it right away; it is not too late.
>
> **[Start the 5-minute walkthrough]**

### LPV-02: MFA Enrollment (T-MFA-02)

> **This was a MedDefense training simulation. You are not in trouble.**
>
> The email "Required: complete MFA enrollment by [date]" was a practice message from the MedDefense security team. Nothing was collected, and your MFA status has not changed.
>
> **Why it was convincing.** MedDefense really is rolling out MFA, and you regularly receive compliance tasks from IT. That familiarity is what attackers use: in March, more than half of the billing and administrative staff who received a similar "compliance task" email clicked it, and the first report came only after two coworkers had clicked.
>
> **What gave it away:**
>
> 1. **External sender pretending to be MedDefense IT.** The address after the @ was not a MedDefense address. MedDefense IT does not send sign-in tasks from new external domains.
> 2. **"Open compliance task" link.** Real enrollment happens through the MedDefense portal bookmark or the IT Service Desk, not a link in an email.
> 3. **A deadline with a consequence** ("limited to on-site access"), designed to make you finish it quickly.
>
> **What to do now:** take the 5-minute walkthrough. If a real MFA prompt ever appears on your phone when you did not just sign in, tap **Deny** and report it.
>
> **[Start the 5-minute walkthrough]**

### LPV-03: Benefits Enrollment (T-HR-03)

> **This was a MedDefense training simulation. You are not in trouble, and your benefits are not affected.**
>
> The email "Your benefits elections are incomplete" was a practice message from the MedDefense security team, reviewed with HR. Your real elections have not changed.
>
> **Why it was convincing.** Benefits deadlines are real, and losing a benefit feels personal and urgent. That is why attackers use this theme: it makes careful people act fast.
>
> **What gave it away:**
>
> 1. **The link went outside MedDefense.** Benefits are always reached through the intranet path to the HR portal, never through a link in an email.
> 2. **"Reply to this email" for questions.** A real HR team gives you a known contact; replying to a suspicious message only starts a conversation with the sender.
> 3. **Pressure plus scarcity:** "closes in 3 days" and "default plan" push you to act before checking.
>
> **What to do now:** if you want to check your real elections, open the HR portal from the intranet. Then take the 5-minute walkthrough.
>
> **[Start the 5-minute walkthrough]**

### LPV-04: Executive Request (T-BEC-04)

> **This was a MedDefense training simulation. You are not in trouble, and no payment or document was involved.**
>
> The email "Confidential: vendor settlement approval needed before 3 PM today" appeared to come from the CFO. It was a practice message, prepared with the CFO office and Finance, based on real attempts against peer healthcare finance teams this year.
>
> **Why it was convincing.** It came from a senior leader, mentioned that the CEO and finance committee had already agreed, asked for confidentiality and gave a same-day deadline. Challenging an executive feels uncomfortable; attackers count on that.
>
> **What gave it away:**
>
> 1. **The reply address was different from the sender.** Any reply would have gone to someone else.
> 2. **Money and secrecy by email only.** "Keep this off the distribution list" and "email is the best way to reach me" are designed to stop you from checking.
> 3. **No way to verify inside the message.** The safe action was to call the CFO office on the number you already know.
>
> **What to do now:** take the 5-minute walkthrough. Any request involving payments, banking changes or confidential documents should always be verified by phone or in person, using a number you already have.
>
> **[Start the 5-minute walkthrough]**

## 2. Microtraining Modules

Each module takes about 5 minutes: (a) 90 seconds, (b) 60 seconds, (c) 90 seconds, (d) 30 seconds, plus a 30-second check question. The check question is not graded and the answer is shown immediately.

### Module for LPV-01: Epic Account Verification

**(a) What you saw**, the email shown with three highlighted callouts:

| Callout | Annotation |
| --- | --- |
| `Epic Account Services <notifications@...>` | "The name is easy to fake. Look at what comes after the @. It was not meddefense.org." |
| "temporary access hold ... patient records ... handoff notes" | "It was written to make you worry about patient care, so you would act before thinking." |
| "Complete Epic verification" button and "before your next shift" | "Real Epic access issues are handled by the Service Desk. A link plus a shift deadline is the pattern of the March attack." |

**(b) What a real attacker gains:** your Epic username and password. With them, the attacker can open patient records under your name, use your access to move into the clinical network, and start an incident like March 2026, which went from one click to a full incident response in less than a day.

**(c) What to do next time:**

1. Open Epic from your usual desktop shortcut or app, never from an email link.
2. Check the address after the @ before tapping anything about your account, even on your phone.
3. If you are told your access will be blocked, call the IT Service Desk at ext. 4-HELP (a number you already know), not a number in the email.

**(d) How to report (30 seconds):** in Outlook, select the message and press **Report Phishing** (desktop: Home tab; web and mobile: the **...** menu, then **Report**, then **Report phishing**). The email is sent to the security team and removed from your inbox. If you already clicked or entered your password, also call ext. 4-SECURITY. Reporting after a click is the most useful thing you can do.

**Check question:** "An email says your Epic access will be held before your shift. What do you do?" Answer shown: "Report it, then open Epic from your usual shortcut. If you really have a problem, call ext. 4-HELP."

### Module for LPV-02: MFA Enrollment

**(a) What you saw:**

| Callout | Annotation |
| --- | --- |
| `MedDefense IT Compliance <it-compliance@...>` | "MedDefense IT messages come from MedDefense addresses. This one came from outside." |
| "Open compliance task" | "Real enrollment is done from the portal bookmark or with the Service Desk. Hover over or long-press a link to see where it goes." |
| "limited to on-site access" and a 5-day deadline | "A consequence plus a deadline is meant to make you finish quickly." |

**(b) What a real attacker gains:** your password plus an MFA registration on the attacker's phone. That gives them a fully trusted MedDefense account: your email, the billing portal and, for remote staff, VPN access to the network. MFA protects you only if you never approve a request you did not start.

**(c) What to do next time:**

1. Open compliance and enrollment tasks from your saved MedDefense portal bookmark, not from the email.
2. If unsure whether a task is real, call the IT Service Desk at ext. 4-HELP.
3. Never approve an MFA prompt you did not start. Tap **Deny** and report it.

**(d) How to report:** press **Report Phishing** in Outlook (Home tab on desktop; **...** > **Report** > **Report phishing** on web and mobile). For an unexpected MFA prompt, call ext. 4-SECURITY.

**Check question:** "Your phone shows an MFA approval request while you are not signing in. What do you do?" Answer shown: "Deny it and call ext. 4-SECURITY."

### Module for LPV-03: Benefits Enrollment

**(a) What you saw:**

| Callout | Annotation |
| --- | --- |
| `MedDefense Benefits Center <benefits@...>` | "Not a MedDefense address. HR uses the HR portal and known HR contacts." |
| "closes [date] ... default plan" | "Urgency plus something you could lose: the most common pressure in HR lures." |
| "Reply to this email" | "Replying to a suspicious email continues the conversation with the sender, not with HR." |

**(b) What a real attacker gains:** your HR portal login. With it they can change the bank account where your salary is paid, and read your and your family members' personal information (addresses, dates of birth, Social Security numbers).

**(c) What to do next time:**

1. Reach the HR portal from the MedDefense intranet, never from an email link.
2. To check a deadline, use the HR contact listed on the intranet, not the reply button.
3. Treat any message about pay, bank details or dependents as something to verify first.

**(d) How to report:** press **Report Phishing** in Outlook. If you entered your HR password, call ext. 4-SECURITY and change the password from the intranet.

**Check question:** "Where do you go to check your benefits?" Answer shown: "The HR portal, opened from the intranet."

### Module for LPV-04: Executive Request

**(a) What you saw:**

| Callout | Annotation |
| --- | --- |
| `From:` CFO name and `Reply-To:` a different address | "Replies would have gone somewhere else. On a phone, tap the sender name to see both." |
| "[CEO] and the finance committee have already signed off" and "keep this off the distribution list" | "Social proof and secrecy: two reasons not to check with anyone." |
| "release the payment in today's run ... email is the best way to reach me" | "Money, a deadline and a request not to call. That combination is the alarm." |

**(b) What a real attacker gains:** a payment released to the attacker's account, a vendor's bank details changed for future payments, or confidential board and contract documents. A single successful request can cost more than every clinical phishing click combined, and the money is rarely recovered.

**(c) What to do next time:**

1. Verify any request for payment, banking changes or confidential documents by calling the person on a number you already have, or in person.
2. Never confirm by replying to the same email thread.
3. Apply the payment verification step every time, even when the request comes from the most senior person in the organization. Executives have agreed to be called.

**(d) How to report:** press **Report Phishing** in Outlook and tell the Finance Representative or the CFO office through a known number. If any payment or document was sent, call ext. 4-SECURITY immediately; speed matters for recovering funds.

**Check question:** "The CFO emails asking you to release a confidential payment today and says not to call. What do you do?" Answer shown: "Call the CFO office on the known number before doing anything, then report the email."

## 3. Repeat-Click Escalation Protocol

A repeat is a click in **two consecutive waves**; several clicks in the same wave count once (`clinical_schedule_constraints.md`). The protocol follows `hr_privacy_rules.md`: individual results go to a manager only when all four conditions are met (two consecutive clicks, microtraining not completed, HR confirmation, coaching purpose).

| Stage | Trigger | What happens | Who is notified | What the employee is told |
| --- | --- | --- | --- | --- |
| **1. First click** | Click in any wave | Landing page and 5-minute module (above) | No one; recorded for the program manager | "This was training. You are not in trouble. Here is what to look for." |
| **2. Second consecutive click** | Click in Wave N and Wave N+1 | Module for the new template plus a 15-minute role-specific module; private email from the awareness team offering a 15-minute one-to-one walkthrough (optional) | Program manager only | "These messages are designed to be hard. We have put together a slightly longer module for your role, and we are happy to walk through it with you. Your results are private." |
| **3. Training not completed** | Stage 2 and assigned training not completed within 72 hours, after one reminder at 48 hours | Program manager refers the case to HR with the facts (waves, templates, completion status) | HR Director | Nothing until HR decides. If HR declines, the case returns to Stage 2 with another reminder |
| **4. HR-coordinated coaching** | HR confirms the trigger | HR and the manager hold a coaching conversation; a short written coaching plan (training, check-in in 30 days). The security team checks the account's MFA and access, especially for privileged users | HR, then the employee's manager **for coaching only** | "Phishing simulations are training. Because the last two practice emails were clicked and the follow-up training is still open, HR and your manager will help you find a time to complete it. This is not a disciplinary process and will not appear in your performance review." |
| **5. Pattern continues** | Clicks in three or more consecutive waves after coaching | HR reviews whether simulation timing or format is the problem (for example, shift pattern) and may place the employee on an HR-approved support plan, which excludes them from waves for an agreed period. Security adds technical protection (stricter mail filtering, phishing-resistant MFA) | HR, manager (coaching), security (account protection) | Same non-disciplinary framing; the focus is support and protection |

At no stage are simulation results used for performance reviews, promotion, compensation, termination or discipline. Data is retained for 18 months and then aggregated or deleted, unless part of an active HR coaching plan.

## 4. Positive Reinforcement Design

When an employee presses **Report Phishing** on a simulation email, the platform recognizes the simulation ID and sends an automatic response **within 60 seconds**. The SOC does not need to handle it.

**What the employee sees immediately (in Outlook, after pressing the button):**

> "Thanks! Your report has been sent to the MedDefense security team."

**Email received within 60 seconds:**

```text
From: MedDefense Security Team <security@meddefense.org>
Subject: Great catch: that was a training email

Hi [First Name],

Thanks for reporting "[Subject of the simulation email]". It was a MedDefense
training simulation, and reporting it was exactly the right move.

What you may have noticed: [cue for this template, for example
"the sender address was not a MedDefense address even though it said
MedDefense IT Compliance"].

You reported it [N] minutes after it arrived. Fast reports are what let us
stop a real attack before it spreads: in March 2026, the average report took
74 minutes and most clicks happened before the first report.

Nothing else to do. Keep using the Report Phishing button for anything that
feels off, even if you are not sure. A report that turns out to be harmless
is never a problem.

MedDefense Security Team | ext. 4-SECURITY
```

**Proportional and specific:**

- The cue in the message is chosen by template: sender domain (T-EPIC-01, T-MFA-02), HR portal link (T-HR-03), Reply-To and verification (T-BEC-04).
- If the employee **reported after clicking**, the message says: "Thank you for reporting even after opening the link. That is the most valuable thing anyone can do, because it lets us act quickly." This rewards the behavior March showed was missing.
- For T-BEC-04, an employee who **called the CFO office to verify** receives the same confirmation when the office records the call: "You verified through a known channel, which is the exact step that stops payment fraud."
- No badges, rankings or public lists by name. Department managers see only aggregate report-rate trends (for example "Billing report rate rose from 25% to 41% this quarter"), which the Communications Lead may share as team recognition.

**Real emails reported as phishing** (false positives) receive a different automatic message: "Thanks for reporting. Our team will review it. If it was legitimate, nothing is lost, and we would always rather check." This keeps reporting safe even when the employee is wrong.

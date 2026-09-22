# Social Engineering Analysis

Content analysis of the four suspicious emails (E2, E3, E5, E7): what each one asks the reader to do, how it tries to make them do it, and how much the sender had to know about the recipient. Headers and authentication explain how the mail was sent; this file explains how it tries to influence the person who receives it. Source is the evidence batch only; no link was visited and no attachment was opened.

## Targeting scale used

| Level | Meaning |
|---|---|
| GENERIC | The same message could go to anyone. No recipient-specific detail. |
| SEMI-TARGETED | Personalized with public or easily guessed data such as name, email address, organization, department or a common business process. No internal knowledge. |
| TARGETED | Contains information specific to the individual or internal to the organization, such as a per-user token, named internal systems or workflows, that is not trivially public. |

---

## Email 2 — Staff portal re-verification lure

- Psychological lever: urgency (24-hour deadline), backed by authority (sent as "MedDefense IT Security" with an IT ticket number) and fear of losing access to the scheduling system, the EHR gateway and shift swaps.
- Pretext: a security policy update "rolled out this weekend" means every staff member must re-verify portal access. The footer adds a ticket reference, `INC-2026-04-14-7741`, and a confidentiality line to look like a real IT notice.
- Requested action: click **VERIFY MY ACCESS NOW**, which leads to `meddefense-portal.com/verify/staff` with the recipient's username and a token in the query string, and verify (log in) there.
- Targeting level: TARGETED.
- Content red flags:
  - "Within 24 hours" and "immediate re-verification" with a suspension threat.
  - Consequences are chosen for a nurse: scheduling, EHR gateway, shift swap requests.
  - The link goes to `meddefense-portal.com`, not `meddefense.com`, and the button text hides the destination.
  - The URL carries `id=dmarsh` and `token=a8f3e2d1`, a per-recipient link that also lets the sender see who clicked.
  - "This is an automated message. Do not reply." discourages questions.
  - The logo is loaded from the attacker's own domain.
  - It contradicts the genuine E4 notice: IT never emails password links, and the portal is reachable only from inside the network or over VPN.
  - Three high-priority headers on an "IT notice".
- Attacker knowledge required:
  - Diane Marsh's full name and her username format (first initial plus surname, `dmarsh`).
  - That she works at MedDefense with portal and EHR gateway access.
  - The names of internal workflows: a scheduling system, an EHR gateway and shift-swap requests.
  - MedDefense branding (name, logo, brand blue `#0a4d8c`) and what an internal IT ticket number looks like.
  - The batch does not show how this was obtained. A staff directory, social media, a prior breach or earlier reconnaissance would each be enough.
- Conclusion: the most tailored of the four. It combines a named person, her username, nursing-specific consequences and an internal-looking ticket, which is why it is also the only one with a confirmed click. One click does not prove personalization raised the success rate, but it is consistent with it. Treated as credential harvesting.

## Email 3 — Microsoft security alert lure

- Psychological lever: fear (an unrecognized sign-in from Lagos, Nigeria, meaning "your account may have been compromised"), with authority through impersonation of Microsoft and a secondary urgency (a 48-hour lock).
- Pretext: Microsoft detected a sign-in attempt from an unknown Windows device (IP `41.203.72.188`, "April 15, 2026 at 10:47 AM UTC") on the account `rmendez@meddefense.com`.
- Requested action: click **Verify account**, which leads to `outlook-protection.com/verify`, and confirm the account (log in).
- Targeting level: SEMI-TARGETED (low end).
- Content red flags:
  - Sender is `outlook-protection.com`, not a Microsoft domain, presented under the display name "Microsoft Account Protection".
  - A foreign city and an unknown device are chosen to alarm. The location, IP and device cannot be verified from the message.
  - The remedy offered is a link in the same email, when a real account concern is resolved by going to the service directly.
  - A 48-hour lock threat for not verifying.
  - The footer copies "© 2026 Microsoft Corporation" and the Redmond address, and the logo is loaded from `outlook-protection.com/img/ms_logo.png`.
  - The wording is a consumer-style "Microsoft account" alert for a corporate address.
  - The link has no per-user token: one generic URL for every recipient.
- Attacker knowledge required:
  - Rafael Mendez's first name and email address.
  - That the organization is likely to use Microsoft accounts. This is a safe assumption for almost any company, and the lure works without knowing the real tenant. The batch shows an on-premises Exchange 2019 hub (E4), so whether MedDefense actually uses Microsoft 365 for mailboxes is not established by this evidence.
  - Nothing internal: no MedDefense systems, people, roles or processes are mentioned.
- Conclusion: a brand-impersonation template with mail-merge personalization (name and address). It depends on the recipient trusting the Microsoft name and reacting to a fear trigger, not on knowledge of MedDefense. It is the most generic of the four, and no click has been reported. Treated as credential harvesting.

## Email 5 — Invoice lure

- Psychological lever: financial pressure (USD 24,716.38 due in 7 days, a 2% late fee and suspension of future deliveries), with impersonation of a supplier and the routine authority of an ordinary business process.
- Pretext: a supplier, "MedEquip Supplies", invoices MedDefense for medical supplies "delivered on April 9, 2026", invoice `INV-2026-04891`, due April 23, 2026.
- Requested action: pay through the linked invoice portal (`medequip-supplies.net/invoices/pay`), or if the attachment is not viewable, log in at `medequip-supplies.net/portal/login` to retrieve a copy. There is also a PDF attachment, `INV-2026-04891.pdf`, that carries the same payment link. The email gives three routes to the same domain: click, log in, or open the PDF.
- Targeting level: SEMI-TARGETED.
- Content red flags:
  - Generic greeting "Dear Accounts Payable" despite a named recipient.
  - The AP recipient does not recognize the invoice or the vendor.
  - No purchase order number, contract reference or remittance details. The only contact is a vanity phone number (`1-800-MED-EQUIP`).
  - Payment is requested through a link in the email, not through a vendor-master remittance channel.
  - The "log in to retrieve a copy" fallback funnels the reader to a credential prompt.
  - Late-fee and delivery-suspension threats on a 7-day clock, and `X-Priority: 1` on an invoice.
  - Sender is a `.net` lookalike-style domain with no established history.
- Attacker knowledge required:
  - That MedDefense buys medical supplies, which is true of any healthcare organization.
  - That an Accounts Payable function exists and how to address it (`arivera@`, first initial plus surname).
  - A plausible invoice number format, amount range and delivery date.
  - Not needed: real vendor names, purchase orders or contracts. The AP report that the invoice "looks wrong" suggests the sender lacked that data.
- Conclusion: role-targeted invoice fraud aimed at the AP function, combined with credential harvesting through the login fallback. It relies on a busy AP clerk paying a plausible amount without checking the vendor master. The invoice should not be paid or opened, and the vendor should be verified using a contact already on file.

## Email 7 — Benefits enrollment lure

- Psychological lever: scarcity (an enrollment window "closes at midnight tomorrow"), plus fear of loss (coverage lapses and the employee is defaulted to a basic plan until November 2026) and authority (HR).
- Pretext: "Our records show you have not yet completed your 2026 benefits re-enrollment." The notice is labelled **FINAL NOTICE** with a deadline of April 17, 2026.
- Requested action: click **COMPLETE ENROLLMENT**, which leads to `meddefense-benefits.org/enroll`, and sign in or provide information to enroll. The email adds that people who believe they already enrolled should "still verify on the portal".
- Targeting level: SEMI-TARGETED (upper end).
- Content red flags:
  - "FINAL NOTICE" in a red header and a next-day deadline, sent on the afternoon before it, which leaves little time to check.
  - A coverage-lapse threat.
  - "Still verify" removes the excuse for anyone who has already enrolled.
  - The link goes to `meddefense-benefits.org`, a `.org` lookalike, not to the real HR or benefits system.
  - The recipient, Linda Patterson in Billing, says she never signed up for anything, which conflicts with the claim that her records show a pending re-enrollment.
  - No plan names, no HR contact and no reference number.
  - The footer repeats the recipient's address to look personal.
- Attacker knowledge required:
  - Linda's first name and email address.
  - That MedDefense has a benefits program with an enrollment period, and the name of its HR function.
  - MedDefense branding.
  - Whether an enrollment window really was open on those dates is not established by the batch and should be confirmed with HR. An HR-themed lure landing in a Billing mailbox suggests a workforce-wide pretext, not one crafted for her role.
- Conclusion: an organization-themed lure with first-name personalization and a deadline, relying on public information and a benefits process every employee knows. It is more MedDefense-specific than E3, less individually tailored than E2. Treated as credential harvesting.

---

## Comparison

| Email | Primary lever | Requested action | Deadline in the lure | Targeting |
|---|---|---|---|---|
| E2 | Urgency, authority, fear of lockout | Click and log in | 24 hours | TARGETED |
| E3 | Fear, impersonation of Microsoft | Click and log in | 48 hours | SEMI-TARGETED (low) |
| E5 | Financial pressure, vendor impersonation | Click, log in or open PDF, pay | 7 days | SEMI-TARGETED |
| E7 | Scarcity, fear of loss, HR authority | Click and log in | About 1 day | SEMI-TARGETED (high) |

- All four attach a deadline to a consequence and send the reader to an external lookalike domain. This matches the pattern described in the HC3 alert (E8): 24 to 48 hour deadlines, lockout threats, enrollment cutoffs and role-flavoured lures.
- Each email uses a different pretext family: internal IT, Microsoft security, supplier invoice, HR benefits. Different lures with the same PHPMailer toolchain (see `1-header_analysis.md`) point to one playbook applied across roles, with the personalization set to whatever data the sender had for each recipient.
- The batch shows one recipient per email, so the number of staff who received each lure is unknown.

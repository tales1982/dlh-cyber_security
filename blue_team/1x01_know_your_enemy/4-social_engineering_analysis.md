
# 4. The Human Vector Social Engineering Analysis

**Analyst:** Threat Intelligence Analyst
**Date:** Current

## Instructions Recap

For each of the 7 scenarios below, complete the block. Use the exact Sec+ 2.2 vector term, be specific about the target and why they're vulnerable, pick the dominant psychological lever, list 3 concrete red flags found in the scenario text, and propose one technical + one administrative control.

---

## Scenario 1 FortiGate Firmware Email to Sarah Park

```
Vector Type: Phishing (brand impersonation of Fortinet support)
Target: Sarah Park, IT Director she owns the FortiGate directly, so a firmware
  alert lands squarely inside her job responsibility and reads as plausible,
  routine vendor correspondence rather than an unsolicited message.
Psychological Lever: Urgency (24-hour deadline, threat of service termination)
Red Flags:
  1. Sender domain is fortinet-support.net, not Fortinet's real support domain.
  2. The "patch" arrives as an email link rather than through the official
     FortiGate management console or Fortinet's normal advisory channel.
  3. The threat of "service termination" for not patching within 24 hours is
     manufactured pressure vendors don't threaten to cut off a customer
     over a delayed patch.
Technical Control: Email security gateway with domain reputation/DMARC
  enforcement and automatic link sandboxing for external URLs.
Administrative Control: A policy requiring IT staff to verify "critical"
  vendor security alerts through the vendor's official portal or a known
  account rep before acting, never through a link in the email itself.
```

---

## Scenario 2 CEO Wire Transfer Request to Robert Kim

```
Vector Type: Business Email Compromise (BEC)
Target: Robert Kim, CFO — he holds the authority to move large sums, and the
  message is engineered to look like a direct order from his own CEO.
Psychological Lever: Authority (impersonating the CEO) reinforced by Urgency
Red Flags:
  1. The sender address has a subtle difference from the CEO's real email.
  2. The instruction to "not discuss with anyone" is an isolation tactic that
     bypasses MedDefense's normal financial oversight and approval process.
  3. "Email only, I'm in meetings all day" pre-emptively blocks the one
     verification step (a phone call) that would expose the fraud.
Technical Control: Email authentication enforcement (SPF/DKIM/DMARC) plus a
  banner flagging external senders whose display name matches an internal
  executive.
Administrative Control: Mandatory out-of-band verification a call to a
  known, pre-saved number, not any number in the email for any wire
  transfer request, especially one explicitly asking to skip normal process.
```

---

## Scenario 3 "Mike from IT" Password Request

```
Vector Type: Vishing (voice phishing), using a pretexted "security audit" cover
Target: A nurse at MedDefense Central clinical staff are trained to be
  helpful and are focused on patient care, not trained to challenge an
  internal IT caller's authority, especially right after a real incident.
Psychological Lever: Authority (posing as IT) reinforced by Helpfulness
Red Flags:
  1. Legitimate IT never needs a user to read a password aloud over the phone.
  2. The caller's identity ("Mike from IT") could not be independently
     verified no callback through a known IT helpdesk number occurred.
  3. The recent, real billing-server incident is used as false legitimacy to
     make an invented "emergency audit" sound plausible.
Technical Control: A self-service, MFA-backed password reset process so
  that IT staff never need or ask for a user's actual password.
Administrative Control: A hard policy that no one, including IT, requests a
  password over the phone, paired with mandatory callback verification
  through the official helpdesk number before any credential action.
```

---

## Scenario 4 Parking Permit SMS

```
Vector Type: Smishing (SMS phishing)
Target: All MedDefense employees a parking permit notice is mundane and
  universally relevant, so it doesn't trigger the suspicion a high-value
  request would, and most security training never covers SMS at all.
Psychological Lever: Urgency (avoid getting towed)
Red Flags:
  1. An unsolicited SMS containing a link is itself unusual for an HR/parking
     notice, which would normally arrive by email or the internal portal.
  2. The link leads to a page requesting AD (domain) credentials no
     legitimate parking-renewal workflow needs a network login.
  3. The URL does not match any MedDefense-owned domain.
Technical Control: Mobile device management (MDM) with URL reputation
  filtering on corporate devices, blocking navigation to known-bad or
  unrecognized domains before a credential form can even load.
Administrative Control: Security awareness training that explicitly covers
  smishing (most training focuses only on email), plus clear communication
  that the intranet is the only legitimate channel for staff notices.
```

---

## Scenario 5 Regional Healthcare Association Website Compromise

```
Vector Type: Watering Hole Attack
Target: MedDefense physicians who visit the Regional Healthcare Association
  site monthly for CME credits it's a routine, trusted destination they
  don't treat with the same caution as an unsolicited email or link.
Psychological Lever: Familiarity (trust in a habitual, expected destination)
Red Flags:
  1. An unexpected redirect, pop-up or plugin/update prompt appearing on a
     site that has never asked for one before.
  2. Unusual browser or workstation behavior shortly after visiting a routine
     professional site (slowdown, unexpected background activity).
  3. Any prompt to download or run something to "view" association content
     that previously loaded normally without it.
Technical Control: A secure web gateway with browser isolation/sandboxing
  that intercepts exploit attempts before they reach the endpoint, combined
  with current, enforced browser patching on all workstations.
Administrative Control: A policy extending endpoint protection and patch
  management to cover browsers organization-wide, closing the same kind of
  coverage gap already flagged for servers in 1x00 (GAP-005).
```

---

## Scenario 6 meddefence-portal.com

```
Vector Type: Typosquatting combined with Brand Impersonation
Target: Patients searching for the MedDefense patient portal (and any staff
  who might land on the page while assisting one) patients don't have the
  real URL memorized, rely on search results, and won't notice a one-letter
  domain difference in a pixel-perfect copy.
Psychological Lever: Familiarity (trust in what looks like the top, correct
  search result)
Red Flags:
  1. The domain reads "meddefence" instead of "meddefense" a one-letter
     typosquat easy to miss at a glance.
  2. The result is a paid/sponsored ad ranked above the real organic result,
     which itself is a reason to check the URL before clicking.
  3. The page is visually identical to the real portal but sits on a domain
     MedDefense does not own.
Technical Control: Defensive registration of common typo-variant domains
  plus a lookalike-domain monitoring service that flags new registrations
  resembling MedDefense's brand for takedown.
Administrative Control: Proactive patient communication (in appointment
  reminders, on the real portal) stating the one correct URL and warning
  patients about lookalike sites, backed by a legal takedown process.
```

---

## Scenario 7 Tailgating in Scrubs

```
Vector Type: Impersonation (physical social engineering / tailgating)
Target: MedDefense staff near the badge-controlled IT corridor employees
  are conditioned to be polite and hold doors for anyone who visually looks
  like a colleague, and aren't trained to scrutinize a badge closely.
Psychological Lever: Familiarity (the visual costume of belonging — scrubs,
  stethoscope, hospital-branded cup) reinforced by social politeness norms
Red Flags:
  1. The person follows someone through the door instead of badging in
     themselves piggybacking through a controlled door is the core red flag.
  2. The explanation ("my badge is in my locker") is a classic pretext used
     specifically to avoid producing credentials on demand.
  3. The visitor badge, though present, is expired and was partially
     concealed rather than clearly displayed.
Technical Control: Anti-tailgating enforcement at the badge reader (a
  mantrap/turnstile, or an alarm that flags more than one person passing on
  a single badge swipe).
Administrative Control: A formally trained "no-piggybacking" policy that
  empowers and expects every employee to politely challenge or verify anyone
  following them through a secured door the same physical-security
  discipline already missing at the network closet (GAP-006 in 1x00).
```

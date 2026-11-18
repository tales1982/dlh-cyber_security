# Email Header Inspection Results

**Case ID:** MD-SOC-M4-HEADER-0426  
**Source:** Module 4 email header inspection lab  
**Prepared by:** SOC Analyst Team  
**Classification:** Internal Training / Defensive Use

## Purpose

This artifact provides realistic header-level observations from the phishing campaign analyzed in Module 4. It is intended to guide simulation realism and reporting guidance. It should not be used to build delivery infrastructure.

## Message Samples Reviewed

| Sample ID | Target Group | Claimed Sender | Actual Sender Domain | Final User Action |
|---|---|---|---|---|
| MSG-001 | Clinical staff | Epic Account Services | `epic-healthsystems.net` | Clicked |
| MSG-002 | Billing staff | MedDefense IT Compliance | `meddefense-it-support.org` | Reported |
| MSG-003 | Finance | CFO Office | `meddefense-exec-mail.com` | Opened only |
| MSG-004 | Nursing supervisor | Secure Clinical Message | `clinical-message-center.net` | Clicked |
| MSG-005 | IT helpdesk | Vendor Patch Coordination | `nexus-updates-support.net` | Reported late |

## Header Findings

### Finding 1: Display Name Was More Persuasive Than Domain

Most recipients who clicked recalled the display name but not the sender domain. This supports training that teaches employees to inspect both sender display name and domain, especially when a message asks for login, payment, document access or workflow-impacting action.

### Finding 2: Authentication Results Were Mixed

Some messages had SPF alignment but failed organizational legitimacy checks because the sending domain was external and newly registered. Employees cannot be expected to read raw headers, but the SOC and mail gateway can use these signals for detection.

Example defensive summary:

```text
Authentication-Results: spf=pass smtp.mailfrom=epic-healthsystems.net;
dmarc=none header.from=epic-healthsystems.net;
dkim=pass header.d=epic-healthsystems.net
```

Training implication: "A message can pass technical checks and still be malicious if the domain is not the real business partner."

### Finding 3: Reply-To Mismatch Appeared in Finance Lures

The executive-themed sample used a visible sender resembling the CFO office but routed replies to an unrelated mailbox. Finance guidance should include "do not resolve payment or document requests by replying to the same email thread; verify through a known channel."

### Finding 4: Timing Increased Credibility

Clinical samples arrived shortly before day shift start and evening shift start. Finance samples arrived late Friday morning before vendor payment runs. IT samples arrived during a planned maintenance window.

### Finding 5: Link Text Was Process-Oriented

The links did not say "click here to reset password." They used process labels:

- "Complete Epic verification"
- "Review secure message"
- "Open compliance task"
- "Approve document request"
- "Join vendor support queue"

## Training Cues To Emphasize

| Cue | Employee-Friendly Language |
|---|---|
| Sender display name mismatch | "The name can be typed by anyone. Check whether the domain fits the real process." |
| Unusual external domain | "MedDefense IT does not send login tasks from new external domains." |
| Urgency tied to patient care | "Urgency is exactly why you should use a known verification path." |
| Reply-to mismatch | "Do not confirm unusual payment or document requests by replying to the message." |
| Workflow timing | "Attackers time messages when people are busiest." |

## Campaign Design Use

- T-EPIC-01 should include a believable sender and domain warning opportunities.
- T-MFA-02 should look like a compliance task but contain enough cues for reporting.
- T-BEC-04 should include reply-channel verification as the expected safe behavior.
- Vishing scenarios should teach known-channel verification, not caller politeness.

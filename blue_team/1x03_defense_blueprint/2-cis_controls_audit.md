# 2. The CIS Controls Audit MedDefense Health Systems

**Analyst:** Security Analyst
**Date:** Current

## Control Scoring

**CIS Control 1: Inventory and Control of Enterprise Assets**

- Score: Partial
- Evidence: No formal inventory existed before this engagement 1x00 Task 7 built the Asset Registry from scratch and discovered three undocumented shadow-IT devices (A-012, A-023, A-025) in the process, and 1x02 (Findings 028/029) confirmed at least two of them are still unaddressed months later.

**CIS Control 2: Inventory and Control of Software Assets**

- Score: Not Implemented
- Evidence: Windows XP (Finding 004), Windows Server 2012 R2 (Finding 008) and Ubuntu 18.04 without ESM (Finding 011) have all run years past vendor support with no process flagging or addressing this.

**CIS Control 3: Data Protection**

- Score: Partial
- Evidence: A data classification scheme exists (1x00 Task 9 defined Restricted/Confidential categories), but access control lists fail in practice (Finding 003, PostgreSQL open network-wide) and encryption is inconsistent (Finding 015, unencrypted NAS backups).

**CIS Control 4: Secure Configuration of Enterprise Assets and Software**

- Score: Not Implemented
- Evidence: Default credentials remain unchanged on 7 of 7 scanned BD Alaris pumps (Finding 010), and default/permissive configurations account for 13 of the 31 findings in the 1x02 vulnerability scan.

**CIS Control 5: Account Management**

- Score: Partial
- Evidence: A password complexity policy exists (1x00, C-006), but SSH password authentication remains enabled on every Linux server except one (Finding 009), and no dormant-account review process was found anywhere.

**CIS Control 6: Access Control Management**

- Score: Not Implemented
- Evidence: No MFA exists anywhere in the environment (GAP-014), the single most frequently cited gap across both the 1x01 threat landscape and the 1x02 kill-chain analysis.

**CIS Control 7: Continuous Vulnerability Management**

- Score: Partial
- Evidence: A vulnerability scan now exists as a one-time deliverable of this engagement (1x02), but no remediation-tracking or automated patch-management process existed before it, and Task 12 found three EOL systems that will never receive automated patches at all.

**CIS Control 8: Audit Log Management**

- Score: Partial
- Evidence: SSH logging (C-005) and FortiGate traffic logging (C-013) exist, but GAP-002 confirms nothing reviews or alerts on them, and retention is capped at 30 days.

**CIS Control 9: Email and Web Browser Protections**

- Score: Not Implemented
- Evidence: No DNS filtering or supported-browser/email-client enforcement was documented anywhere, and phishing succeeds as the initial-access step in Kill Chain #1 (1x01, Task 10) with no described control interrupting it.

**CIS Control 10: Malware Defenses**

- Score: Partial
- Evidence: Sophos is deployed on workstations (C-008) but explicitly excludes every Windows and Linux server (GAP-005) the exact gap that let a cryptominer run undetected on `billing-srv-01` for two weeks (1x00, Task 2).

**CIS Control 11: Data Recovery**

- Score: Partial
- Evidence: Nightly Veeam backups exist (C-009), but GAP-003 confirms they have never been tested at full scale, the NAS-01 repository itself is unencrypted and network-exposed (1x02, Finding 015), and `pacs-srv-01` is explicitly excluded from backup coverage entirely.

**CIS Control 12: Network Infrastructure Management**

- Score: Not Implemented
- Evidence: The entire environment is a single flat `/16` network with zero segmentation (1x00 Task 7 network scan, GAP-012), confirmed independently by 1x02 Task 14's quantified finding that this single architectural gap amplifies the real-world risk of every other vulnerability in the scan.

**CIS Control 13: Network Monitoring and Defense**

- Score: Not Implemented
- Evidence: No intrusion detection/prevention capability or centralized traffic-flow analysis exists anywhere the same absence documented under GAP-002.

**CIS Control 14: Security Awareness and Skills Training**

- Score: Partial
- Evidence: An annual "CyberSafe Basics" training program exists (1x00, C-012), but 1x00 Task 8's Attack Surface Map found completion sitting at only 58-71% with no phishing simulation component.

**CIS Control 15: Service Provider Management**

- Score: Not Implemented
- Evidence: 1x01's Scenario 3 ("The MedTech Backdoor") depends entirely on a vendor (MedTech Solutions) whose remote-access risk was never assessed, inventoried or governed by any MedDefense policy.

**CIS Control 16: Application Software Security**

- Score: Not Implemented
- Evidence: MedDefense does not appear to run a significant internal development shop, but the Patient Portal's broken-access-control/IDOR incident (1x00, Task 1, Incident B) confirms that whatever custom or configured web application logic exists has already produced a real security failure with no secure-development process behind it.

**CIS Control 17: Incident Response Management**

- Score: Not Implemented
- Evidence: GAP-002/G-005 (1x00) confirm no designated incident-handling personnel, no reporting process and no documented enterprise IR plan every prior incident (ransomware, cryptominer, IDOR, pharmacy dosage overwrite) was handled improvised.

**CIS Control 18: Penetration Testing**

- Score: Not Implemented
- Evidence: No penetration test has ever been performed SecurePoint's own 1x02 methodology notes state explicitly that "no active exploitation was attempted," meaning even this engagement's own scan does not substitute for one.

## Scorecard Summary

| Score           | Count        |
| --------------- | ------------ |
| Implemented     | 0            |
| Partial         | 8            |
| Not Implemented | 10           |
| **Total** | **18** |

**Zero controls are fully Implemented.** This is not an overstatement for effect across all three prior projects, every control that exists in some form (backup, training, endpoint protection, logging) is present but incomplete, unverified, or covers only part of what it should. This mirrors the exact pattern identified in the 1x00 Gap Analysis: MedDefense over-invests in initial, partial preventive measures and has almost nothing that is complete, tested, or actively monitored end to end.

## Top 5 Priority Controls

1. **CIS Control 6 (Access Control Management).** Implementing MFA is the single highest-leverage fix available: it appears as the step that would have broken multiple kill chains in 1x01, it is achievable using MedDefense's existing O365 licensing with no new procurement, and it directly closes GAP-014, the most frequently cited gap across the entire three-project engagement.
2. **CIS Control 12 (Network Infrastructure Management).** 1x02's own quantitative analysis (Task 14) already proved that flat-network architecture amplifies the effective risk of every other finding by one to two orders of magnitude, making segmentation the one control whose impact compounds across the entire vulnerability set rather than fixing a single issue.
3. **CIS Control 8 (Audit Log Management), paired with Control 13.** The organization's core failure mode across three projects incidents discovered "by accident, not by design" cannot be fixed by any preventive control; only a functioning detection capability, built on top of the logging that already partially exists, breaks that pattern.
4. **CIS Control 7 (Continuous Vulnerability Management).** Without a repeatable remediation process, the 1x02 vulnerability assessment becomes a one-time snapshot that decays the day after delivery exactly the "point-in-time" limitation that project itself warned about.
5. **CIS Control 11 (Data Recovery).** With ransomware profiled as MedDefense's highest-likelihood, highest-impact threat actor (1x01, Task 6) and Kill Chain #1 explicitly ending in backup destruction, a backup that has never been tested at scale and excludes a Critical asset (PACS) is the single point of failure that turns a recoverable incident into an unrecoverable one.

# Module 5 Incident Summary

**Incident:** MedDefense Cobalt Strike compromise  
**Date range:** 2026-03-25 to 2026-03-26  
**Prepared for:** 6x04 Security Awareness Program  
**Classification:** Internal Training

## Executive Summary

The Module 5 incident began with a phishing campaign that targeted MedDefense employees using healthcare-specific lures. The campaign achieved a 56% click rate. Technical controls eventually detected Cobalt Strike beacon activity, and the IR team contained the incident, but the first failure occurred at the human layer: employees trusted messages that appeared operationally relevant to their work.

## Key Facts

| Fact | Value |
|---|---:|
| Phishing emails delivered | 41 |
| Employees who clicked | 23 |
| Click rate | 56% |
| User reports before SOC alert | 2 |
| Total user reports | 6 |
| Mean time to report | 74 minutes |
| Time from first click to first SOC correlation | 4 hours 33 minutes |
| Confirmed ePHI exfiltration | Not confirmed |
| Confirmed credential exposure | Yes |
| Cobalt Strike beacon detected | Yes |

## Root Causes Relevant to 6x04

1. Employees lacked practical phishing recognition tied to healthcare workflows.
2. Staff did not consistently use the phishing report button.
3. Clinical pressure windows increased click likelihood.
4. Security awareness training completion existed but did not produce behavior change.
5. No structured phishing simulation program was in place.
6. No post-click microtraining existed.
7. Managers lacked guidance for repeat risky behavior without using shame or discipline.

## What Technical Controls Did

- SIEM detected beacon activity.
- IR team activated containment.
- Credential exposure playbook was used.
- Endpoint forensics reconstructed activity.

## What Technical Controls Could Not Do

- Prevent employees from entering credentials into a convincing fake workflow.
- Make staff report suspicious messages quickly.
- Teach employees to verify unusual requests through known channels.
- Provide role-specific training at the moment of failure.

## Program Design Implication

The awareness program should not be built as annual compliance training. It must use behavior measurement, immediate feedback, role-based content and repeat reinforcement.

# Cobalt Strike Phishing Path

**Purpose:** Connect phishing behavior to downstream incident impact for awareness program design.  
**Classification:** Internal Training

## Attack Chain Summary

```text
Healthcare-specific phishing email
    ↓
Employee click during workflow pressure window
    ↓
Credential submission / session capture risk
    ↓
Unauthorized access to workstation or portal context
    ↓
Beacon observed on endpoint
    ↓
Credential access attempt
    ↓
Lateral movement using privileged or service account context
    ↓
Incident response activation
```

## Human-Layer Decision Points

| Point | Employee Could Disrupt By | Why It Was Difficult |
|---|---|---|
| Email received | Inspecting sender/domain and reporting | Message matched clinical workflow language |
| Link presented | Using known portal bookmark instead | Email created urgency around patient record access |
| Credential prompt | Stopping and verifying through IT | Page looked familiar and prefilled identity |
| Suspicious after click | Reporting immediately | Employee feared blame |
| Coworker receives same lure | Sharing report path, not forwarding link | No shared team protocol existed |

## Technical-Layer Decision Points

| Point | Control | Limitation |
|---|---|---|
| Email gateway | Sender/domain analysis | Some messages passed basic authentication |
| SIEM | Beacon detection | Triggered after initial human failure |
| EDR | Endpoint behavior | Cannot prevent credential entry alone |
| IAM | Privileged access controls | Service account hygiene was weak |
| IR playbook | Containment | Reactive, not preventive |

## Training Message

The goal of awareness training is not to make employees "security experts." The goal is to make the safe action easier than the unsafe action:

- report suspicious email
- verify through known channel
- slow down requests involving credentials, money, PHI or remote access
- report even after clicking

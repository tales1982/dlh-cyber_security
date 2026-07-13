# Shadow Systems Assessment MedDefense Health Systems

## System 1: Dr. Patel's Personal NAS (Cardiology)

### Risk Assessment

1. **Sensitive data:** Clinical/cardiology research data, which may include re-identifiable patient information depending on the study design.
2. **Controls not covering it:** None of the 16 controls in the Task 10 matrix apply it was never inventoried, so it has no backup, no antivirus, no access logging, and sits outside the firewall's asset-aware rules.
3. **Worst case:** A consumer-grade NAS fails or is compromised, and research data potentially containing patient identifiers is lost or exposed with no audit trail and no way to know what was on it.

### Recommended Response: **Legitimize and Secure**

Dr. Patel bought this because the shared drive was "too slow" that's a real, unmet need, not a frivolous one. Decommissioning without an alternative just pushes the same behavior somewhere less visible. Bring the device under IT governance: inventory it, apply backup and access controls, and evaluate whether the underlying performance complaint needs fixing on the official file infrastructure.

## System 2: Marketing's Shared Google Drive (Personal Gmail)

### Risk Assessment

1. **Sensitive data:** Media files and press communications generally lower classification (Public/Internal), but pre-release communications could be commercially sensitive before publication.
2. **Controls not covering it:** All of them this data lives entirely outside MedDefense's network, so no firewall rule, backup job, or endpoint control has any reach into it.
3. **Worst case:** The employee who owns the personal Gmail account leaves the organization, and MedDefense loses access to (or control over) its own marketing assets and communications history, with no transition process.

### Recommended Response: **Migrate**

MedDefense already pays for O365 E3 (Task 0), which includes SharePoint/OneDrive a functionally equivalent, already-licensed, already-controlled alternative. This is the clearest "why are we paying for shadow IT when we already own the sanctioned version" case of the three.

## System 3: Raspberry Pi ("Network Monitor," 2nd Floor Central)

### Risk Assessment

1. **Sensitive data:** Unclear by design it was set up as a network monitoring tool, which typically implies broad visibility into network traffic, not storage of a specific dataset.
2. **Controls not covering it:** All of them nobody has touched it since Marcus and the intern left, so it has received no patches, no review, and isn't in anyone's inventory.

   *Cross-reference:* this description matches `UNKNOWN-01` (A-012) from the Task 7 network scan almost exactly a Linux host with SSH and two web services, on the Central server subnet, that Sarah could not identify but suspected was "Marcus's or the intern's." This is very likely the same device, not a fourth undiscovered one.
3. **Worst case:** A forgotten device with broad network visibility, unpatched for months, becomes a foothold for lateral movement exactly the kind of overlooked pivot point that turned a single compromised host into a network-wide problem in Task 2.

### Recommended Response: **Decommission** (pending confirmation)

Unlike the other two, nobody currently depends on this device for anything its original purpose (an intern project) ended when its owner left. Before removing it, confirm it isn't quietly performing a function someone now relies on (per the Task 7 reconciliation notes), but the default path should be removal, not legitimization, since there is no current business owner to secure it under.

## Asset Registry Update (Task 7)

| Asset ID          | Name                                        | Type        | Location                                        | Owner (Dept)                 | OS/Platform            | Critical Services                    | Network Segment                 | Status    | Notes                                                                                                                                     |
| ----------------- | ------------------------------------------- | ----------- | ----------------------------------------------- | ---------------------------- | ---------------------- | ------------------------------------ | ------------------------------- | --------- | ----------------------------------------------------------------------------------------------------------------------------------------- |
| A-026             | Dr. Patel's Personal NAS                    | Data Store  | Central, Cardiology office                      | Cardiology (unofficial)      | Unknown (consumer NAS) | Research data storage                | 10.10.1.0/24 (office wall port) | Shadow IT | Purchased to work around slow shared drive; recommend Legitimize and Secure                                                               |
| A-027             | Marketing Shared Drive                      | Application | Cloud (personal Gmail-linked)                   | Marketing (unofficial)       | Google Drive (SaaS)    | Media/press file storage             | N/A (external cloud)            | Shadow IT | Tied to a personal account; recommend Migrate to O365/SharePoint                                                                          |
| A-012*(update)* | UNKNOWN-01 / "Network Monitor" Raspberry Pi | Server      | Central, 2nd floor / server subnet (10.10.2.99) | None (former intern project) | Linux 4.x              | Unclear — likely network monitoring | 10.10.2.0/24                    | Shadow IT | Likely the Raspberry Pi Mike Torres described; unmaintained since Marcus and the intern left; recommend Decommission pending confirmation |

## Shadow IT Policy Recommendation

The single most effective policy change would be establishing a **fast, low-friction IT intake process** for new tools and devices all three cases here exist because someone had a real, unmet need (a slow shared drive, a need to share media externally, a desire to monitor the network) and no easy sanctioned path to get it addressed quickly. A lightweight request process with a committed response time (e.g., 48 hours) would remove the incentive to solve problems quietly outside IT's visibility, which is a more durable fix than any amount of after-the-fact detection.

# Compensating Control Strategy — MRI Workstation (Radiology, Central)

## 1. Risk Analysis

This MRI workstation is a risk to the entire network, not just Radiology, because Windows XP has received no security patches since 2014 over a decade of publicly known, weaponized exploits (including the SMB-based vulnerabilities that powered WannaCry, which specifically targeted unpatched Windows systems) apply to it. Because the workstation sits on the same VLAN as every other hospital workstation, there is no network boundary isolating it: an attacker who compromises any ordinary workstation can pivot directly to the MRI, and an attacker who compromises the MRI itself an easy target given its OS can pivot laterally into systems that hold PHI. The vulnerability characteristic (an old, unpatched, widely-exploited OS) combines with the architecture characteristic (a flat, unsegmented network) to turn one legacy device into an entry point, or a pivot point, for the entire hospital network rather than an isolated Radiology-department problem.

## 2. Compensating Control Strategy

### Control 1

- **Description:** Move the MRI workstation off the shared hospital VLAN onto its own isolated network segment, with a firewall rule permitting only the specific traffic needed to reach the PACS server nothing else in or out.
- **Category:** Technical
- **Function:** Compensating
- **How it reduces risk (without OS modification):** It never touches the Windows XP install itself; it changes only where the workstation sits on the network. This removes the exposure identified in the Risk Analysis instead of being reachable from (and able to reach) every other workstation in the hospital, the MRI can only talk to the one system it actually needs.
- **Limitations / Residual Risk:** It does not fix the underlying unpatched vulnerabilities. If an attacker compromises the PACS server itself (the one system still allowed to communicate with the MRI), or gains local/physical access to the workstation, this control provides no protection. It also depends on the firewall rule being configured and maintained correctly.

### Control 2

- **Description:** Establish a formal, documented risk acceptance and monitoring process for the MRI: a written exception signed off by both IT leadership and clinical/compliance leadership, a quarterly review requirement, a named owner responsible for tracking it, and a defined replacement timeline tied to the device's remaining 6-year lifecycle.
- **Category:** Administrative
- **Function:** Compensating
- **How it reduces risk (without OS modification):** It does not touch the device at all it ensures the already-known risk is actively tracked and escalated to decision-makers with budget authority, instead of sitting unaddressed the way it has for the past 6 months on Marcus's desk.
- **Limitations / Residual Risk:** This is pure process, not a technical protection it does not reduce the device's actual exposure. If reviews are skipped or treated as a formality, the control provides no real protection, and it depends entirely on organizational follow-through, which MedDefense has already shown to be inconsistent elsewhere (e.g., unaddressed security requests sitting for months).

### Control 3

- **Description:** Restrict physical access to the MRI control workstation to authorized radiology staff only, and physically disable or lock its USB ports to prevent removable media from being connected.
- **Category:** Physical
- **Function:** Preventive
- **How it reduces risk (without OS modification):** Even with network isolation in place, anyone who can physically reach the workstation could plug in a USB device and bypass every network-level control entirely. Restricting physical access and locking USB ports closes that path without touching the OS.
- **Limitations / Residual Risk:** Does not protect against an authorized staff member's credentials being compromised, or against misuse through the one network channel still permitted (PACS). Physical restriction is only as strong as the badge/door system enforcing it, which Task 3's walk-through already found to be weak in other parts of the facility.

## 3. Implementation Priority

If only one control could be implemented immediately, **Control 1 (network segmentation)** provides the greatest risk reduction. It directly addresses the root architectural exposure identified in the Risk Analysis the flat, unsegmented VLAN rather than managing the problem administratively or closing a secondary bypass path. It is also a one-time technical change that, once correctly configured, does not depend on ongoing human compliance the way Control 2 does, and it protects against the most likely and scalable attack path (network-based compromise and lateral movement) rather than the physical access path, which requires an attacker to already be inside the building.

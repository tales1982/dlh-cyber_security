# Physical Security Assessment — MedDefense Central

<!-- For each observation, decompose the risk into its four formal components:
     Vulnerability, Threat, Impact (name the CIA pillar(s)), and Severity
     (justified in one sentence, weighing ease of exploitation against impact). -->

## Observation 1 Server Room Access

- **Vulnerability:** Server room shares a public corridor with the cafeteria; the door accepts the same generic badge every employee gets, with no camera and no visitor log.
- **Threat:** Someone with no legitimate reason to be there (borrowed badge, opportunistic staff) enters unnoticed, since nothing records who comes in.
- **Impact:** Tampering with or accessing hardware breaks **Confidentiality** and **Integrity**; damaging equipment breaks **Availability** the room hosts the EHR and billing servers.
- **Severity:** High no technical skill needed to exploit, and the room hosts systems critical to patient care and billing.

## Observation 2 Network Closet

- **Vulnerability:** The network closet has no lock, the door sits ajar, and a sheet taped to the wall lists the switch management username and password in plain view.
- **Threat:** Someone unauthorized  a visitor, a contractor, or an employee with no reason to be there  enters the unlocked closet, reads the credentials on the wall, and uses them to log into the switch's management interface.
- **Impact:** With that access, an attacker can power off the switch (**Availability**), reconfigure ports or VLANs (**Integrity**), or mirror ports to intercept traffic in transit (**Confidentiality**).
- **Severity:** Critical  exploitation requires no technical skill (the password is written on the wall and the door doesn't even lock), and the compromised switch can take down or intercept traffic for an entire floor.

## Observation 3 Nurse Station

- **Vulnerability:** The EHR workstation has no session timeout, and a posted sign tells staff not to log out between shifts, leaving patient records open on screen for anyone nearby.
- **Threat:** Someone passing the unattended station  a visitor, another patient, or a staff member with no need to see that record  reads or edits the open patient chart while no one is watching.
- **Impact:** Viewing the exposed record breaks **Confidentiality**; editing it breaks **Integrity**  both directly expose protected patient health data.
- **Severity:** High  no skill needed, just proximity to a public station, and the data on screen is regulated patient health information.

## Observation 4 Medical IoT

- **Vulnerability:** The vital signs monitor runs firmware from 2019 and sits on the same network segment as ordinary staff workstations, with no isolation for medical devices.
- **Threat:** An attacker who compromises any workstation on that same segment pivots across the network to reach the monitor and exploit known flaws in its outdated firmware.
- **Impact:** Tampering with the device or its readings breaks **Integrity** and **Availability**  a direct threat to patient safety, since clinical staff rely on accurate, continuous vitals.
- **Severity:** Critical  outdated firmware plus no network segmentation means a compromise anywhere on that segment can reach a life-safety device.

## Observation 5 Emergency Exit

- **Vulnerability:** A fire exit linking the public waiting area to the restricted administrative wing is propped open with a wooden wedge, bypassing whatever access control normally guards it.
- **Threat:** Anyone from the waiting area no badge, no check-in, no escort walks straight into the administrative wing, including the corridor to IT and executive offices.
- **Impact:** Unrestricted physical entry to IT and leadership areas breaks **Confidentiality**, and could enable further tampering (a planted device, stolen documents) breaking **Integrity**.
- **Severity:** Hightakes zero skill or effort to exploit (the door is already open), and it grants direct access to IT and leadership without any credential at all.

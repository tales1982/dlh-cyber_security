# Tabletop Exercise: Nexus Supply Chain Compromise

**Exercise ID:** TTX-2026-01
**Date:** 2026-04-28 (09:00-11:45, Main campus, Board Room B; 160 minutes including hotwash)
**Classification:** Internal - Exercise Use Only
**Facilitator:** Tales Lima (SOC Analyst, exercise designer)
**Scenario version:** 1.1 (updated after designer simulation, see execution_record.md)
**Exercise sponsor:** Dr. Patricia Morales, CISO
**Participants:** James Chen (SOC Lead / IR Commander), Sarah Park (IT Director), Dr. Patricia Morales (CISO), Helena Reyes (General Counsel), Marcus Webb (Communications Director), Robert Kim (Infrastructure Lead), Clinical Director representative

> This is an exercise. Everything in this document is fictional and is used only to test MedDefense decision-making. Do not act on it outside the room. Say "EXERCISE EXERCISE EXERCISE" before any real-world call made during the session.

---

## Exercise rules

- The exercise runs in simulated real time: 1 minute in the room = 1 minute in the scenario unless the facilitator announces a time jump.
- You only know what has been told to you. Do not assume facts that have not been delivered by an inject.
- Decisions must be stated out loud, with who owns them. "We would look into it" is not a decision.
- There is no single right answer. The goal is to find where MedDefense would break, not to look good.

---

## Organization background

MedDefense is a regional healthcare provider operating three sites (West Campus, Main campus and North Site) that together handle about 3,500 patient scheduling interactions every week, from outpatient visits to oncology infusion and dialysis sessions. Outpatient scheduling, pre-registration and insurance eligibility checks for all three sites run through a single third-party SaaS platform, Nexus Patient Scheduling, which writes confirmed appointments directly into Epic. As a HIPAA Covered Entity, MedDefense is accountable for the protected health information (ePHI) that its Business Associates create, receive or transmit on its behalf, and it closed a confirmed ePHI incident (IR-2026-0414-01) two weeks ago.

---

## Vendor background

**Who they are.** Nexus Patient Scheduling is a multi-tenant, cloud-hosted appointment and pre-registration platform built by Nexus Health Technologies, Inc. (Austin, TX). MedDefense has used it since 2023-08-14. Each customer runs in a dedicated AWS pod (MedDefense: `us-east-1`).

**What data they access.**

- Patient demographics (name, date of birth, address, phone, email) and insurance details used for eligibility checks (ePHI)
- Appointment data: date, time, location, provider, visit type and wait-list position for every outpatient booking
- Staff rostering: provider schedules and clinic availability used to offer slots
- SMS and email reminders are sent through Nexus subprocessors Twilio and SendGrid

**How the Epic integration works.**

- HL7 FHIR R4 over HTTPS, OAuth2 client-credentials flow with a dedicated service principal `svc-nexus-prod`
- Outbound (MedDefense to Nexus): scheduling requests, patient demographics, insurance eligibility queries to `https://fhir.nexushealth.io/v1/`
- Inbound (Nexus to MedDefense): confirmed appointments, wait-list notifications and **automated schedule updates** written to `https://ehr-ingest.meddefense.local/nexus-inbound/` over a site-to-site IPsec tunnel. Nexus can create, move and cancel appointments in Epic through this channel.
- An on-premises `nexus-agent` runs on a dedicated scheduling server at each site: `SCHED-SVR-01` (Main campus, primary), `SCHED-SVR-02` (West Campus), `SCHED-SVR-03` (North Site). The agent is **updated automatically**: Nexus pushes signed updates that the agent installs after checking the "Nexus Health Technologies, Inc." code-signing certificate.

**Contract position (SLA and BAA).**

- SLA: 99.9 % monthly availability; Severity 1 vendor response within 1 hour through the 24x7 Nexus SecOps line (+1 512 555 0184, soc@nexushealth.io)
- Business Associate Agreement in force since 2023-08-01, last amended 2025-05-20 (aligned to the 2025 HIPAA Security Rule update)
- BAA obligations: Nexus must notify MedDefense of a breach **within 24 hours of discovery**, provide an annual SOC 2 Type II report, and return or destroy PHI on termination. Disclosed subprocessors: AWS, Twilio, SendGrid.
- Last MedDefense security review of Nexus: 2025-11-14 (Vendor Risk, Lisa Tanaka). Residual findings accepted at the time:
  1. The update channel relies only on code-signing certificate validation; MedDefense does not pin or verify update hashes independently.
  2. No software bill of materials for third-party npm dependencies in the on-prem agent.
  3. The joint incident communication path with Nexus is documented at contact level but has never been tested in a joint exercise (last contact test: 2024-09).

---

## Opening situation

**Monday 2026-04-28, 08:15. You are called into Board Room B.**

**What participants know at exercise start (T+0):**

1. **Network alert.** 45 minutes ago (07:30) the SOC flagged unusual outbound HTTPS traffic from `SCHED-SVR-02` (West Campus Nexus scheduling server, 10.42.30.12) to `193.42.100.77:443`, an external IP not seen before in MedDefense traffic. The IP is not a Nexus or AWS address.
2. **Host names.** The Nexus agent hosts are `SCHED-SVR-01` (Main), `SCHED-SVR-02` (West Campus) and `SCHED-SVR-03` (North Site). Only `SCHED-SVR-02` has alerted so far.
3. **EDR alert.** WazuhEDR shows `nexus-agent.exe` on `SCHED-SVR-02` making periodic outbound connections to `193.42.100.77` at **four-hour intervals** (03:30, 07:30). Each session lasts about 90 seconds.

**Nothing else is known.** Patient scheduling is running normally. Today's schedule has about 700 appointments across the three sites, including oncology infusion and dialysis sessions starting at 09:30. No vendor communication has been received.

---

## Facilitator-only: true state of the scenario (sealed, do not read aloud)

> Remove this section from the participant copy before distribution.

- **Three days ago (Friday 2026-04-25, 02:10)** a threat actor with access to Nexus's build infrastructure and its code-signing certificate shipped `nexus-agent` version 4.12.3. The update was **validly signed**, so it was installed automatically on all three MedDefense scheduling servers between 02:10 and 02:40.
- The update contains a backdoor that beacons every four hours and can read the agent's FHIR session. The backdoor has been running on `SCHED-SVR-01`, `-02` and `-03` since deployment. Only `-02` triggered the EDR rule because `-01` and `-03` use a proxy that masks the destination.
- During the compromise window the backdoor used the inbound FHIR channel to **modify appointment records in Epic** (moves and cancellations), creating a patient safety dimension.
- Nexus detected the build compromise internally on 2026-04-24 but has not yet notified customers. Their advisory arrives at INJ-01.

---

## Built-in organizational tensions (no clear right answer)

These are deliberate. The facilitator must not resolve them for the participants.

- **A-1. Is a signed update more or less trustworthy now?** The malicious code arrived through the channel MedDefense trusted *because* it was signed. When Nexus ships a "clean" signed fix, is the signature worth anything? Disabling automatic updates protects MedDefense but also blocks the vendor fix.
- **A-2. Isolate the vendor system or keep scheduling running?** Taking the Nexus agents offline stops a possible data flow but halts online scheduling, eligibility checks and reminders for about 700 appointments today, including time-critical infusion and dialysis patients. Keeping it running may keep the attacker inside an Epic-connected system.
- **A-3. Who owns the breach notification?** Nexus is a **Business Associate**: the breach happened in its build pipeline, and under the BAA it must notify MedDefense within 24 hours of discovery. But MedDefense is the **Covered Entity** and remains responsible for notifying affected patients, HHS and possibly the media (HIPAA Breach Notification Rule, 45 CFR 164.404-408). If Nexus discovered the compromise days before telling MedDefense, when did MedDefense's 60-day clock start?

## Patient safety dimension

Nexus can create, move and cancel appointments in Epic through the inbound FHIR channel. If the attacker could act through the agent, **appointment records may have been modified during the compromise window**: patients could arrive for slots that no longer exist, or miss treatment because a cancellation they never requested was confirmed by SMS. Clinical staff currently trust the Epic schedule as correct.

## HIPAA obligation tension

Nexus is MedDefense's Business Associate. A compromise of Nexus's systems that exposes MedDefense patient demographics and insurance data is a breach of unsecured PHI held by a BA. Nexus's BAA duty (notify MedDefense within 24 hours of discovery) does **not** transfer MedDefense's own obligations: MedDefense must still run the four-factor risk assessment and, if a breach is confirmed, notify individuals without unreasonable delay and no later than 60 days after discovery, HHS (at the same time if 500 or more individuals, otherwise in the annual log), and prominent media if more than 500 residents of a state are affected. The exercise tests whether MedDefense waits for the vendor or starts its own assessment.

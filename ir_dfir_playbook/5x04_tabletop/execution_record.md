# Exercise Execution Record: Nexus Supply Chain Compromise Tabletop

**Exercise ID:** TTX-2026-01
**Simulation date:** 2026-04-24 (designer dry run, four days before the live exercise)
**Simulated by:** Tales Lima (facilitator and all participant roles)
**Artifacts used:** exercise_scenario.md v1.0, capability_map.yaml, inject_schedule.yaml v1.0, evaluation_criteria.yaml
**Scoring rule:** PASS / FAIL per criterion inside the inject window (evaluation_criteria.yaml). Times are minutes from exercise start (T+).

> The simulation ran on version 1.0 of the scenario and inject schedule. The three design problems found are listed in the Design feedback section. Their fixes are already applied in version 1.1 of `exercise_scenario.md` and `inject_schedule.yaml`. Inject text below is quoted as it was delivered in v1.0; where v1.1 differs, it is marked.

---

## INJ-00 (T+0 min)

**Inject delivered:** "The SOC has flagged unusual outbound HTTPS traffic from the Nexus scheduling server at West Campus, SCHED-SVR-02 (10.42.30.12), to 193.42.100.77, a host associated with bulletproof hosting infrastructure in Eastern Europe. The alert fired 45 minutes ago. WazuhEDR shows the process is nexus-agent.exe and that it connects every four hours (03:30, 07:30), each session about 90 seconds. SCHED-SVR-01 (Main) and SCHED-SVR-03 (North Site) have not alerted. The Nexus system is operational and patient scheduling is running normally. No other anomalies have been detected."

**Participant responses:**

- James Chen (SOC Lead / IR Commander): "That's a C2 pattern. I'm declaring SEV2 now. I'll page Dr. Morales and Marcus, and I want a memory capture of SCHED-SVR-02 before anyone touches it."
- Sarah Park (IT Director): "Should we just pull SCHED-SVR-02 off the network? It's one of three, scheduling would survive on the other two."
- Dr. Patricia Morales (CISO): "Hold containment until James has the memory image. Keep me updated every 15 minutes."
- Helena Reyes (General Counsel): Silent; asks to be told if patient data is involved.
- Marcus Webb (Communications): "Nothing goes out yet. I'll prepare a staff note in case scheduling goes down."
- Robert Kim (Infrastructure Lead): "I'll pull the firewall flows for 193.42.100.77 and the network diagram for SCHED-SVR-02."
- Clinical Director representative: Not yet engaged; asks whether today's schedule is affected (answer: no).

**Evaluation:**

- Criterion 1 (incident declared within 5 min, severity reasoned): PASS - Chen declares SEV2 at T+2 ("C2 pattern on a server with patient data access")
- Criterion 2 (two roles notified by name): PASS - CISO and Communications Director notified at T+2
- Criterion 3 (evidence before containment): PASS - Morales holds Park's isolation proposal until memory capture (T+5)
- Criterion 4 (vendor considered as possible vector): FAIL - no participant asked whether nexus-agent itself or a Nexus update is the source; the traffic was treated as an intruder on the server
- Criterion 5 (scope extended to SCHED-SVR-01 and -03): FAIL - Kim pulls flows for SCHED-SVR-02 only; Park even assumes the other two servers are a safe fallback

**Inject result:** FAIL (criteria 4, 5) -> finding F-005

**Facilitator note:** Asked: "The process making the connection is nexus-agent.exe. Who wrote that code, and how does it get onto your servers?" Kim answered "Nexus pushes it automatically", but nobody connected this to the alert or to the accepted 2025-11-14 finding about the update channel. The vendor dimension stayed invisible until INJ-01 delivered it. The probe also showed that Park saw the other two agent hosts as the fallback, which would have kept the backdoor running.

---

## INJ-01 (T+20 min)

**Inject delivered (v1.0):** "Nexus Health Technologies publishes security advisory NX-SA-2026-004: 'A threat actor gained access to our build pipeline and code-signing certificate. nexus-agent updates distributed in the last 21 days may contain a malicious component. Version 4.12.3, pushed automatically on 2026-04-25 at 02:10 UTC, is confirmed malicious ... A fixed build is not yet available.' MedDefense's update log shows 4.12.3 installed on all three scheduling servers ... It is 08:35; the first dialysis and oncology infusion sessions start at 09:30 and about 700 appointments are booked today."
*(v1.1 adds: "the West Campus front desk reports that two patients arrived for appointments that Epic shows as cancelled", see DF-01.)*

**Participant responses:**

- James Chen (SOC Lead): "All three servers have the malicious build. I want all three agents and the FHIR inbound tunnel cut now."
- Sarah Park (IT Director): "I can't take scheduling down for three sites without someone above me signing. Patricia?"
- Dr. Patricia Morales (CISO): "This is now SEV1: a vendor with ePHI access is confirmed compromised. But I don't own clinical operations. I need the Clinical Director's view."
- Helena Reyes (General Counsel): "Is patient data on those servers? If yes, I need to start an assessment."
- Marcus Webb (Communications): "If scheduling goes down, all three sites need a message in the next 30 minutes."
- Robert Kim (Infrastructure Lead): "I can block the tunnel in five minutes, and isolate the three servers on the switch."
- Clinical Director representative: "We have dialysis at 09:30. If you take it down, my front desks are blind. Paper lists for today, fine, but I need them printed before you pull it."

**Evaluation:**

- Criterion 1 (isolation decision made or escalated with named authority): FAIL - discussion ran 18 minutes; Park and Morales each said the decision belonged to the other; isolation was finally "agreed in principle" at T+38 without a named authorizer
- Criterion 2 (manual fallback named by clinical role, plan for dialysis / infusion): PASS - Clinical Director requested printed day lists and phone confirmation for dialysis / infusion at T+27
- Criterion 3 (patient safety in rationale): PASS - Clinical Director and Morales both cited the 09:30 dialysis sessions
- Criterion 4 (Clinical Director consulted before decision): PASS - Morales asked explicitly at T+24
- Criterion 5 (automatic updates disabled or kept with reason): FAIL - no participant mentioned the update channel; automatic updates stayed on
- Criterion 6 (severity reviewed to SEV1): PASS - Morales raised to SEV1 at T+23

**Inject result:** FAIL (criteria 1, 5) -> findings F-001, F-007

**Facilitator note:** Asked: "If the vendor pushes another update in the next hour, will it install?" Silence, then Kim: "Yes, it's automatic." The team had decided to isolate the servers, but nobody had thought to stop the delivery channel that caused the compromise. The probe also showed that no document names who can take a vendor-operated clinical-support system offline: Park, Morales and the Clinical Director each believed someone else had that authority.

---

## INJ-02 (T+35 min)

**Inject delivered (v1.0):** "Nexus SecOps returns MedDefense's call. They confirm the us-east-1 pod and all three MedDefense agents received 4.12.3. They 'cannot yet say' whether data left their environment. They ask MedDefense to keep the agents online so their responders can collect telemetry, and ask that the advisory not be shared outside MedDefense because it is under NDA. The engineer mentions their team 'first saw signs of the build compromise on Thursday' (2026-04-24, four days ago). Meanwhile Priya Natarajan, the Nexus Account Executive, emails Marcus Webb directly offering a joint press statement."
*(v1.1 changes the discovery date so that it is revealed only if a participant asks for it, see DF-02.)*

**Participant responses:**

- James Chen (SOC Lead): "I'm on with SecOps. I'll ask for IOCs." (Asks verbally; no written request sent.)
- Sarah Park (IT Director): Calls Priya Natarajan in parallel "to understand the commercial side", without telling Chen.
- Dr. Patricia Morales (CISO): "We're not keeping the agents online for their telemetry. They can get it from their side. Our risk, our call."
- Helena Reyes (General Counsel): "Thursday? Write that down. The BAA says 24 hours from discovery. And nobody agrees to an NDA on a call."
- Marcus Webb (Communications): "I'll reply to Priya that we'll talk later. No joint statement today."
- Robert Kim (Infrastructure Lead): "Isolation of SCHED-SVR-01/02/03 is done, tunnel blocked at T+41."
- Clinical Director representative: Focused on paper lists; not engaged with the vendor.

**Evaluation:**

- Criterion 1 (one vendor liaison named): FAIL - Chen with SecOps and Park with the Account Executive in parallel, no coordination
- Criterion 2 (keep-online request decided on MedDefense risk): PASS - Morales refuses explicitly at T+38
- Criterion 3 (written request for IOCs, versions, discovery date, data, subprocessors): FAIL - all requests were verbal; nothing in writing, subprocessors (Twilio, SendGrid) not asked about
- Criterion 4 (vendor discovery date recorded for BAA clock): PASS - Reyes records 2026-04-24 at T+40
- Criterion 5 (NDA referred to Legal): PASS - Reyes refuses NDA on the call at T+40

**Inject result:** FAIL (criteria 1, 3) -> finding F-003

**Facilitator note:** Asked: "What exactly did Nexus tell you, and where is it written?" Chen and Park gave different versions of the call (Chen: "no data loss confirmed"; Park: "they think only the agent is affected"). This confirms the untested communication path (residual risk R3): two channels, no record, no single liaison. The discovery date was captured only because the role-player said it without being asked; this made the criterion too easy (see DF-02).

---

## INJ-03 (T+50 min)

**Inject delivered:** "The Epic integration team pulls the audit trail for writes by svc-nexus-prod since 2026-04-25 02:10. 212 appointments were moved or cancelled through the inbound FHIR channel in a pattern that does not match normal Nexus behavior: 38 of them are oncology infusion and dialysis sessions over the next five days. Twilio sent SMS confirmations of the changes to the patients. One dialysis patient whose session was 'cancelled' did not come in on Saturday. Epic cannot tell which of the 212 changes were legitimate patient requests."

**Participant responses:**

- James Chen (SOC Lead): "Export that audit trail now and hash it, before anyone fixes anything."
- Sarah Park (IT Director): "The front desk already started putting the West Campus cancellations back in at 09:00 this morning."
- Dr. Patricia Morales (CISO): "This is a patient safety event. The Clinical Director owns patient outreach from now."
- Helena Reyes (General Counsel): "Changing records is also a HIPAA integrity issue, not only confidentiality."
- Marcus Webb (Communications): "Patients got SMS from us. They'll call. I need a script."
- Robert Kim (Infrastructure Lead): "I'm disabling svc-nexus-prod in Entra and the integration engine now."
- Clinical Director representative: "Nephrology on-call calls the Saturday dialysis patient now. My nurses call the 38 in order of treatment date, today's first."

**Evaluation:**

- Criterion 1 (inbound FHIR writes frozen): PASS - Kim disables svc-nexus-prod at T+53
- Criterion 2 (clinical owner named, 38 called first): PASS - Clinical Director at T+54
- Criterion 3 (missed dialysis escalated today): PASS - nephrology on-call tasked at T+54
- Criterion 4 (audit trail preserved before correction): FAIL - front desk had already corrected West Campus records at 09:00 before the export; Chen's export request came after
- Criterion 5 (integrity review extended to the 21-day window): FAIL - review limited to the 72 hours since 4.12.3; nobody connected the advisory's "last 21 days"

**Inject result:** FAIL (criteria 4, 5) -> finding F-002

**Facilitator note:** Asked: "The advisory says updates from the last 21 days may be malicious. What window are you checking in Epic?" Kim: "Since Friday." The team anchored on the confirmed version and ignored the uncertain window. Also showed that front-line staff fix records without knowing they are evidence: there is no instruction to front desks during an integration incident.

---

## INJ-04 (T+70 min)

**Inject delivered (v1.0):** "Forensic triage of SCHED-SVR-01 (Main, the primary agent host) shows the backdoor read the agent's FHIR session token. Proxy logs show 2.3 GB sent to 193.42.100.77 over the last 72 hours from the three servers. The agent can query demographics and insurance data for every patient scheduled in the last 18 months: about 41,000 patients across the three sites. Nexus emails: 'As the breached party we will handle all regulatory notifications. No action is required from MedDefense.' The BAA states Nexus must notify MedDefense within 24 hours of discovery."
*(v1.1 removes the patient count from the inject so the team must scope it, see DF-03.)*

**Participant responses:**

- James Chen (SOC Lead): "2.3 GB is a lot for a beacon. We can't say it's PHI yet."
- Sarah Park (IT Director): "If Nexus is handling notifications, that takes it off our plate."
- Dr. Patricia Morales (CISO): "Helena, is that true? Are we covered by their BAA?"
- Helena Reyes (General Counsel): "Their BAA obliges them to tell us. Let me check whether that's enough. They also missed the 24 hours." (Does not state MedDefense's own obligation in the window.)
- Marcus Webb (Communications): "41,000 is a headline number."
- Robert Kim (Infrastructure Lead): "I can give you the list of patients the agent touched in 72 hours from the Epic FHIR logs by end of day."
- Clinical Director representative: Still on patient calls; not engaged.

**Evaluation:**

- Criterion 1 (Counsel states MedDefense keeps CE obligations): FAIL - Reyes did not state it; Park's "off our plate" was not corrected in the window
- Criterion 2 (four-factor assessment started with owner and date): FAIL - not mentioned
- Criterion 3 (discovery date question raised and assigned): PASS - Reyes raises the missed 24-hour notice and the 2026-04-24 date at T+76
- Criterion 4 (60-day notice and 500-individual threshold named): FAIL - not mentioned
- Criterion 5 (vendor email answered in writing): PASS - Reyes drafts reply "MedDefense will coordinate any notification to its patients" at T+82
- Criterion 6 (PHI scoping assigned, confirmed/probable/unknown, deadline): PASS - Morales assigns Kim the 72-hour patient list by 18:00

**Inject result:** FAIL (criteria 1, 2, 4) -> finding F-004

**Facilitator note:** Asked: "If the vendor sends letters, whose name is on them, and who does HHS fine if they are late?" Reyes: "Ultimately us, as the Covered Entity." She knew the rule when probed but the team's default was to let the vendor own it. Because the inject handed over "41,000 patients", nobody had to work out the scope: CAP-04 was barely tested (DF-03).

---

## INJ-05 (T+90 min)

**Inject delivered:** "A reporter from the regional health news outlet emails Marcus Webb: 'We have a copy of Nexus advisory NX-SA-2026-004 listing MedDefense as an affected customer, and patients posting that their chemotherapy appointments were cancelled by text message. Can you confirm patient data was stolen? We publish at 11:00.' It is 09:45. The West Campus call center has received 60 calls in 30 minutes and agents are telling patients 'it is a Nexus system problem'."

**Participant responses:**

- James Chen (SOC Lead): "We cannot confirm theft. We can confirm the vendor incident."
- Sarah Park (IT Director): "Call center agents should stop naming Nexus."
- Dr. Patricia Morales (CISO): "Marcus, draft; Helena and I approve by 10:30."
- Helena Reyes (General Counsel): "No confirmation or denial of data theft. Say we are investigating with the vendor and patients should call to verify appointments."
- Marcus Webb (Communications): Drafts holding statement; sends to Reyes and Morales at T+101; approved at T+112 (10:07).
- Robert Kim (Infrastructure Lead): Not engaged.
- Clinical Director representative: "My nurses are calling oncology patients now; the paper is already out of date because of the calls."

**Evaluation:**

- Criterion 1 (holding statement approved by Legal and CISO before 11:00): PASS - approved 10:07
- Criterion 2 (vendor incident confirmed, no data theft claim, how to verify appointments): PASS - wording as Reyes proposed
- Criterion 3 (call center script with priority line): FAIL - Park's instruction ("stop naming Nexus") was the only guidance; no script, no priority line for time-critical patients
- Criterion 4 (no joint statement with Nexus before facts aligned): PASS - Webb declined the joint statement in INJ-02

**Inject result:** FAIL (criterion 3) -> finding F-006

**Facilitator note:** Asked: "A patient calls at 10:15 asking whether her chemo tomorrow is still on. What exactly does the agent say?" Nobody could answer. The public statement was handled well; the patient-facing line, where the patient safety risk is, had nothing.

---

## INJ-06 (T+105 min)

**Inject delivered:** "The Board Chair calls Dr. Morales: an emergency board call is scheduled in 90 minutes and she needs a written status brief 30 minutes before. At the same time Nexus releases signed version 4.12.4, 'clean and verified', and asks all customers to re-enable automatic updates so the fix can roll out. Nexus still cannot confirm whether updates before 4.12.3 in the 21-day window were clean, and cannot say whether the 2.3 GB contained PHI."

**Participant responses:**

- James Chen (SOC Lead): "We don't install anything signed with a key they just told us was stolen."
- Sarah Park (IT Director): "If we don't install the fix, we stay on manual scheduling for days. It's signed and they say it's verified. I'd put it on SCHED-SVR-01 and watch it."
- Dr. Patricia Morales (CISO): Drafts the brief with Chen: "Known / Not known / Decisions / Patient safety". Approves Park's plan to install 4.12.4 on SCHED-SVR-01 "under monitoring".
- Helena Reyes (General Counsel): Adds regulatory section: "up to 41,000 patients, assessment started, discovery date in question".
- Marcus Webb (Communications): Adds media status (statement published 10:07).
- Robert Kim (Infrastructure Lead): "If we install it, it goes back on the network. Isolated host won't get the update."
- Clinical Director representative: Adds: "38 time-critical patients: 31 reached, 7 pending, dialysis patient seen today."

**Evaluation:**

- Criterion 1 (one-page written brief, confirmed / probable / unknown): PASS - brief drafted by T+128 with Known / Not known sections
- Criterion 2 (decisions with owners and times): PASS - isolation (T+41, Kim), SEV1 (T+23, Morales), svc-nexus-prod disabled (T+53, Kim)
- Criterion 3 (patient safety and regulatory exposure in brief): PASS - both sections present
- Criterion 4 (specific decisions requested from the board): FAIL - brief informs the board but asks for nothing (vendor suspension, outside counsel, notification budget not requested)
- Criterion 5 (4.12.4 not installed until verified out of band): FAIL - Morales approves installing on SCHED-SVR-01 because it is signed and "verified" by the vendor, with no independent hash or certificate check
- Criterion 6 (open questions stated explicitly): PASS - brief lists pre-4.12.3 updates and PHI in the 2.3 GB as unknown; the notification clock start is listed as "under review"

**Inject result:** FAIL (criteria 4, 5) -> findings F-007, F-008

**Facilitator note:** Asked: "What has changed about the signature since Friday?" Chen: "Nothing; that's the problem." Park: "They have a new key." Nobody had confirmed whether there was a new key. The team repeated the exact trust assumption (residual risk R1) that caused the compromise, under the pressure of restoring scheduling. Open questions left unresolved at ENDEX, as designed: whether pre-4.12.3 updates were malicious, whether the 2.3 GB held PHI, and when the 60-day clock started.

---

## Summary of results

| Inject | Capability | Criteria passed | Result | Finding |
|---|---|---|---|---|
| INJ-00 | CAP-01 | 3 / 5 | FAIL | F-005 |
| INJ-01 | CAP-02 | 4 / 6 | FAIL | F-001, F-007 |
| INJ-02 | CAP-03 | 3 / 5 | FAIL | F-003 |
| INJ-03 | CAP-06 | 3 / 5 | FAIL | F-002 |
| INJ-04 | CAP-05 | 3 / 6 | FAIL | F-004 |
| INJ-05 | CAP-07 | 3 / 4 | FAIL | F-006 |
| INJ-06 | CAP-08 | 4 / 6 | FAIL | F-007, F-008 |

Every inject produced at least one finding. The design target was that each inject is hard enough to fail: this held, but DF-02 and DF-03 show two criteria were easier than intended because the inject text gave the answer.

---

## Design feedback

### DF-01: The patient safety signal arrived after the continuity decision

In v1.0 the first sign that appointments had been modified arrived at INJ-03 (T+50), but the decision to take Nexus offline was forced at INJ-01 (T+20). In the simulation the team argued about isolation purely as availability vs. confidentiality, and the Clinical Director argued *against* isolation to protect today's schedule, not knowing the schedule itself might be wrong. The data integrity concern should shape the continuity decision, not follow it.

**Change made:** INJ-01 (v1.1) now includes a secondary fact: "the West Campus front desk reports that two patients arrived for appointments that Epic shows as cancelled". The full scope (212 changes, 38 time-critical) stays in INJ-03. Added the fail indicator "the two patients arriving for cancelled appointments are not linked to the incident" to INJ-01 in evaluation_criteria.yaml.

### DF-02: The vendor discovery date was handed to the team

In v1.0 the Nexus engineer volunteered "we first saw signs on Thursday". INJ-02 criterion 4 (record the vendor discovery date for the BAA clock) was therefore passed without anyone having to ask, so the exercise did not test whether MedDefense knows to ask a vendor for its discovery date, which is the key fact for the HIPAA timeline.

**Change made:** INJ-02 (v1.1) role-play instruction: the Nexus SecOps role-player gives the discovery date **only if a participant asks when Nexus first detected the compromise**; otherwise says "we are still building the timeline". Criterion 4 stays the same, so it now measures the question, not the listening.

### DF-03: INJ-04 gave the PHI scope as a number

In v1.0 INJ-04 said "about 41,000 patients". CAP-04 (phi_exposure_assessment) is supposed to test whether the team can scope exposure. With the number handed over, participants discussed the headline but nobody worked out how the scope is built (which data elements, which time window, which subprocessors). Marcus Webb used the number as fact.

**Change made:** INJ-04 (v1.1) states only the raw facts: the agent can query demographics and insurance for patients scheduled in the last 18 months, three sites, 3,500 interactions per week. The facilitator reveals "about 41,000 unique patients" only if a participant asks the Epic team for a count. Added to the facilitator script: track whether Twilio / SendGrid data is raised (subprocessors were never mentioned in the simulation).

### DF-04: INJ-05 and INJ-06 overlap too much for a fair executive briefing test

INJ-06 arrived at T+105 while the holding statement from INJ-05 was still being approved (T+112). Dr. Morales was approving the media statement and drafting the board brief at the same time, so the CAP-08 failure (no board asks) is partly caused by the exercise timing, not only by the organization.

**Change made:** INJ-06 moved from T+105 to T+115 and hotwash from T+130 to T+140; exercise duration extended to 160 minutes. The 90-minute board deadline in the inject text stays, as the pressure is intended.

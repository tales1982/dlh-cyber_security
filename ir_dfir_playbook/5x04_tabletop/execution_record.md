# Exercise Execution Record: Nexus Supply Chain Compromise Tabletop

**Exercise ID:** TTX-2026-01
**Simulation date:** 2026-04-24 (designer dry run, four days before the live exercise on 2026-04-28)
**Simulated by:** Tales Lima (facilitator and all participant roles)
**Artifacts used:** exercise_scenario.md v1.0, capability_map.yaml, inject_schedule.yaml v1.0, evaluation_criteria.yaml
**Evaluators (capability_map.yaml):** EVAL-LEAD Tales Lima (CAP-01, CAP-07, CAP-08), EVAL-REG Lisa Tanaka (CAP-03, CAP-04, CAP-05), EVAL-CLIN Nursing Quality Officer (CAP-02, CAP-06). In the dry run all three scoring roles were performed by the designer.
**Clock:** times are minutes from exercise start (T+). T+0 = 08:15 scenario time on Monday 2026-04-28, so T+20 = 08:35, T+90 = 09:45, T+112 = 10:07.
**Scoring rule (evaluation_criteria.yaml):** a criterion is PASS only if it is observed inside the inject window (from delivery until the next inject is delivered). An inject FAILS if any pass criterion is not observed in the window **or** any fail indicator is observed. Each verdict below gives the time and the words or action observed. Fail indicators are checked one by one for every inject.

> The simulation ran on version 1.0 of the scenario and inject schedule. It found **four** design problems (DF-01 to DF-04, see Design feedback). Their fixes are already applied in version 1.1 of `exercise_scenario.md` and `inject_schedule.yaml`. Inject text below is quoted as it was delivered in v1.0; where v1.1 differs, it is marked.

**v1.0 timing:** INJ-00 T+0, INJ-01 T+20, INJ-02 T+35, INJ-03 T+50, INJ-04 T+70, INJ-05 T+90, INJ-06 T+105, hotwash T+130, ENDEX T+150.

---

## INJ-00 (T+0 min): window T+0 to T+20

**Capability:** CAP-01 supply_chain_detection | **Evaluation owner:** EVAL-LEAD

**Inject delivered:** "The SOC has flagged unusual outbound HTTPS traffic from the Nexus scheduling server at West Campus, SCHED-SVR-02 (10.42.30.12), to 193.42.100.77, a host associated with bulletproof hosting infrastructure in Eastern Europe. The alert fired 45 minutes ago. WazuhEDR shows the process is nexus-agent.exe and that it connects every four hours (03:30, 07:30), each session about 90 seconds. SCHED-SVR-01 (Main) and SCHED-SVR-03 (North Site) have not alerted. The Nexus system is operational and patient scheduling is running normally. No other anomalies have been detected."

**Participant responses:**

- T+2 James Chen (SOC Lead / IR Commander): "That's a C2 pattern on a server with patient data access. I'm declaring SEV2 now. I'm paging Dr. Morales and Marcus Webb, and I want a memory capture of SCHED-SVR-02 before anyone touches it."
- T+4 Sarah Park (IT Director): "Should we just pull SCHED-SVR-02 off the network? It's one of three, scheduling would survive on the other two."
- T+5 Dr. Patricia Morales (CISO): "Hold containment until James has the memory image. Keep me updated every 15 minutes."
- T+6 James Chen: "Memory capture on SCHED-SVR-02 is running."
- T+7 Helena Reyes (General Counsel): Silent until now; "Tell me if patient data is involved."
- T+8 Marcus Webb (Communications): "Nothing goes out yet. I'll prepare a staff note in case scheduling goes down."
- T+9 Robert Kim (Infrastructure Lead): "I'll pull the firewall flows for 193.42.100.77 and the network diagram for SCHED-SVR-02."
- T+12 Clinical Director representative: Not yet engaged; asks whether today's schedule is affected (facilitator answer: no).

**Pass criteria:**

| # | Criterion | Result | Time and evidence |
|---|---|---|---|
| 1 | Incident declared within 5 min, severity reasoned | PASS | T+2, Chen: "C2 pattern on a server with patient data access. I'm declaring SEV2 now." |
| 2 | Two roles notified by name | PASS | T+2, Chen pages Dr. Morales (CISO) and Marcus Webb (Communications) |
| 3 | Evidence collection before containment is discussed | PASS | T+2 Chen names memory capture before Park's isolation proposal (T+4); T+5 Morales holds containment. Note: agent version and update history were **not** requested (feeds F-005) |
| 4 | Vendor considered as possible vector | FAIL | Not observed T+0 to T+20. No participant asked whether nexus-agent or a Nexus update is the source; the traffic was treated as an intruder on the server |
| 5 | Scope extended to SCHED-SVR-01 and -03 | FAIL | Not observed. T+9 Kim pulls flows for SCHED-SVR-02 only; T+4 Park treats the other two servers as a safe fallback |

**Fail indicators:**

| Fail indicator | Observed? | Evidence |
|---|---|---|
| Incident not declared | No | Declared T+2 |
| Containment proposed before evidence step named | No | Memory capture named T+2, isolation proposed T+4 |
| Vendor Nexus not mentioned as a dimension of the alert | **Yes** | No vendor discussion until the facilitator probe at T+14 |
| Only SCHED-SVR-02 investigated | **Yes** | T+9 Kim, SCHED-SVR-02 only |

**Inject result:** FAIL (criteria 4, 5; two fail indicators) -> finding F-005

**Facilitator note:** At T+14 asked: "The process making the connection is nexus-agent.exe. Who wrote that code, and how does it get onto your servers?" T+15 Kim: "Nexus pushes it automatically." Nobody connected this to the alert or to the accepted 2025-11-14 finding about the update channel (R1). The vendor dimension stayed invisible until INJ-01 delivered it. The probe also showed that Park saw the other two agent hosts as the fallback, which would have kept the backdoor running.

---

## INJ-01 (T+20 min): window T+20 to T+35

**Capability:** CAP-02 business_continuity_decision (secondary CAP-01) | **Evaluation owner:** EVAL-CLIN

**Inject delivered (v1.0):** "Nexus Health Technologies publishes security advisory NX-SA-2026-004: 'A threat actor gained access to our build pipeline and code-signing certificate. nexus-agent updates distributed in the last 21 days may contain a malicious component. Version 4.12.3, pushed automatically on 2026-04-25 at 02:10 UTC, is confirmed malicious. We advise all customers to take immediate action. A fixed build is not yet available.' MedDefense's update log shows 4.12.3 installed on all three scheduling servers between 02:10 and 02:40 on 2026-04-25. It is 08:35; the first dialysis and oncology infusion sessions start at 09:30 and about 700 appointments are booked today."
*(v1.1 adds: "the West Campus front desk reports that two patients arrived for appointments that Epic shows as cancelled", see DF-01.)*

**Participant responses:**

- T+21 James Chen (SOC Lead): "All three servers have the malicious build. I want all three agents and the FHIR inbound tunnel cut now."
- T+22 Sarah Park (IT Director): "I can't take scheduling down for three sites without someone above me signing. Patricia?"
- T+23 Dr. Patricia Morales (CISO): "This is now SEV1: a vendor with ePHI access is confirmed compromised. But I don't own clinical operations."
- T+24 Dr. Patricia Morales: "I need the Clinical Director's view before we decide."
- T+25 Helena Reyes (General Counsel): "Is patient data on those servers? If yes, I need to start an assessment."
- T+26 Marcus Webb (Communications): "If scheduling goes down, all three sites need a message in the next 30 minutes."
- T+26 Robert Kim (Infrastructure Lead): "I can block the tunnel in five minutes, and isolate the three servers on the switch."
- T+27 Clinical Director representative: "We have dialysis at 09:30. If you take it down, my front desks are blind. Paper lists for today, fine, but I need them printed before you pull it, and my nurses phone every dialysis and infusion patient to confirm their slot."
- T+28 to T+35: Park and Morales each state that the go / no-go belongs to the other; no decision is taken before INJ-02 is delivered.
- T+38 (inside the INJ-02 window): isolation "agreed in principle" by the group; nobody is recorded as the authorizer.

**Pass criteria:**

| # | Criterion | Result | Time and evidence |
|---|---|---|---|
| 1 | Isolation decision made or escalated with named authority | FAIL | No decision in the window (T+20 to T+35). Agreed "in principle" only at T+38, after the window closed, with no named authorizer |
| 2 | Manual fallback named by a clinical role, plan for dialysis / infusion | PASS | T+27, Clinical Director: printed day lists, nurses phone every dialysis and infusion patient |
| 3 | Patient safety in the decision rationale | PASS | T+27 Clinical Director and T+24 Morales cite the 09:30 dialysis sessions |
| 4 | Clinical Director consulted before decision | PASS | T+24, Morales asks for the Clinical Director's view |
| 5 | Automatic updates disabled or kept with reason | FAIL | Not observed. Nobody mentioned the update channel; automatic updates stayed on |
| 6 | Severity reviewed to SEV1 | PASS | T+23, Morales: "This is now SEV1" |

**Fail indicators:**

| Fail indicator | Observed? | Evidence |
|---|---|---|
| Decision deferred pending unavailable information | **Yes** | T+28 to T+35 no decision; deferred until T+38 |
| Clinical Director not consulted | No | Consulted T+24 |
| Nobody can name who can take a vendor system offline | **Yes** | T+22 Park and T+23 Morales each point to the other |
| Two patients at cancelled appointments not linked | N/A | Fact added in v1.1 only (DF-01) |

**Inject result:** FAIL (criteria 1, 5; two fail indicators) -> findings F-001, F-007

**Facilitator note:** At T+30 asked: "If the vendor pushes another update in the next hour, will it install?" Silence, then T+31 Kim: "Yes, it's automatic." The team had decided to isolate the servers but nobody thought to stop the delivery channel that caused the compromise. The probe also showed that no document names who can take a vendor-operated clinical-support system offline: Park, Morales and the Clinical Director each believed someone else had that authority.

---

## INJ-02 (T+35 min): window T+35 to T+50

**Capability:** CAP-03 vendor_communication (secondary CAP-04) | **Evaluation owner:** EVAL-REG

**Inject delivered (v1.0):** "Nexus SecOps returns MedDefense's call. They confirm the us-east-1 pod and all three MedDefense agents received 4.12.3. They 'cannot yet say' whether data left their environment. They ask MedDefense to keep the agents online so their responders can collect telemetry, and ask that the advisory not be shared outside MedDefense because it is under NDA. The engineer mentions their team 'first saw signs of the build compromise on Thursday' (2026-04-24, four days ago). Meanwhile Priya Natarajan, the Nexus Account Executive, emails Marcus Webb directly offering a joint press statement."
*(v1.1 reveals the discovery date only if a participant asks for it, see DF-02.)*

**Participant responses:**

- T+36 James Chen (SOC Lead): "I'm on with SecOps. I'll ask for IOCs." (Asks verbally; no written request sent.)
- T+37 Sarah Park (IT Director): Calls Priya Natarajan in parallel "to understand the commercial side", without telling Chen.
- T+38 Dr. Patricia Morales (CISO): "We're not keeping the agents online for their telemetry. They can get it from their side. Our risk, our call."
- T+39 Marcus Webb (Communications): "I'll reply to Priya that we'll talk later. No joint statement today."
- T+40 Helena Reyes (General Counsel): "Thursday? Write that down. The BAA says 24 hours from discovery. And nobody agrees to an NDA on a call."
- T+41 Robert Kim (Infrastructure Lead): "Isolation of SCHED-SVR-01/02/03 is done, tunnel blocked."
- Clinical Director representative: Focused on paper lists; not engaged with the vendor.

**Pass criteria:**

| # | Criterion | Result | Time and evidence |
|---|---|---|---|
| 1 | One vendor liaison named | FAIL | T+36 Chen with SecOps and T+37 Park with the Account Executive, in parallel, uncoordinated |
| 2 | Keep-online request decided on MedDefense risk | PASS | T+38, Morales: "Our risk, our call" |
| 3 | Written request for IOCs, versions, discovery date, data, subprocessors | FAIL | All requests verbal; nothing in writing; Twilio / SendGrid not asked about |
| 4 | Vendor discovery date recorded for the BAA clock | PASS | T+40, Reyes records 2026-04-24 against the 24-hour BAA notice (passed only because the date was volunteered, see DF-02) |
| 5 | NDA referred to Legal | PASS | T+40, Reyes refuses the NDA on the call |

**Fail indicators:**

| Fail indicator | Observed? | Evidence |
|---|---|---|
| More than one person contacts Nexus with no coordination | **Yes** | T+36 Chen, T+37 Park |
| Agents kept online only because the vendor asked | No | T+38 refused; isolated T+41 |
| Vendor discovery date not asked for or not recorded | No | Recorded T+40 (not asked for: volunteered) |
| Joint press statement accepted without Legal review | No | T+39 Webb declines |

**Inject result:** FAIL (criteria 1, 3; one fail indicator) -> finding F-003

**Facilitator note:** At T+45 asked: "What exactly did Nexus tell you, and where is it written?" Chen and Park gave different versions of the call (Chen: "no data loss confirmed"; Park: "they think only the agent is affected"). This confirms the untested communication path (residual risk R3): two channels, no record, no single liaison. The discovery date was captured only because the role-player said it without being asked, which made criterion 4 too easy (DF-02).

---

## INJ-03 (T+50 min): window T+50 to T+70

**Capability:** CAP-06 data_integrity_response (secondary CAP-02, CAP-04) | **Evaluation owner:** EVAL-CLIN

**Inject delivered:** "The Epic integration team pulls the audit trail for writes by svc-nexus-prod since 2026-04-25 02:10. 212 appointments were moved or cancelled through the inbound FHIR channel in a pattern that does not match normal Nexus behavior: 38 of them are oncology infusion and dialysis sessions over the next five days. Twilio sent SMS confirmations of the changes to the patients. One dialysis patient whose session was 'cancelled' did not come in on Saturday. Epic cannot tell which of the 212 changes were legitimate patient requests."

**Participant responses:**

- T+51 James Chen (SOC Lead): "Export that audit trail now and hash it, before anyone fixes anything."
- T+51 Sarah Park (IT Director): "The front desk already started putting the West Campus cancellations back in at 09:00 this morning." (09:00 = T+45, before this inject.)
- T+52 Dr. Patricia Morales (CISO): "This is a patient safety event. The Clinical Director owns patient outreach from now."
- T+52 Helena Reyes (General Counsel): "Changing records is also a HIPAA integrity issue, not only confidentiality."
- T+53 Robert Kim (Infrastructure Lead): "I'm disabling svc-nexus-prod in Entra and the integration engine now." Confirmed done at T+53.
- T+54 Clinical Director representative: "Nephrology on-call calls the Saturday dialysis patient now. My nurses call the 38 in order of treatment date, today's first."
- T+55 Marcus Webb (Communications): "Patients got SMS from us. They'll call. I need a script." (No script produced; see INJ-05.)

**Pass criteria:**

| # | Criterion | Result | Time and evidence |
|---|---|---|---|
| 1 | Inbound FHIR writes frozen | PASS | T+53, Kim disables svc-nexus-prod |
| 2 | Clinical owner named, 38 called first | PASS | T+52 Morales names the Clinical Director; T+54 the 38 called by treatment date |
| 3 | Missed dialysis escalated today | PASS | T+54, nephrology on-call tasked |
| 4 | Audit trail preserved before correction | FAIL | West Campus records corrected at 09:00 (T+45); export requested only at T+51 |
| 5 | Integrity review extended to the 21-day window | FAIL | Review limited to the ~72 hours since 4.12.3; the advisory's "last 21 days" not applied |

**Fail indicators:**

| Fail indicator | Observed? | Evidence |
|---|---|---|
| Only confidentiality discussed, no action on modified records | No | T+52 Reyes, T+53 Kim, T+54 Clinical Director act on integrity |
| Records corrected before audit trail preserved | **Yes** | 09:00 corrections vs T+51 export request |
| No clinical role assigned to outreach | No | T+52 |
| Missed dialysis not raised as immediate safety issue | No | T+54 |

**Inject result:** FAIL (criteria 4, 5; one fail indicator) -> finding F-002

**Facilitator note:** At T+60 asked: "The advisory says updates from the last 21 days may be malicious. What window are you checking in Epic?" Kim: "Since Friday." The team anchored on the confirmed version and ignored the uncertain window. The inject also showed that front-line staff fix records without knowing they are evidence: there is no instruction to front desks during an integration incident.

---

## INJ-04 (T+70 min): window T+70 to T+90

**Capability:** CAP-05 hipaa_notification_posture (secondary CAP-04) | **Evaluation owner:** EVAL-REG

**Inject delivered (v1.0):** "Forensic triage of SCHED-SVR-01 (Main, the primary agent host) shows the backdoor read the agent's FHIR session token. Proxy logs show 2.3 GB sent to 193.42.100.77 over the last 72 hours from the three servers. The agent can query demographics and insurance data for every patient scheduled in the last 18 months: about 41,000 patients across the three sites. Nexus emails: 'As the breached party we will handle all regulatory notifications. No action is required from MedDefense.' The BAA states Nexus must notify MedDefense within 24 hours of discovery."
*(v1.1 removes the patient count from the inject so the team must scope it, see DF-03.)*

**Participant responses:**

- T+72 James Chen (SOC Lead): "2.3 GB is a lot for a beacon. We can't say it's PHI yet."
- T+73 Sarah Park (IT Director): "If Nexus is handling notifications, that takes it off our plate."
- T+74 Dr. Patricia Morales (CISO): "Helena, is that true? Are we covered by their BAA?"
- T+76 Helena Reyes (General Counsel): "Their BAA obliges them to tell us. Let me check whether that's enough. They also missed the 24 hours: they knew on the 24th." (Does not state MedDefense's own obligation.)
- T+77 Marcus Webb (Communications): "41,000 is a headline number."
- T+78 Robert Kim (Infrastructure Lead): "I can give you the list of patients the agent touched in the last 72 hours from the Epic FHIR logs."
- T+79 Dr. Patricia Morales: "Robert, that list by 18:00 today."
- T+82 Helena Reyes: Drafts written reply to Nexus: "MedDefense will coordinate any notification to its patients."
- Clinical Director representative: Still on patient calls; not engaged.

**Pass criteria:**

| # | Criterion | Result | Time and evidence |
|---|---|---|---|
| 1 | Counsel states MedDefense keeps Covered Entity obligations | FAIL | Not stated in the window; T+73 Park's "off our plate" not corrected |
| 2 | Four-factor assessment started with owner and date | FAIL | Not mentioned |
| 3 | Discovery date question raised and assigned | PASS | T+76, Reyes raises the missed 24-hour notice and the 2026-04-24 date |
| 4 | 60-day notice and 500-individual threshold named | FAIL | Not mentioned |
| 5 | Vendor email answered in writing | PASS | T+82, Reyes's written reply |
| 6 | PHI scoping assigned with confirmed / probable / unknown and a deadline | FAIL | T+79 an owner (Kim) and a deadline (18:00) were set, but no confirmed / probable / unknown split, and the scope was limited to 72 hours although the agent could read 18 months of patients |

**Fail indicators:**

| Fail indicator | Observed? | Evidence |
|---|---|---|
| Team accepts Nexus "handles all notifications" and takes no regulatory action | Partly | T+73 accepted by Park and not corrected; but T+82 written reply is a regulatory action, so not scored as observed |
| No one asks when MedDefense's discovery clock started | No | T+76 Reyes |
| Patient count not discussed or assumed zero | No | Discussed (T+77), but only because the inject gave it (DF-03) |

**Inject result:** FAIL (criteria 1, 2, 4, 6) -> finding F-004

**Facilitator note:** At T+85 asked: "If the vendor sends letters, whose name is on them, and who does HHS fine if they are late?" Reyes: "Ultimately us, as the Covered Entity." She knew the rule when probed, but the team's default was to let the vendor own it. Because the inject handed over "41,000 patients", nobody had to work out the scope and CAP-04 was barely tested (DF-03).

---

## INJ-05 (T+90 min): window T+90 to T+105

**Capability:** CAP-07 crisis_communications | **Evaluation owner:** EVAL-LEAD

**Inject delivered:** "A reporter from the regional health news outlet emails Marcus Webb: 'We have a copy of Nexus advisory NX-SA-2026-004 listing MedDefense as an affected customer, and patients posting that their chemotherapy appointments were cancelled by text message. Can you confirm patient data was stolen? We publish at 11:00.' It is 09:45. The West Campus call center has received 60 calls in 30 minutes and agents are telling patients 'it is a Nexus system problem'."

**Participant responses:**

- T+92 James Chen (SOC Lead): "We cannot confirm theft. We can confirm the vendor incident."
- T+93 Sarah Park (IT Director): "Call center agents should stop naming Nexus."
- T+94 Dr. Patricia Morales (CISO): "Marcus, draft; Helena and I approve by 10:30."
- T+96 Helena Reyes (General Counsel): "No confirmation or denial of data theft. Say we are investigating with the vendor and patients should call to verify appointments."
- T+99 Clinical Director representative: "My nurses are calling oncology patients now; the paper is already out of date because of the calls."
- T+101 Marcus Webb (Communications): Sends the holding statement draft to Reyes and Morales.
- T+112 (10:07, inside the INJ-06 window): Reyes and Morales approve the statement; published.
- Robert Kim (Infrastructure Lead): Not engaged.

**Pass criteria:**

| # | Criterion | Result | Time and evidence |
|---|---|---|---|
| 1 | Holding statement approved by Legal and CISO before 11:00 | PASS (note) | Approved T+112 (10:07), 53 minutes before the 11:00 deadline. The approval came after INJ-06 was delivered (T+105), so it is outside the inject window. Scored PASS because the criterion sets its own deadline (11:00) and the late approval was caused by the INJ-05 / INJ-06 overlap, not by the team (DF-04). Under a strict window reading this would be FAIL; the inject result is FAIL either way |
| 2 | Vendor incident confirmed, no data theft claim, how to verify appointments | PASS | T+96 wording by Reyes, used in the approved text |
| 3 | Call center script with priority line | FAIL | Only guidance was T+93 Park's "stop naming Nexus"; no script, no priority line for time-critical patients |
| 4 | No joint statement with Nexus before facts aligned | PASS | Joint statement declined at T+39 (INJ-02) and not revisited |

**Fail indicators:**

| Fail indicator | Observed? | Evidence |
|---|---|---|
| Deadline passes with no statement / "no comment" | No | Published 10:07 |
| Statement confirms or denies theft without evidence | No | T+96 wording |
| Call center keeps giving inconsistent answers (no script) | **Yes** | No script issued in the window |
| Joint statement agreed without Legal review | No | Declined T+39 |

**Inject result:** FAIL (criterion 3; one fail indicator) -> finding F-006

**Facilitator note:** At T+103 asked: "A patient calls at 10:15 asking whether her chemo tomorrow is still on. What exactly does the agent say?" Nobody could answer. The public statement was handled well; the patient-facing line, where the patient safety risk is, had nothing.

---

## INJ-06 (T+105 min): window T+105 to T+130 (hotwash)

**Capability:** CAP-08 executive_briefing_under_pressure (secondary CAP-01, CAP-05) | **Evaluation owner:** EVAL-LEAD

**Inject delivered:** "The Board Chair calls Dr. Morales: an emergency board call is scheduled in 90 minutes and she needs a written status brief 30 minutes before. At the same time Nexus releases signed version 4.12.4, 'clean and verified', and asks all customers to re-enable automatic updates so the fix can roll out. Nexus still cannot confirm whether updates before 4.12.3 in the 21-day window were clean, and cannot say whether the 2.3 GB contained PHI."
*(v1.1 moves this inject to T+115, see DF-04.)*

**Participant responses:**

- T+107 James Chen (SOC Lead): "We don't install anything signed with a key they just told us was stolen."
- T+110 Sarah Park (IT Director): "If we don't install the fix, we stay on manual scheduling for days. It's signed and they say it's verified. I'd put it on SCHED-SVR-01 and watch it."
- T+111 Robert Kim (Infrastructure Lead): "If we install it, it goes back on the network. Isolated host won't get the update."
- T+115 Dr. Patricia Morales (CISO): Approves Park's plan to install 4.12.4 on SCHED-SVR-01 "under monitoring". No hash or certificate check requested.
- T+118 Dr. Patricia Morales with James Chen: Start the brief under "Known / Not known / Decisions / Patient safety".
- T+120 Helena Reyes (General Counsel): Adds regulatory section: "up to 41,000 patients, assessment started, discovery date in question".
- T+122 Marcus Webb (Communications): Adds media status (statement published 10:07).
- T+124 Clinical Director representative: Adds "38 time-critical patients: 31 reached, 7 pending, dialysis patient seen today."
- T+128 Brief finished (one page).

**Pass criteria:**

| # | Criterion | Result | Time and evidence |
|---|---|---|---|
| 1 | One-page written brief, confirmed / probable / unknown | PASS | T+128, one page with Known / Not known sections |
| 2 | Decisions listed with owners and times | PASS | Brief lists SEV1 (T+23, Morales), isolation (T+41, Kim), svc-nexus-prod disabled (T+53, Kim), statement (T+112, Webb / Reyes / Morales), 4.12.4 on SCHED-SVR-01 (T+115, Morales) |
| 3 | Patient safety and regulatory exposure in brief | PASS | T+124 and T+120 sections |
| 4 | Specific decisions requested from the board | FAIL | Brief informs but asks nothing (vendor suspension, outside counsel, notification budget not requested) |
| 5 | 4.12.4 not installed until verified out of band | FAIL | T+115 Morales approves install because it is signed and "verified" by the vendor; no independent hash or certificate check |
| 6 | Open questions stated explicitly | PASS | Brief lists pre-4.12.3 updates and PHI in the 2.3 GB as unknown; notification clock start "under review" |

**Fail indicators:**

| Fail indicator | Observed? | Evidence |
|---|---|---|
| Brief delayed or verbal only | No | Written, T+128 |
| Probable facts presented as confirmed, or unknowns omitted | No | Unknowns listed; patient count given as "up to" |
| Signed 4.12.4 re-enabled because it is signed, no independent verification | **Yes** | T+115 |

**Inject result:** FAIL (criteria 4, 5; one fail indicator) -> findings F-007, F-008

**Facilitator note:** At T+116 asked: "What has changed about the signature since Friday?" Chen: "Nothing; that's the problem." Park: "They have a new key." Nobody had confirmed whether there was a new key. The team repeated the exact trust assumption (residual risk R1) that caused the compromise, under the pressure of restoring scheduling. Open questions left unresolved at ENDEX, as designed: whether pre-4.12.3 updates were malicious, whether the 2.3 GB held PHI, and when the 60-day clock started.

---

## Secondary capability observation: CAP-04 phi_exposure_assessment (EVAL-REG)

CAP-04 has no inject of its own; it is scored through INJ-02 and INJ-04.

| Expected behavior (capability_map.yaml) | Observed? | Time and evidence |
|---|---|---|
| Data elements the agent can read are listed | No | Nobody listed demographics / insurance / appointment / rostering data |
| Number of patients in the compromise window worked out | No | Count handed over by the v1.0 INJ-04 text (DF-03) |
| Outbound volume to 193.42.100.77 considered | Yes | T+72 Chen: "2.3 GB is a lot for a beacon. We can't say it's PHI yet." |
| Twilio / SendGrid PHI asked about | No | Never raised (T+36 to T+50, T+70 to T+90) |
| Confirmed / probable / unknown separation | No | Not used until the INJ-06 brief |

**Result:** not demonstrated -> recorded under F-004 (INJ-04 criterion 6) and DF-03.

---

## Key decision log

| Time | Decision | Owner | Authorized by |
|---|---|---|---|
| T+2 | Incident declared SEV2 | Chen | Chen (IR Commander) |
| T+5 | Containment held until memory image | Morales | Morales |
| T+23 | Severity raised to SEV1 | Morales | Morales |
| T+38 | Isolate SCHED-SVR-01/02/03 and FHIR tunnel ("in principle") | Kim (execution) | **Not recorded** (F-001) |
| T+38 | Vendor request to keep agents online refused | Morales | Morales |
| T+40 | NDA refused on the call | Reyes | Reyes |
| T+41 | Isolation and tunnel block completed | Kim | (see T+38) |
| T+53 | svc-nexus-prod disabled | Kim | Morales (T+52 patient safety call) |
| T+54 | Patient outreach: 38 time-critical by treatment date, nephrology on-call for missed dialysis | Clinical Director | Morales (T+52) |
| T+79 | 72-hour patient list by 18:00 | Kim | Morales |
| T+82 | Written reply to Nexus on notifications | Reyes | Reyes |
| T+112 | Holding statement published | Webb | Reyes, Morales |
| T+115 | Install 4.12.4 on SCHED-SVR-01 "under monitoring" | Park | Morales (F-007) |
| never | Automatic Nexus updates disabled | none | none (F-007) |

---

## Summary of results

| Inject | Capability | Evaluator | Criteria passed | Fail indicators observed | Result | Finding |
|---|---|---|---|---|---|---|
| INJ-00 | CAP-01 | EVAL-LEAD | 3 / 5 | 2 | FAIL | F-005 |
| INJ-01 | CAP-02 | EVAL-CLIN | 4 / 6 | 2 | FAIL | F-001, F-007 |
| INJ-02 | CAP-03 | EVAL-REG | 3 / 5 | 1 | FAIL | F-003 |
| INJ-03 | CAP-06 | EVAL-CLIN | 3 / 5 | 1 | FAIL | F-002 |
| INJ-04 | CAP-05 | EVAL-REG | 2 / 6 | 0 | FAIL | F-004 |
| INJ-05 | CAP-07 | EVAL-LEAD | 3 / 4 | 1 | FAIL | F-006 |
| INJ-06 | CAP-08 | EVAL-LEAD | 4 / 6 | 1 | FAIL | F-007, F-008 |
| (secondary) | CAP-04 | EVAL-REG | not demonstrated | n/a | FAIL | F-004 |

Every inject produced at least one finding. The design target was that each inject is hard enough to fail: this held, but DF-02 and DF-03 show two criteria were easier than intended because the inject text gave the answer.

### Finding traceability

Every failed criterion maps to one finding in `after_action_report.md`:

| Finding | Failed criteria | Capability |
|---|---|---|
| F-001 | INJ-01 c1 | CAP-02 |
| F-002 | INJ-03 c4, c5 | CAP-06 |
| F-003 | INJ-02 c1, c3 | CAP-03 |
| F-004 | INJ-04 c1, c2, c4, c6 | CAP-05, CAP-04 |
| F-005 | INJ-00 c4, c5 | CAP-01 |
| F-006 | INJ-05 c3 | CAP-07 |
| F-007 | INJ-01 c5, INJ-06 c5 | CAP-01, CAP-08 |
| F-008 | INJ-06 c4 | CAP-08 |

---

## Hotwash (T+130 to T+150) and ENDEX

Each role answered "what went well / what would you change" (simulated):

- **Chen:** declaring early and imaging first worked; the hunt should have covered all three agent hosts from T+0.
- **Park:** did not know she could, or could not, take Nexus offline; wants the authority written down.
- **Morales:** approving 4.12.4 under schedule pressure was the wrong call; the board brief needs an "asks" section.
- **Reyes:** knew the Covered Entity rule but did not say it until probed; wants a BA-breach checklist.
- **Webb:** the public statement was on time; the call center had nothing.
- **Kim:** nobody told the front desks to stop correcting records.
- **Clinical Director:** the paper fallback worked only because the nurses improvised the call order.

**ENDEX:** T+150. Open questions handed to the AAR: pre-4.12.3 updates in the 21-day window, PHI in the 2.3 GB, start of the 60-day clock.

---

## Design feedback

### DF-01: The patient safety signal arrived after the continuity decision

In v1.0 the first sign that appointments had been modified arrived at INJ-03 (T+50), but the decision to take Nexus offline was forced at INJ-01 (T+20). In the simulation the team argued about isolation purely as availability vs. confidentiality, and the Clinical Director argued *against* immediate isolation to protect today's schedule, not knowing the schedule itself might be wrong. The data integrity concern should shape the continuity decision, not follow it.

**Change made:** INJ-01 (v1.1) now includes a secondary fact: "the West Campus front desk reports that two patients arrived for appointments that Epic shows as cancelled". The full scope (212 changes, 38 time-critical) stays in INJ-03. Added the fail indicator "the two patients arriving for cancelled appointments are not linked to the incident" to INJ-01 in evaluation_criteria.yaml.

### DF-02: The vendor discovery date was handed to the team

In v1.0 the Nexus engineer volunteered "we first saw signs on Thursday". INJ-02 criterion 4 (record the vendor discovery date for the BAA clock) was therefore passed without anyone having to ask, so the exercise did not test whether MedDefense knows to ask a vendor for its discovery date, which is the key fact for the HIPAA timeline.

**Change made:** INJ-02 (v1.1) role-play instruction: the Nexus SecOps role-player gives the discovery date **only if a participant asks when Nexus first detected the compromise**; otherwise says "we are still building the timeline". Criterion 4 stays the same, so it now measures the question, not the listening.

### DF-03: INJ-04 gave the PHI scope as a number

In v1.0 INJ-04 said "about 41,000 patients". CAP-04 (phi_exposure_assessment) is supposed to test whether the team can scope exposure. With the number handed over, participants discussed the headline but nobody worked out how the scope is built (which data elements, which time window, which subprocessors). Marcus Webb used the number as fact.

**Change made:** INJ-04 (v1.1) states only the raw facts: the agent can query demographics and insurance for patients scheduled in the last 18 months, three sites, 3,500 interactions per week. The facilitator reveals "about 41,000 unique patients" only if a participant asks the Epic team for a count. Added to the facilitator script: track whether Twilio / SendGrid data is raised (subprocessors were never mentioned in the simulation).

### DF-04: INJ-05 and INJ-06 overlap too much for a fair executive briefing test

INJ-06 arrived at T+105 while the holding statement from INJ-05 was still being approved (T+112). Dr. Morales was approving the media statement and drafting the board brief at the same time, so the CAP-08 failure (no board asks) is partly caused by the exercise timing, not only by the organization. The overlap also pushed the INJ-05 approval outside its own inject window (see INJ-05 criterion 1).

**Change made:** INJ-06 moved from T+105 to T+115 and hotwash from T+130 to T+140; exercise duration extended to 160 minutes. The 90-minute board deadline in the inject text stays, as the pressure is intended.

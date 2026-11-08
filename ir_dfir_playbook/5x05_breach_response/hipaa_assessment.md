# HIPAA Breach Risk Assessment: IR-2026-0420-01

- Assessment date: 2026-04-20 (started 23:00Z, completed 23:50Z)
- Conducted by: Tales Lima, on-call IR (evidence and analysis)
- Reviewed by: Helena Reyes, General Counsel (pending), with the MedDefense Privacy Officer
- Method: 45 CFR 164.402(2): an impermissible use or disclosure of PHI is presumed to be a breach unless the covered entity shows a low probability that the PHI has been compromised, based on at least the four factors below. Playbook node `hipaa_assessment` (PB-001, update PB-UPD-004).
- PHI involved: 1,847 patient files (lab results and clinical notes) accessed from FILE-SVR-01 (`D:\clinical\labs\`, `D:\clinical\notes\`)
- Discovery date: 2026-04-20 (incident declared 19:52Z; PHI access confirmed during the forensic phase, FS-001, 22:05Z). The 60-day notification clock (45 CFR 164.404) runs from discovery, 2026-04-20, and in no case later than 2026-06-19.
- Evidence references: `forensic_findings.md` finding IDs (FS-001, FS-002, FS-003, PROXY-002, PROXY-003, MEM-003, MEM-004, MEM-005, SYS-002, SYS-003, SYS-004) and `containment_execution.md` step IDs (C-xx).

## Factor 1: Nature and extent of PHI involved

Evidence:
- FS-002: 1,847 distinct PDF files, each read once: 1,104 lab result reports (`D:\clinical\labs\2026-04-15` to `2026-04-18_panel_*.pdf`) and 743 clinical progress notes (318 emergency department admissions, 425 inpatient floor 4).
- Lab reports and progress notes at MedDefense carry the patient's full name, medical record number, date of birth, ordering clinician and clinical content (test values, diagnoses, ED presenting complaint, treatment notes). These are direct identifiers combined with sensitive clinical information. Re-identification needs no effort: the documents name the patient.
- ED admission notes can include mental health, substance use, injury and other high-sensitivity details.
- FS-002: the attacker took all recent files in both folders rather than selected patients, so the exposure covers every patient with a lab panel on 15-18 April and every ED / floor 4 admission note in the folder.
- The number of individuals is below or equal to 1,847 (several files per patient are expected) and is being established by Health Information Management from the MRNs (forensic_findings.md open item 1).

Conclusion: high risk. The PHI is directly identifiable, clinically sensitive (lab results, ED and inpatient notes) and covers a large population. This factor alone weighs heavily against a low-probability finding.

Confidence: high on the type and sensitivity of the data (file categories confirmed, content type probable from folder and naming); medium on the exact number of individuals (pending MRN mapping, but it is certain to be well above 500 unless almost every patient has three or more files, which the 4-day lab spread makes unlikely).

## Factor 2: The unauthorized person who used the PHI or to whom it was disclosed

Evidence:
- MEM-004 and DISK-004: the reads were done by a Cobalt Strike beacon (reflective `beacon.x64.dll`) run by an external operator, not by a workforce member.
- PROXY-002: C2 at 45.152.66.114, listed by the proxy reputation feed as a known Cobalt Strike team server, reached through a look-alike Microsoft domain registered by the attacker.
- SYS-003 and SYS-004: the same actor staged a ransomware script on four workstations and started its beacon on the scheduling server. This is the usual pattern of financially motivated extortion groups, who steal data before encryption to pressure victims ("double extortion").
- FS-003: the account used (MEDDEFENSE\jdoe) was stolen (MEM-005, SYS-002). jdoe herself did not access the files; she was asleep and her workstation was operated remotely.
- The recipient is not another HIPAA covered entity or business associate bound to protect the data, and no assurance can be obtained from it.

Conclusion: high risk. The PHI was accessed by a criminal external actor with intent to monetize, the worst case for this factor.

Confidence: high (external actor and tooling confirmed; extortion motive probable from the ransomware staging).

## Factor 3: Whether the PHI was actually acquired or viewed

Evidence:
- FS-001: 1,847 events 4663 with access mask `0x1` (ReadData) by `svchost32.exe` on FILE-SVR-01, 2026-04-19T02:14:01Z to 02:41:12Z. Reading the full file content is confirmed; this is not just listing a directory.
- PROXY-003: 2,400,412 bytes sent from FILE-SVR-01 to the C2 at 02:14:22Z, inside the same attacker session as the reads. It is the only large transfer from the file server in 72 h.
- The transfer is much smaller than 1,847 full PDFs. It could be a compressed subset, extracted text or a list of files. The TLS session was not inspected, so the content of the 2.4 MB cannot be established.
- No DLP or content inspection exists on that path; no evidence can show that any given record was **not** sent.

Conclusion: acquisition is probable and cannot be excluded for any of the 1,847 files. The PHI was read by the attacker's code (confirmed) and data left the server to the attacker (probable). MedDefense cannot show which records stayed private, so this factor does not support a low probability of compromise.

Confidence: high that the files were read; medium on how much was exfiltrated. The uncertainty runs against MedDefense: the burden is on the covered entity to prove low probability, and the evidence cannot do it.

## Factor 4: The extent to which the risk to the PHI has been mitigated

Evidence:
- containment_execution.md C-02, C-15 to C-18: C2 severed on all six hosts at 20:31Z-20:33Z, confirmed from firewall, proxy/DNS and EDR telemetry. No attacker access to FILE-SVR-01 since 2026-04-19T02:41:18Z (FS-001).
- C-07: the staged ransomware script is blocked fleet-wide; no encryption of the patient files took place (FS-001: ReadData only; files intact).
- C-10 to C-14: jdoe and all accounts exposed on the six hosts reset; no privileged account exposed.
- Mitigation came **after** the exposure: the files were read and the 2.4 MB transfer happened about 41 hours before containment. Nothing done tonight can recall data already sent.
- No assurance, return or destruction of the data can be obtained from a criminal actor. Monitoring for publication (leak sites) starts with external IR support; nothing has been seen yet, which is not proof of anything.

Conclusion: partial mitigation only. Further harm is prevented (no more access, no encryption, credentials reset), but the risk that comes from the data already taken is unchanged.

Confidence: high (containment confirmed by three independent sources; the limit of mitigation follows from the timeline).

## Determination

The four-factor assessment **does not** support a conclusion of low probability of compromise. Factors 1 and 2 are high risk, factor 3 cannot show that the PHI was not acquired, and factor 4 limits future harm but does not reduce the harm from the data already taken. Under the breach presumption in 45 CFR 164.402, this is a **reportable breach of unsecured PHI. Notification is required.**

Obligations that follow (to be confirmed by General Counsel):
- Individual notice to each affected patient without unreasonable delay and no later than 60 days after discovery (by 2026-06-19), first-class mail, content per 45 CFR 164.404(c).
- HHS (OCR) notice at the same time as individual notice if 500 or more individuals are affected (45 CFR 164.408), which is expected here.
- Media notice in each state or jurisdiction with more than 500 affected residents (45 CFR 164.406).
- State breach laws and any business associate contract obligations reviewed by Legal.
- Substitute notice if contact details are missing for 10 or more patients.

Final determination: made by **Helena Reyes, General Counsel (Legal_Liaison)**, with the Privacy Officer, on this assessment and the HIM patient count. Target: signed before Dr. Patricia Morales presents to the board at **07:00 on 2026-04-21**, so the board hears a decided regulatory position (draft reviewed by Helena Reyes on the bridge at 23:50Z; written sign-off due 06:30Z). The assessment and its evidence are retained for at least six years (45 CFR 164.530(j)).

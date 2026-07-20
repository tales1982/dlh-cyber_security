# 15. The Medical IoT — MedDefense Vulnerability Scan

**Analyst:** Threat Intelligence Analyst
**Date:** Current

## BD Alaris Assessment

The real BD/CISA advisory for this vulnerability (CISA ICSMA-20-317-01, "BD Alaris 8015 PC Unit and BD Alaris Systems Manager Network Session Vulnerability," CVE-2020-25165) describes a network session authentication weakness between the BD Alaris 8015 PC Unit and the BD Alaris Systems Manager: an attacker on the same network can intercept and manipulate the authentication handshake, potentially forcing the pump's wireless capability offline (a denial-of-service condition, not data theft or dosage manipulation). BD's own published CVSS v3 score for this is **6.5** (`AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:L`) — notably **lower** than the 7.5 the scan report assigns (`C:N/I:N/A:H`), a discrepancy worth flagging on its own: the scan's own impact rating (full Availability loss, no Integrity impact) doesn't match the vendor's official scoring (partial Integrity and Availability impact) for the same CVE, and this is worth resolving directly with BD or the original advisory before treating either number as final.

**Affected versions and fix:** Public advisories consistently describe affected units as **BD Alaris PC Unit Model 8015, versions 9.33.1 and earlier**, with the fix landing in **software version 12.1.1 and later**. This surfaces a second, more consequential discrepancy: MedDefense's fleet is running firmware **12.1.2** — a version *later* than the documented fix (12.1.1). Taken at face value, this suggests the pumps may already be patched against CVE-2020-25165 specifically, and Finding 010 may be flagging a version that no longer contains this exact flaw. **This needs to be validated directly against BD's official bulletin and MedDefense's specific device configuration before being dismissed** — it is exactly the kind of claim this project's earlier false-positive analysis (Task 11) teaches you not to accept without checking, in either direction.

**Vendor recommendation, and what MedDefense has and hasn't done:** Separate from the firmware question, BD's bulletin recommends **network isolation** of the pump fleet as the primary mitigation regardless of firmware version. On this point, the scan report is unambiguous and requires no further validation: "vendor-recommended isolation as mitigation has **not** been done." MedDefense has, at best, only partially followed BD's guidance (possibly current on firmware, but confirmed not network-isolated) — and the report separately confirms 7 of 7 scanned pumps still use unchanged default web-interface credentials (`admin/admin`), a finding entirely independent of firmware version and unambiguously unaddressed.

## Philips IntelliVue Assessment

The exposed interfaces on the Philips IntelliVue fleet carry two distinct categories of data: the web management interface (ports 80/443) exposes device configuration and status, while port 2575 carries live **HL7 (Health Level 7)** traffic — the healthcare industry-standard protocol for exchanging clinical data, meaning real-time patient vitals (heart rate, SpO2, blood pressure, respiratory rate) flowing directly from the monitor to whatever system aggregates it. Documented real-world vulnerabilities in this exact device family (CISA ICSMA-18-156-01, CVE-2018-10599/10597/10601) describe unauthenticated **read and write** access to device memory over the network within the same subnet — meaning an attacker with the network access MedDefense's flat topology already provides would not need to discover a new flaw at all; the documented capability alone allows reading a patient's live vitals data, writing arbitrary values into device memory (falsifying a vitals reading a clinician relies on), or triggering a denial-of-service restart of the monitor itself, per the same advisory. With 13 of these monitors already confirmed reachable network-wide (Finding 016) and firmware dating as far back as 2019, this is not a hypothetical capability — it is a documented one, sitting on hardware already exposed exactly as required to trigger it.

## Patient Safety Dimension

A compromised IT workstation is, at worst, a confidentiality or integrity problem for data: records get read, files get encrypted, operations get disrupted, and recovery — however painful — restores a known-good state. A compromised infusion pump or patient monitor is a **direct physical safety problem for a specific human being connected to it at that moment**: a falsified vitals reading can delay a clinician's response to a real deterioration, and a manipulated dosage on an Alaris pump is not "corrupted data" — it is medication delivered incorrectly to a patient's bloodstream, in real time, with no "restore from backup" available after the fact. The worst-case scenario for a compromised workstation is a bad day for the IT department; the worst-case scenario for a compromised infusion pump is a preventable patient death, which is precisely why medical device findings cannot be scored, prioritized, or remediated on the same scale as a server finding of identical CVSS.

## Remediation Challenge

Patching medical devices is categorically harder than patching IT systems for at least three reasons:

1. **Regulatory:** Medical devices like infusion pumps and patient monitors are FDA-regulated hardware/software bundles — a firmware change can require the vendor to re-validate and, in some cases, re-clear the device configuration before it can legally be deployed clinically, meaning MedDefense cannot simply "apply the patch" the way it would on a Linux server even after the vendor releases one.
2. **Operational:** These devices are in active clinical use around a patient, often continuously — there is no equivalent to a routine maintenance window that doesn't risk interrupting monitoring or medication delivery for a real patient at that moment, which is exactly why BD's own recommended mitigation here is network isolation rather than an urgent mandatory firmware push.
3. **Vendor dependency:** MedDefense cannot patch BD or Philips firmware itself under any circumstances — every fix must come from the manufacturer on the manufacturer's own release schedule, and MedDefense has zero ability to accelerate that timeline the way it could prioritize an internal engineering fix; this is the same structural dependency already established for the MRI workstation in Task 12, just recurring across the entire medical device fleet rather than one machine.

## Repo

- **GitHub repository:** `dlh-cyber_security`
- **Directory:** `blue_team/1x02_the_weak_links`
- **File:** `15-medical_iot.md`

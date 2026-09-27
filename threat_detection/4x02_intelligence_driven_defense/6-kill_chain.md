# HEALTHBANE Kill Chain Reconstruction

## 1. Campaign Timeline

| Event | Date | Source |
|---|---|---|
| Earliest infrastructure acquisition (C2 IP 51.38.42.191 first_seen) | 2026-03-24 | Commercial feed |
| Earliest possibly-related but unconfirmed phishing activity (rx-benefits-portal.com) | 2026-03-28 – 2026-04-10 | Commercial feed (self-flagged "possibly earlier campaign by same operator," not confirmed HEALTHBANE) |
| Lookalike domains registered | 2026-04-05 – 2026-04-10 | HC3, MedDefense (exact dates: meddefense-portal.com 04-09, medequip-supplies.net 04-08, meddefense-benefits.org 04-10) |
| **Earliest confirmed HEALTHBANE activity** | **2026-04-14** | HC3 (first reported phishing email, Midwest ISAC partner) |
| **MedDefense Stage 1 event** (dmarsh clicks Email 2) | **2026-04-14 15:02:33 UTC** | MedDefense 4x00 |
| Stage 1 window (all 6 HC3-visible orgs) | 2026-04-14 – 2026-04-16 | HC3 |
| Researcher obtains live kit access | 2026-04-18 | Researcher blog |
| Stage 2 malware delivery window | 2026-04-16 – 2026-04-22 | HC3 |
| Kit infrastructure taken down | ~2026-04-22 | Researcher blog |
| Researcher notifies HC3; HC3 requests 72h publication delay | 2026-04-22 | Researcher blog |
| Stage 3 exfiltration window | 2026-04-23 – 2026-04-26 | HC3 |
| Researcher blog published | 2026-04-24 14:22 UTC | Researcher blog |
| **HC3 advisory published** | **2026-04-25** | HC3 |
| **Most recent reported event** (commercial feed indicator last-seen / extract date) | **2026-04-26** | Commercial feed |

Note on the earliest date row: infrastructure *acquisition* (IP allocation,
domain registration) necessarily precedes *use*, and is not itself evidence
of earlier attacks — it reflects normal attacker operational lead time
(registering domains and standing up VPS infrastructure before the first
phishing email goes out). The `rx-benefits-portal.com` entry is kept
separate and explicitly labeled unconfirmed because the commercial feed
itself only asserts a *possible* link to an earlier campaign by the same
operator, not confirmed HEALTHBANE activity.

## 2. Attack Phases

### Stage 1 — Credential Harvesting

- **Phishing operation:** Spear-phishing emails impersonating
  healthcare-adjacent senders (staff portal, insurance, HR benefits),
  sent via PHPMailer 6.6.0. Landing pages are served by a PHP-based,
  single-page credential harvester (`index.php` + `handlers/post.php`)
  that is **per-target templated** — logos and text are pulled
  programmatically from each real target organization's own website
  rather than manually customized, indicating mass production across
  many victim organizations, not bespoke lures.
- **Targeting pattern:** US healthcare providers, strongest signal in the
  Midwest ISAC region; sector scope includes hospital systems, outpatient
  clinics, medical billing services, and regional insurance administrators
  (explicitly *not* observed: medical device manufacturers, pharmacies,
  public health departments). At MedDefense specifically, three employees
  across two functional roles were targeted — a clinical nurse (dmarsh)
  and two finance/billing staff (arivera, lpatterson) — indicating
  indiscriminate targeting across departments rather than a role-specific
  campaign.
- **Infrastructure used:** Namecheap-registered lookalike domains
  registered 4–10 days before first use, hosted on Hostinger,
  DigitalOcean, or OVH. One domain (`outlook-protection.com`) is a
  higher-sophistication variant: fully SPF/DKIM/DMARC-authenticated
  because the attacker correctly configured DNS for their own lookalike
  domain, meaning email-authentication-based detection alone would not
  catch it (per MedDefense 4x00 finding F3).
- **Known victims:** At least 14 healthcare organizations targeted
  sector-wide; HC3 has direct or partner visibility on 6, all 6 of which
  (100%) experienced Stage 1.
- **MedDefense evidence:** Three flagged emails (E2, E5, E7) shared the
  PHPMailer 6.6.0 X-Mailer header, Namecheap lookalike domains, and
  SPF/DKIM/DMARC failure (E2, E5, E7) or the authenticated-lookalike
  pattern (E3/outlook-protection.com). dmarsh clicked Email 2 at
  2026-04-14 15:02:33 UTC.
- **Success rate across reported victims:** At the organization level, HC3
  reports 100% (6/6) of visible organizations experienced Stage 1. At the
  individual level within MedDefense, 1 of 3 targeted employees clicked
  (33%) — the two metrics are not contradictory: an organization is
  "hit" at Stage 1 if any employee is targeted with a credible lure,
  regardless of how many individuals within it actually click.

### Stage 2 — Malware Delivery via Macro Document

- **Transition from stolen credentials to follow-up emails:** Stage 1
  credentials were used to authenticate directly to the victim's cloud
  email account. The attacker then sent follow-up emails **from the
  compromised account itself** to the victim's colleagues — an
  insider-trusted-sender technique that bypasses much of the suspicion a
  fresh external sender would raise.
- **Document type:** `.docm` macro-enabled Word document
  (`HEALTHBANE_S2_invoice.docm`).
- **Malware/script artifacts:** The macro pulls a Windows executable
  (`svchost_update.exe`) from a secondary C2 domain. The researcher
  additionally recovered a PowerShell exfiltration script
  (`sync_healthdata.ps1`) directly from the kit's own `tools/` directory.
  The commercial feed additionally reports one higher-confidence trojan
  variant (`update_service_v2.exe`, Acme confidence 82) and HC3 reports
  one lower-confidence dropper variant observed at a single partner
  organization.
- **Download infrastructure:** `healthbane-c2.net`
  (`https://healthbane-c2.net/update/svchost_update.exe`) and
  `update-healthbane.net`.
- **Persistence mechanisms:** A scheduled task named "HealthSync Update
  Service" and a Registry Run key.
- **Evidence source:** HC3 (sandbox analysis plus direct observation at 2
  organizations), corroborated by commercial-feed hash confidence scores
  in the 90s for the two highest-confidence samples.
- **MedDefense status:** A mass EDR scan performed 2026-04-16 found **no
  matching hash** on any MedDefense endpoint — a confirmed *negative*
  finding, not an unknown: MedDefense did not experience Stage 2.
- Observed at 2 of 6 HC3-visible organizations (33%).

### Stage 3 — Data Exfiltration via DNS Tunneling

- **Data targeted:** Patient records and insurance claims data.
- **Protocol/tool:** DNS TXT-record tunneling. Data is base32-encoded into
  subdomain labels of TXT queries sent to `data-sync.healthbane-c2.net`,
  at an observed interval of 10–15 seconds, with label lengths of 44–60
  characters. C2 responses also use TXT records, containing
  base64-encoded command strings.
- **Exfiltration infrastructure:** `data-sync.healthbane-c2.net`
  (a subdomain of the confirmed Stage 2/3 C2 domain).
- **Evidence source:** HC3, rated HIGH confidence specifically because it
  is based on direct packet captures from 2 compromised organizations —
  the strongest evidentiary basis of any claim in this advisory.
- **MedDefense status:** No evidence either way — since MedDefense did not
  experience Stage 2, there is no basis to assess Stage 3 exposure at
  MedDefense at all (this is a scope gap, not a negative finding, unlike
  Stage 2's confirmed-absent status above).
- **What is confirmed vs. unclear:** Confirmed: the tunneling mechanism,
  encoding scheme, cadence, and that it occurred at 2 specific
  organizations, via direct packet evidence. Unclear: the total volume of
  data actually exfiltrated sector-wide, whether DNS tunneling was the
  only exfiltration channel used or simply the one channel HC3 happened
  to capture, and whether any organizations beyond the 2 directly observed
  also reached Stage 3.
- Observed at 2 of 6 HC3-visible organizations (33%).

## 3. Evidence Quality Assessment

| Phase | Confirmed evidence | Corroborated evidence | Inferred evidence | Unknowns |
|---|---|---|---|---|
| Stage 1 | MedDefense: E2/E5/E7 headers, dmarsh click event (4x00, packet-confirmed in 4x01). HC3: 100% of 6 visible orgs. | Domain/IP infrastructure cross-confirmed by HC3, commercial feed, and researcher's direct kit access. | Total sector-wide click/compromise rate beyond the 6 HC3-visible orgs. | Individual outcomes at the ≥8 organizations with no HC3 visibility. |
| Stage 2 | HC3: sandbox analysis + direct observation at 2 orgs. MedDefense: confirmed NOT experienced (EDR scan, negative result). | Hash values cross-confirmed by HC3 and commercial feed at high `acme_confidence`. | Full extent of persistence/lateral activity beyond the two documented mechanisms. | Whether any of the 4 other HC3-visible-but-Stage2-negative orgs show partial Stage 2 indicators not yet reported. |
| Stage 3 | HC3: direct packet captures at 2 orgs, HIGH confidence per HC3's own sourcing section. | DNS-tunneling domain and IP cross-confirmed by commercial feed. | Total data volume exfiltrated; whether DNS tunneling is the sole exfil channel. | MedDefense exposure (no data either way); sector-wide Stage 3 prevalence beyond the 2 confirmed orgs. |

## 4. What Is Not Known

- **Attribution gaps:** Three different, non-overlapping-confirmed
  attribution postures exist (HC3: unconfirmed; commercial feed:
  VITALSCORE via automated clustering; researcher: APT-MEDAGENT at
  self-rated MEDIUM confidence) — see `2-source_assessment.md` Section 4
  for the full analysis. No source has confirmed a named threat actor with
  HIGH confidence, and the two non-government sources do not even confirm
  each other.
- **Missing victim telemetry:** HC3 has visibility on only 6 of ≥14 known
  targeted organizations — roughly 8 or more organizations' actual outcomes
  (click rate, Stage 2/3 exposure) are completely unknown to this
  intelligence package.
- **Incomplete Stage 3 visibility:** Only 2 organizations' packet captures
  have been reviewed for exfiltration; the true sector-wide data volume
  lost, and whether DNS tunneling was the attacker's only exfiltration
  method, cannot be determined from the available sources.
- **Commercial-feed uncertainty:** 20 of the commercial feed's 41 raw
  indicators were classified CONTEXTUAL or NOISE in Task 1 — whether any of
  that unconfirmed material represents genuine additional campaign
  infrastructure (as opposed to clustering artifacts or unrelated shared
  hosting) remains genuinely open.
- **What collection would fill the gaps:**
  - Coordinated outreach through HC3 to the other ≥8 targeted
    organizations to obtain their Stage 1–3 outcomes.
  - Full packet capture or DNS resolver logs at the 2 confirmed Stage 3
    organizations, to quantify actual data volume exfiltrated rather than
    only the tunneling *pattern*.
  - Independent technical comparison (kit source, infrastructure
    fingerprint) between the researcher's privately-tracked
    RXBRIDGE/CLAIMBRIDGE/MEDNEXUS campaigns and Acme's VITALSCORE cluster,
    to determine whether APT-MEDAGENT and VITALSCORE genuinely refer to
    the same operator.
  - Ongoing monitoring of `portal-secure-meddefense.com` — the researcher's
    documented, not-yet-active staged domain — since it is the specific,
    named infrastructure most likely to be rotated into active use next.

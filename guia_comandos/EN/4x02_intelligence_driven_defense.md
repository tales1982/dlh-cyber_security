# 4x02 – Intelligence-Driven Defense: HEALTHBANE Campaign

Threat-intelligence synthesis for the same MedDefense incident traced in 4x00/4x01, now widened from "what happened to us" to "what campaign is this part of." Four independent sources (an HC3 sector advisory, a commercial CTI feed, an independent researcher's technical blog, and MedDefense's own 4x00 findings) are triaged, cross-assessed for reliability, reconstructed into a kill chain, mapped to ATT&CK, checked against real detection gaps, and turned into two genuinely tested YARA rules — every deliverable explicit about where its own evidence is strong, thin, or simply missing.

## Task - 0-intel_intake.md

What it does: Parses and normalizes indicators out of all 4 intelligence sources (HC3 sector advisory, a commercial CTI feed's JSON extract, an independent researcher's technical blog, and MedDefense's own 4x00 phishing-dissection findings) into one list, confirming 89 raw indicator mentions and deduplicating by exact literal value down to 50 unique indicators — explicitly documenting why that number differs from the lab's own 64-indicator reference figure (a dedup-methodology discrepancy, not an error hidden from the reader).
How to use it: read `0-intel_intake.md`
Commands:

- Deduplicating strictly by exact literal string value (not by "looks like the same indicator") — a conservative choice documented explicitly, since two nearly-identical entries (e.g. a URL with a differently-worded placeholder token) are kept as separate indicators rather than silently merged, and the file states exactly why that produces a different count than a looser dedup would.
- Cross-referencing every source's own confidence field (HC3's HIGH/MEDIUM, the commercial feed's 0-100 score, the researcher's stated confidence) rather than assigning a fresh confidence score from scratch — intake preserves each source's own judgment as data, instead of re-deriving one.

## Task - 1-indicator_triage.sh

What it does: Classifies all 50 unique indicators from Task 0 into ACTIONABLE (27, safe/justified to block or alert on outright), CONTEXTUAL (10, useful for hunting or correlation but not a block-list candidate), or NOISE (13, unreliable or would cause collateral damage) — with a one-line justification, a confidence rating, and an explicit "uncertain" flag per indicator, derived by reading each source's own stated evidence basis (a direct victim-telemetry hit, a kit-config.php reference, an unreviewed ML-clustering note) rather than computed from a generic scoring formula.
How to use it: `./1-indicator_triage.sh` (reads `0-intel_intake.md` from the same directory)
Commands:

- A pipe-delimited heredoc string (`type|value|sources|category|justification|confidence|uncertain`) as the entire indicator dataset, embedded directly in the script rather than a separate data file — keeps the 50 hand-triaged judgment calls and the code that reports them in one auditable place.
- Directly quoting a source's own hedge language in the justification field (the commercial feed's `"DO NOT BLOCK"`, `"LIKELY NOISE"`, `"Clustered by ML classifier on name similarity; human review not performed"`) instead of paraphrasing it — when a source itself says "don't act on this," that caveat survives into the triage verbatim rather than getting lost in a summary.
- Flagging a 62-character hash (2 short of a valid SHA-256) as CONTEXTUAL specifically because it "cannot be deployed to an EDR/AV blocklist as-is" — a data-quality defect on an otherwise 3-source-corroborated indicator is enough on its own to downgrade it, showing that corroboration and deployability are two different requirements.

## Task - 2-source_assessment.md

What it does: Applies the Admiralty Code (reliability A-F for the source, credibility 1-6 for the specific information) to all 4 intelligence sources, then directly confronts the 3-way attribution conflict between them — HC3 calls the activity HEALTHBANE, the commercial feed calls it VITALSCORE, the researcher's blog calls it APT-MEDAGENT — assessing which name (if any) should be trusted operationally, rather than picking one arbitrarily or silently using all three interchangeably.
How to use it: read `2-source_assessment.md`
Commands:

- The Admiralty Code's two independent axes (source reliability vs. this-specific-report's credibility) scored separately per source — a normally-reliable source can still publish a lower-credibility specific claim, and collapsing the two into one score would hide that distinction.
- Treating the attribution conflict as a naming/tracking problem to resolve for internal use, not a question this desk analysis can definitively answer — the assessment states which name the rest of this module's deliverables standardize on and why, without overclaiming certainty about who the actor actually is.

## Task - 6-kill_chain.md

What it does: Reconstructs the full 3-stage HEALTHBANE campaign timeline (phishing/credential harvest → second-stage payload delivery → DNS-tunnel exfiltration and C2) by merging every source's timestamped claims into one narrative, with an explicit evidence-quality table rating how well each stage is actually supported, and a dedicated "what is not known" section listing the gaps rather than quietly smoothing over them.
How to use it: read `6-kill_chain.md`
Commands:

- Building the same kind of per-stage evidence-quality rating this module uses again in Task 8 (DETECTED/PARTIALLY/NOT) and 4x01 uses for its own kill chain (CONFIRMED/STRONG INFERENCE/NOT VISIBLE) — a recurring pattern across this whole curriculum: never present a reconstructed timeline without also grading how solid each piece of it is.
- A dedicated "what is not known" section as a first-class part of the deliverable, not an afterthought — explicit about which stage transitions are inferred from timing correlation across sources rather than directly observed by any one of them.

## Task - 7-attack_navigator.md / healthbane_layer.json

What it does: Maps the reconstructed kill chain to 22 MITRE ATT&CK techniques (19 OBSERVED — directly evidenced by a source, 3 INFERRED — a reasonable but unconfirmed step the kill chain implies), narrated in `7-attack_navigator.md` and exported as a valid ATT&CK Navigator layer JSON (`healthbane_layer.json`) that can be loaded directly into the Navigator tool to visualize coverage.
How to use it: read `7-attack_navigator.md`; load `healthbane_layer.json` into MITRE ATT&CK Navigator
Commands:

- Tagging every technique as OBSERVED or INFERRED in the narrative *and* carrying that distinction into the JSON layer's own scoring/color metadata — a Navigator layer that doesn't distinguish confirmed from inferred techniques overstates how much of the kill chain is actually proven.
- Validating the output as well-formed JSON in the Navigator-layer schema (score, color, and technique-ID fields in the shape the real Navigator tool expects) rather than a free-form table — the deliverable is meant to be dropped directly into an external tool, not just read as a document.

## Task - 8-detection_gaps.md

What it does: Takes every one of Task 7's 22 ATT&CK techniques and checks it against MedDefense's own actual, documented detection inventory (not a hypothetical one), classifying each as DETECTED, PARTIALLY DETECTED, or NOT DETECTED, then produces a prioritized, actionable gap list — which specific technique to build detection for next, and roughly what that detection would need to look at.
How to use it: read `8-detection_gaps.md`
Commands:

- Cross-referencing against MedDefense's *actual* detection inventory rather than an idealized one — several techniques land as PARTIALLY DETECTED specifically because an existing rule covers a related but not identical behavior, a distinction that matters for prioritizing new work versus tuning existing rules.
- Prioritizing the gap list by a combination of how central the technique is to this specific campaign's kill chain and how completely undetected it currently is — not just a flat list of every NOT DETECTED technique in ATT&CK ID order.

## Task - 9-yara_phishing_pdf.yar

What it does: A single YARA rule (`HEALTHBANE_Phishing_PDF`) detecting the campaign's lure PDFs by their `wkhtmltopdf` tool fingerprint (present in both malicious samples, absent from both benign ones) combined with at least 2 of 6 credential-harvesting URL signals (`/verify`, `/login`, `/portal`, `/enroll`, `token=`, `id=`) — deliberately not keyed to any specific campaign domain, so it keeps matching future HEALTHBANE lures even after this batch's domains are burned and rotated. Real `yara` execution against the sample corpus: 2 TP, 2 TN, 0 FP, 0 FN.
How to use it: `yara 9-yara_phishing_pdf.yar <file_or_dir>`
Commands:

- `$pdf_magic = "%PDF" ascii` required `at 0` in the condition — confirms the file actually is a PDF before evaluating anything else, the same "check the file type first" discipline any content-based rule needs to avoid matching an unrelated file that happens to contain the same strings.
- `2 of ($path_verify, $path_login, $path_portal, $path_enroll, $param_token, $param_id)` — a threshold match across a *set* of related-but-not-identical signals instead of requiring one specific string, so the rule still fires on a lure using `/enroll` instead of `/login`, while a single coincidental hit on an unrelated PDF isn't enough on its own to trigger a false positive.
- A header comment explicitly citing the researcher blog's own warning ("indicator-based blocking will work for about one week; operational-pattern detections will survive rotation") as the *reason* the rule avoids hardcoding domains — the design decision is traced back to a specific source claim, not just asserted as good practice.

## Task - 10-yara_arsenal.yar

What it does: A second YARA rule (`HEALTHBANE_Email_Headers`), reconstructed from context since this specific task wasn't in the original prompt batch (documented explicitly in the file's header, with the reasoning shown), detecting Stage 1 phishing emails by requiring the kit's exact `PHPMailer 6.6.0` X-Mailer fingerprint plus at least one authentication-failure signal (SPF/DKIM/DMARC) plus at least one urgency-language subject cue. Real `yara` execution: 2 TP, 1 TN (+3 out-of-scope TN), 0 FP, 1 genuine FN — a real, diagnosed bug, not a simulated one.
How to use it: `yara 10-yara_arsenal.yar <file_or_dir>`
Commands:

- `$mailer` required unconditionally (not part of an "N of" set) while the auth-failure and urgency signals are each their own `1 of (...)` group — encodes that the mailer fingerprint is this rule's one truly distinguishing signal, and the other two conditions exist only to raise precision, not to substitute for it.
- The diagnosed false negative, documented directly in the rule file's own trailing comment: one sample's `X-Mailer` header uses a hyphen (`PHPMailer-6.6.0`) where the rule's literal string expects a space (`PHPMailer 6.6.0`) — an exact-literal-string YARA match is fragile to exactly this kind of one-character formatting drift, and the fix (a regex or an alternation) is scoped out to Task 11 rather than silently patched here.
- A header comment stating outright that no third "Campaign_Composite" rule was built, because the sample manifest defines no ground truth to test one against — refusing to ship an untestable rule rather than inventing one that looks complete.

## Task - 11-yara_testing.sh

What it does: Runs both YARA rules against the full 8-file sample corpus using real `yara` CLI execution (not simulated output), scoping ground truth *per rule* rather than per file (a PDF rule correctly staying silent on an .eml file is a true negative, not a missed detection, since the file is entirely outside that rule's domain), computing TP/TN/FP/FN, detection rate, false-positive rate, and precision per rule, explaining the diagnosed false negative from Task 10 and proposing a concrete fix, and issuing a DEPLOY/TUNE recommendation per rule based on the measured numbers.
How to use it: `./11-yara_testing.sh` (needs `yara` on PATH; reads `samples/` and `samples/samples_manifest.txt`)
Commands:

- Two separate `GT_PDF`/`GT_EMAIL` ground-truth heredocs, each labeling every one of the 8 sample files `Y`/`N` *for that specific rule* — the header comment explains directly why an earlier version of this script that shared one ground truth across both rules produced a misleadingly low detection rate: it counted "rule correctly ignored a file outside its scope" as a failure.
- `yara "$rule_file" "$filepath" 2>/dev/null | grep -q .` as the literal pass/fail test — a real subprocess call to the actual `yara` binary per file per rule, not a hardcoded prediction of what the rule "should" do.
- A `test_rule()` bash function parameterized by rule file, rule name, and ground-truth string, called once per rule — the same TP/TN/FP/FN accounting logic runs identically for both rules, so the two results are directly comparable instead of computed by two subtly different code paths.

## Task - 13-intelligence_brief.md

What it does: The final synthesis deliverable for MedDefense leadership and sector partners — executive summary, adversary profile, campaign analysis, the ATT&CK mapping, detection gaps, an IOC table, the YARA rule summary (with real test results, not projected ones), tiered recommendations, and collection priorities for what intelligence would most improve the next iteration of this analysis. Explicitly notes, per the module's Scope Note, where a normally-expected input (a formal indicator database from Task 4, a standalone adversary-profile document from Task 12) wasn't part of this batch and what was substituted instead.
How to use it: read `13-intelligence_brief.md`
Commands:

- Reusing Task 1's triage categories (ACTIONABLE/CONTEXTUAL/NOISE) directly in the IOC table rather than re-triaging indicators for the brief — one classification decision made once, carried through every downstream deliverable that needs it.
- "Collection priorities" as a distinct closing section — a brief that only summarizes what's already known is incomplete; naming what intelligence gap would most improve the *next* analysis is itself an actionable output for whoever runs the collection program.
- Documenting the Task 3/4/5/12 scope gap explicitly rather than presenting the brief as if every normally-expected input were available — the same "state the limitation, don't paper over it" discipline this module's YARA rules and kill-chain reconstruction already apply, carried through to the final leadership-facing document.

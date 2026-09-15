# Review: Classification Under Ambiguity

## The scenario
Three alerts on `clin-ws-07` within a 90-second window: `003_interpreter_abuse`
(powershell.exe spawned by **outlook.exe**), `007_unknown_outbound_destination`
(destination reputation `unknown`), `013_privileged_shift_violation`
(privileged logon at 02:17). Asset: `criticality: HIGH`,
`data_classification: PHI`. None of the three alone crosses the escalation
bar on a strict, per-alert read of `triage_methodology.md`.

## It already escalates - the "strict read" is the bug, not the methodology
The Escalation Criteria section has four bullets, and I read the first three
the same narrow way the question does and get the same "no":

- `classification == true_positive` AND `asset.criticality == CRITICAL` -
  fails; this asset is HIGH, not CRITICAL.
- `ioc_hit.reputation == malicious` - fails; the one IOC hit present is
  `unknown`, not `malicious`.
- rule maps to `{TA0006, TA0008, TA0010}` - fails for all three individually:
  003 maps to TA0002 (execution), 007 to TA0011 (C2), 013 to TA0004/TA0001
  (privilege/initial access). None land in the credential/lateral/exfil set.

But the fourth bullet is **"two or more alerts correlate to the same host or
user inside the rule's timeframe"** - and three alerts on one host in 90
seconds satisfies that on its own, no severity judgment required. I wrote
that bullet specifically so correlation could escalate a group that no
single member escalates alone; this scenario is exactly the case it exists
for, not a gap in it. The Priority Ordering Rule's override
("any alert on a CRITICAL asset or PHI/PCI data_classification jumps to the
front") also independently fires here on `data_classification: PHI`, before
correlation is even considered.

## Tracing it through the actual scripts confirms this, not just the doc
- **003 alone (T3/T7):** `outlook.exe` is not in `003_interpreter_abuse.yml`'s
  `filter_standard_parent` list (explorer.exe/cmd.exe/services.exe/
  svchost.exe/wininit.exe/taskeng.exe) - that's *why* the rule fired at all;
  the "abnormal parent" signal is already baked into the match, before my
  scripts see it. With no ioc_hit on this alert, `7-triage_ambiguous_proc_net.sh`
  falls through to `clean_ioc_no_deviation` only if
  `baseline_host_profile.process.expected` already contains this exact
  `process_name` for this host - which it does not in the real dataset (I
  checked this directly against `clin-ws-07`'s baseline while building T4). So
  it lands on the catch-all branch: `true_positive`, `monitor`.
- **007 alone:** `unknown` reputation matches neither the `malicious` nor the
  `suspicious` nor the `reputation in (None, clean)` branch in T7's decision
  tree, so it also falls to the catch-all: `true_positive`, `monitor`.
- **013 alone:** off-hours privileged logon is exactly the auth-ambiguous
  shape T6 exists for; depending on whether the account has used this host
  before it lands as `escalate_tier2` (branch 1) or `monitor` (branch 4) -
  either way `true_positive`, never auto-closed.
- **8-triage_correlation.sh:** all three share `clin-ws-07` and fall inside a
  600-second window (90s ≪ 600s), so they merge into one `high_confidence`
  incident (3 alerts). Since at least one contributing alert is already
  `true_positive`, the incident inherits `true_positive`. Since it's
  `high_confidence` on a HIGH-criticality asset, `recommended_action` is
  `escalate_tier2` by the rule literally spelled out in T8's instructions.

So nothing in the pipeline silently closes this as noise: each alert
individually lands as `true_positive`/`monitor` at worst, and correlation
upgrades the group to escalate. The scenario resolves correctly end to end.

## Why it's a credible pattern, not just a rule-matching coincidence
The sequence maps onto a kill chain, not three unrelated hits: Outlook
spawning PowerShell is the textbook signature of a phishing attachment or
malicious macro executing a payload (T1566 → T1059.001); a privileged logon
at 02:17 right next to it is off-hours use of elevated access, consistent
with an attacker riding a just-compromised session rather than a legitimate
on-call action; an outbound connection to an unscored destination
immediately after is consistent with second-stage staging or a C2 callback
that just hasn't been scored yet - `unknown` in `ioc_context.json` means
*not yet characterized*, not *cleared*. This is also not a novel pattern I'm
inventing after the fact: `003_interpreter_abuse.yml`'s own rule description
already names this exact chain - "the RR-02 risk register scenario
(off-hours PHI access on clin-ws-07) chains directly into this rule when the
off-hours session spawns PowerShell against the EHR server" - written before
any of these three specific alerts existed. `triage_methodology.md`'s own
`escalated` example uses the identical phrase for the identical reason.

## Where my own logic is honestly weaker than the reasoning above
`baseline_violation()` for the `process` category (used in T3 and T7) only
checks whether the raw `process_name` has been seen before on the host - it
does not look at the parent-child pair. In this dataset PowerShell happens
not to be in `clin-ws-07`'s baseline, so the check still works, but that's
this dataset's luck, not the check's design: on a host where PowerShell
*is* a common baseline process, the same automated check would call it "no
deviation" even with `outlook.exe` as parent, because the rule match already
absorbed the actually-informative signal (the abnormal parent) before my
baseline check runs on a field that doesn't see it. The correlation bullet
in the Escalation Criteria is what keeps that particular blind spot from
mattering here - a second, unrelated alert on the same host in the same
90 seconds forces escalation regardless of what any single alert's baseline
check concludes. That's the actual argument for correlating before finalizing
a classification, not after: a per-alert check can be quietly wrong about
one signal it wasn't built to see, but three independent detections
agreeing on the same host in the same 90 seconds are much harder to all be
wrong for the same reason.

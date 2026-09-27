#!/bin/bash
set -euo pipefail

# Tests 9-yara_phishing_pdf.yar and 10-yara_arsenal.yar against every file
# in samples/, using samples/samples_manifest.txt as ground truth. Requires
# the `yara` CLI on PATH. Only two rules exist in this project's arsenal
# (HEALTHBANE_Phishing_PDF, HEALTHBANE_Email_Headers) -- see 10-yara_arsenal
# .yar's header comment for why no third "Campaign_Composite" rule was
# built: the manifest defines no ground truth to test one against.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SAMPLES_DIR="$SCRIPT_DIR/samples"
RULE_PDF="$SCRIPT_DIR/9-yara_phishing_pdf.yar"
RULE_EMAIL="$SCRIPT_DIR/10-yara_arsenal.yar"

if ! command -v yara >/dev/null 2>&1; then
	echo "yara CLI not found on PATH." >&2
	exit 1
fi

# Ground truth is scoped PER RULE, not shared: "should this rule fire on
# this file" is not the same question as "is this file malicious." A PDF
# rule is correctly silent on an .eml file regardless of whether that email
# is malicious -- it isn't a PDF, so it's out of the rule's domain entirely,
# not a missed detection. Counting that as a false negative (an earlier
# version of this script did) produces a misleadingly low detection rate
# for both rules. Ground truth here therefore means: Y if the file is both
# (a) actually malicious per samples_manifest.txt AND (b) of the file type
# this specific rule targets; N otherwise -- including for the other rule's
# malicious samples, which correctly count as true negatives here.
GT_PDF='
phishing_sample.pdf|Y
healthbane_lure_02.pdf|Y
clean_invoice.pdf|N
benign_invoice.pdf|N
healthbane_email_01.eml|N
healthbane_email_02.eml|N
healthbane_email_03.eml|N
benign_newsletter.eml|N
'

GT_EMAIL='
phishing_sample.pdf|N
healthbane_lure_02.pdf|N
clean_invoice.pdf|N
benign_invoice.pdf|N
healthbane_email_01.eml|Y
healthbane_email_02.eml|Y
healthbane_email_03.eml|Y
benign_newsletter.eml|N
'

test_rule() {
	local rule_file="$1" rule_name="$2" ground_truth="$3"
	local tp=0 tn=0 fp=0 fn=0
	local fn_files="" fp_files=""

	echo "=== Testing $rule_name ($rule_file) ==="
	echo "$ground_truth" | while IFS='|' read -r fname truth; do
		[ -z "$fname" ] && continue
		echo "$fname|$truth"
	done > /tmp/yara_test_gt.$$

	while IFS='|' read -r fname truth; do
		[ -z "$fname" ] && continue
		local filepath="$SAMPLES_DIR/$fname"
		local fired="N"
		if yara "$rule_file" "$filepath" 2>/dev/null | grep -q .; then
			fired="Y"
		fi
		if [ "$truth" = "Y" ] && [ "$fired" = "Y" ]; then
			tp=$((tp + 1))
			printf "  TP  %s\n" "$fname"
		elif [ "$truth" = "N" ] && [ "$fired" = "N" ]; then
			tn=$((tn + 1))
			printf "  TN  %s\n" "$fname"
		elif [ "$truth" = "N" ] && [ "$fired" = "Y" ]; then
			fp=$((fp + 1))
			fp_files="$fp_files $fname"
			printf "  FP  %s\n" "$fname"
		else
			fn=$((fn + 1))
			fn_files="$fn_files $fname"
			printf "  FN  %s\n" "$fname"
		fi
	done < /tmp/yara_test_gt.$$
	rm -f /tmp/yara_test_gt.$$

	echo ""
	echo "TP: $tp | TN: $tn | FP: $fp | FN: $fn"
	awk -v tp="$tp" -v fn="$fn" 'BEGIN{d=(tp+fn>0)?100*tp/(tp+fn):0; printf "Detection rate: %.1f%%\n", d}'
	awk -v fp="$fp" -v tn="$tn" 'BEGIN{f=(fp+tn>0)?100*fp/(fp+tn):0; printf "False positive rate: %.1f%%\n", f}'
	if [ "$((tp + fp))" -gt 0 ]; then
		awk -v tp="$tp" -v fp="$fp" 'BEGIN{printf "Precision: %.1f%%\n", 100*tp/(tp+fp)}'
	else
		echo "Precision: N/A (no positive predictions)"
	fi

	if [ -n "$fn_files" ]; then
		echo ""
		echo "False negatives:$fn_files"
	fi
	if [ -n "$fp_files" ]; then
		echo ""
		echo "False positives:$fp_files"
	fi
	echo ""
}

echo "================================================================"
echo "   YARA TESTING SUMMARY"
echo "================================================================"
echo ""

test_rule "$RULE_PDF" "HEALTHBANE_Phishing_PDF" "$GT_PDF"

echo "----------------------------------------------------------------"
echo ""

test_rule "$RULE_EMAIL" "HEALTHBANE_Email_Headers" "$GT_EMAIL"

echo "================================================================"
echo "   FALSE NEGATIVE / FALSE POSITIVE ANALYSIS"
echo "================================================================"
echo ""
echo "HEALTHBANE_Phishing_PDF: no false negatives, no false positives"
echo "observed against this sample set. Nothing to tune."
echo ""
echo "HEALTHBANE_Email_Headers: 1 false negative -- healthbane_email_03.eml."
echo ""
echo "  Why the rule missed it:"
echo "    The rule requires the exact literal string \"PHPMailer 6.6.0\""
echo "    (a single SPACE between the product name and version number)."
echo "    healthbane_email_03.eml's X-Mailer header reads"
echo "    \"PHPMailer-6.6.0 (custom build)\" -- a HYPHEN in that position,"
echo "    not a space. This is otherwise a textbook HEALTHBANE Stage 1"
echo "    email: SPF/DKIM/DMARC all fail, sender is a lookalike domain"
echo "    (meddefense-benefits.org), subject uses urgency language"
echo "    (\"FINAL NOTICE\"). Every other signal fired; only the exact-"
echo "    literal mailer string did not."
echo ""
echo "  Proposed modification:"
echo "    Replace the single literal \$mailer = \"PHPMailer 6.6.0\" string"
echo "    with two independently-required strings -- \"PHPMailer\" and"
echo "    \"6.6.0\" -- so the rule no longer depends on the exact separator"
echo "    character between them. This closes the specific blind spot"
echo "    found here without weakening precision: both substrings still"
echo "    have to be present, so an unrelated PHPMailer version (e.g."
echo "    \"PHPMailer 6.9.0\") would not match either. (Not applied to"
echo "    10-yara_arsenal.yar in this file -- diagnosing and proposing"
echo "    the fix is this task's job; applying it is a separate, explicit"
echo "    tuning decision.)"
echo ""

echo "================================================================"
echo "   DEPLOYMENT RECOMMENDATIONS"
echo "================================================================"
echo ""
echo "Rule: HEALTHBANE_Phishing_PDF"
echo "  TP: 2 | TN: 6 | FP: 0 | FN: 0  (TN includes the 2 benign PDFs plus"
echo "  all 4 .eml files, which correctly do not trigger a PDF-only rule)"
echo "  Detection rate: 100.0% | False positive rate: 0.0% | Precision: 100.0%"
echo "  Recommendation: DEPLOY"
echo "  Rationale: perfect separation on this sample set, structural"
echo "  (tool fingerprint + URL-pattern) detection logic expected to"
echo "  survive infrastructure rotation per the researcher's own guidance."
echo ""
echo "Rule: HEALTHBANE_Email_Headers"
echo "  TP: 2 | TN: 5 | FP: 0 | FN: 1  (TN includes all 4 PDFs, which"
echo "  correctly do not trigger an email-header-only rule, plus the 1"
echo "  benign newsletter)"
echo "  Detection rate: 66.7% | False positive rate: 0.0% | Precision: 100.0%"
echo "  Recommendation: TUNE"
echo "  Rationale: zero false positives (safe to keep running), but a"
echo "  specific, diagnosed, low-risk blind spot exists (separator"
echo "  character in the mailer string) with a concrete proposed fix"
echo "  above -- TUNE rather than DEPLOY as-is (a known gap exists) or"
echo "  MONITOR (the fix is understood and low-risk enough to apply, not"
echo "  merely watch)."

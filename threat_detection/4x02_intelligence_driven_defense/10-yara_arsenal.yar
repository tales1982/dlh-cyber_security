/*
 * Task 10 was not included in the pasted task batch for this module; this
 * file was reconstructed from context (samples_manifest.txt's stated
 * match expectations for a rule named HEALTHBANE_Email_Headers, the
 * pattern established by 9-yara_phishing_pdf.yar, and the email header
 * fields documented in meddefense_4x00_findings.txt Finding F1) rather
 * than a verbatim task prompt. If the real Task 10 instructions differ,
 * this file should be revised to match them.
 *
 * Detection basis: 4x00 Finding F1 states that E2/E5/E7 "share a
 * PHPMailer 6.6.0 X-Mailer header, Namecheap-registered lookalike
 * domains, SPF failure (hard fail or softfail), DKIM absent, DMARC fail."
 * Direct inspection of this project's own .eml sample corpus confirms
 * that pattern for healthbane_email_01/02.eml.
 *
 * Only ONE rule (HEALTHBANE_Email_Headers) is defined here. The
 * authoritative test data for this module (samples/samples_manifest.txt)
 * only specifies match expectations for HEALTHBANE_Phishing_PDF (Task 9)
 * and HEALTHBANE_Email_Headers (this file) -- it does not define expected
 * results for a third "Campaign_Composite" rule, so none is invented here;
 * Task 11's own illustrative expected-output example names a composite
 * rule, but no test data exists to validate one against, consistent with
 * this project's evidence-based standard of not fabricating what the
 * manifest does not support.
 */

rule HEALTHBANE_Email_Headers
{
    meta:
        author       = "MedDefense SOC (4x02 intelligence-driven defense)"
        description  = "Detects HEALTHBANE Stage 1 phishing emails by X-Mailer fingerprint, authentication failure, and urgency-language subject pattern"
        date         = "2026-04-27"
        reference    = "meddefense_4x00_findings.txt Finding F1; HC3-2026-HEALTHBANE-001 Section 2.1"
        threat_level = "high"
        confidence   = "high"

    strings:
        // The kit's hardcoded X-Mailer fingerprint, per 4x00 F1 and
        // researcher_blog_analysis.txt Section 4 ("PHPMailer 6.6.0 for
        // outbound SMTP (hardcoded X-Mailer header)"). Matched as an
        // exact literal, including the single space between "PHPMailer"
        // and the version number.
        $mailer = "PHPMailer 6.6.0" ascii

        // Authentication-Results failure signals (SPF hard fail or
        // softfail, DKIM absent, DMARC fail), per 4x00 F1.
        $spf_fail  = "spf=fail" ascii
        $spf_soft  = "spf=softfail" ascii
        $dkim_none = "dkim=none" ascii
        $dmarc_1   = "dmarc=fail" ascii
        $dmarc_2   = "dmarcfail" ascii

        // Urgency-language subject-line pattern shared across the
        // Stage 1 lures in this corpus (E1/E2: "URGENT"; E3: "FINAL
        // NOTICE") -- a social-engineering pressure tactic, not itself
        // proof of maliciousness, so it is used only as a secondary
        // signal alongside the mailer fingerprint and auth failure.
        $urgent_1 = "URGENT" ascii
        $urgent_2 = "FINAL NOTICE" ascii

    condition:
        // The mailer fingerprint is REQUIRED (not "N of"): this is a
        // deliberately narrow, high-precision rule scoped to this
        // specific kit's hardcoded sender signature, plus at least one
        // authentication-failure signal and one urgency-language cue.
        $mailer and
        1 of ($spf_fail, $spf_soft, $dkim_none, $dmarc_1, $dmarc_2) and
        1 of ($urgent_1, $urgent_2)
}

/*
 * Test results (yara 10-yara_arsenal.yar samples/), verified 2026-04-27:
 *
 *   HEALTHBANE_Email_Headers samples/healthbane_email_01.eml  -- MATCH (expected: true positive)
 *   HEALTHBANE_Email_Headers samples/healthbane_email_02.eml  -- MATCH (expected: true positive)
 *   samples/healthbane_email_03.eml                            -- no match (expected: FALSE NEGATIVE, see manifest)
 *   samples/benign_newsletter.eml                               -- no match (expected: true negative)
 *
 * The false negative on healthbane_email_03.eml is real, not simulated:
 * that email's X-Mailer header reads "PHPMailer-6.6.0 (custom build)" --
 * a HYPHEN between "PHPMailer" and the version number, where E1/E2 (and
 * the $mailer string literal above) use a SPACE. The exact-literal-string
 * match on $mailer therefore fails for this one email even though every
 * other signal (auth failure, urgency subject, lookalike sender domain)
 * is present. Root-cause analysis and a proposed fix are documented in
 * 11-yara_testing.sh's per-rule false-negative section, not "fixed"
 * silently here -- diagnosing this is explicitly Task 11's job.
 */

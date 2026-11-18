# 6x02 IAM Audit Summary for Awareness Design

## Executive Summary

The IAM audit showed that MedDefense identity risk is not limited to access-control configuration. Several failures depend on human workflow: managers failing to report role changes, IT staff accepting vendor privilege requests, and support teams leaving migration accounts active.

## Awareness-Relevant Findings

### Service Account Hygiene

Service accounts were granted broad privileges for projects and vendor installations, then left in place. IT awareness should include a practical rule: if a service account has no owner, no documented function, or no recent expected activity, it should be reviewed.

### Contractor and Transfer Process

At least one contractor account remained enabled after contract end. One transferred employee retained IT-level privileges after moving to Finance. Manager guidance should emphasize role-change reporting.

### MFA and Admin Discipline

Privileged access without strong verification remains a risk. IT and executives should receive targeted guidance on not approving admin actions through email alone.

### Board Message

Identity failures directly contributed to the prior incident path. Security awareness must teach employees to recognize when an access request, support call or workflow action does not fit the person's role.

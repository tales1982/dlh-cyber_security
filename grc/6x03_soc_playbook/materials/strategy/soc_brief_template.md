# SOC Automation Brief Template

## Executive Summary

State what was built and what operational problem it solves.

## Current Manual Burden

Use: 150 alerts/day, 8 minutes/alert, 67 percent enrichment work, 45-minute incident enrichment delay.

## What Was Automated

- IOC enrichment
- case creation
- phishing triage
- credential exposure triage
- isolation recommendation queue
- audit logging

## What Was Not Automated

- no automatic endpoint isolation
- no automatic account disablement
- no automatic mailbox quarantine
- no production blocking action

## Integration Test Result

Summarize the five test scenarios and whether expected outcomes matched actual outcomes.

## Roadmap

Phase 1: stabilize enrich-and-triage playbooks.  
Phase 2: add metrics, deduplication and analyst feedback.  
Phase 3: consider limited action automation only after false-positive thresholds are met.

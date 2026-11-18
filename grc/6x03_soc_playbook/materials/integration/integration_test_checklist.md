# Integration Test Checklist

## Pre-Test Reset

```bash
rm -f cases.db playbook_audit.log isolation_queue.json
mkdir -p alerts
cp /opt/meddefense/materials/alerts/phishing/*.json alerts/
cp /opt/meddefense/materials/alerts/credential/*.json alerts/
cp /opt/meddefense/materials/threat_intel/ioc_feed.json ./ioc_feed.json
cp /opt/meddefense/materials/iam/privileged_accounts.json ./privileged_accounts.json
```

## Commands

```bash
python3 playbook_phishing_triage.py alerts/ALT-20260428-001.json
python3 playbook_phishing_triage.py alerts/ALT-20260428-002.json
python3 playbook_phishing_triage.py alerts/ALT-20260428-003.json
python3 playbook_credential_exposure.py alerts/ALT-20260428-007.json
python3 playbook_credential_exposure.py alerts/ALT-20260428-009.json
python3 case_manager.py list
```

Document command, expected outcome, actual stdout, case ID, severity, status, queue result, and PASS/FAIL.

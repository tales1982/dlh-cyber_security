# CloudVault Medical Subprocessor List

## Disclosed Subprocessors

| Subprocessor | Location | Role | Data Exposure |
|---|---|---|---|
| FastRoute Health CDN | United States | Content delivery and transfer acceleration | May handle encrypted backup transfer metadata |
| MetricLake Analytics GmbH | European Union | Service performance analytics | May process operational metadata and tenant identifiers |

## Open Questions

1. Does MetricLake receive patient identifiers or only service telemetry?
2. Is metadata considered ePHI when linked to backup archive identifiers?
3. Are subprocessors contractually bound to HIPAA-equivalent safeguards?
4. Does either subprocessor have administrative access to CloudVault production systems?
5. Are subprocessors included in breach notification obligations?

## Risk Note

The EU analytics processor creates a jurisdiction and data-flow review requirement. This is not automatically disqualifying, but it must be documented and approved before ePHI access.

# Cross-Platform Trade-off Table

| Scenario | CLI (s) | Export (s) | Delta (s) | Faster | Cause |
|---|---|---|---|---|---|
| anchor | 21 | 1 | 20 | wazuh_export | native_field_surface |
| scenario_a | 23 | 1 | 22 | wazuh_export | native_field_surface |
| scenario_b | 21 | 1 | 20 | wazuh_export | context_join_ergonomics |
| scenario_c | 5 | 0 | 5 | wazuh_export | native_field_surface |

# Credential Exposure Decision Logic

Extract `source_ip`, `username`, `host`, and `mitre_technique`.

| Source IP Verdict | Username is Domain Admin | Username is Server Admin | Case Severity | Case Status | Isolation Queue |
|---|---|---|---|---|---|
| BLOCK | any | any | Critical | escalated | yes |
| INVESTIGATE | true | any | Critical | escalated | yes |
| INVESTIGATE | false | true | High | open | no |
| INVESTIGATE | false | false | High | open | no |
| ALLOW | true | any | High | escalated | no |
| ALLOW | false | true | Medium | open | no |
| ALLOW | false | false | Medium | open | no |

`isolation_queue.json` is a human authorization queue only. The playbook must not isolate the host.

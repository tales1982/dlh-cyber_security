# Incident Identity Path

The Cobalt Strike incident escalated because identity controls allowed a compromised endpoint to become a privileged domain compromise.

Path: workstation compromise → credential extraction → service account credential discovered → Domain Admin membership → lateral movement and administrative actions.

Current-state findings that resemble the path: `svc_epic_int`, `svc_helpdesk`, `svc_backup`, `t.morrison`, `admin.legacy`, `j.yamamoto`. These are not theoretical; a similar standing privileged credential already enabled the prior compromise.

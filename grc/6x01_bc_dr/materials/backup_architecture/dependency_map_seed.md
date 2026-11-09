# Dependency Map Seed

```text
Network Core
├── Active Directory
│   ├── Epic EHR
│   │   ├── LIS interface
│   │   ├── Pharmacy Dispensing System
│   │   └── PACS/RIS ordering and results
│   ├── Email and Secure Messaging
│   ├── Security Operations Platform
│   └── Backup and DR Infrastructure access control
├── Medical Device Integration Gateway
├── PACS/RIS image movement
└── Backup replication traffic
```

## Recovery Implication

A clinical application can have a valid backup and still fail recovery if its dependencies are not restored first.

Suggested sequence:

1. Network Core
2. Active Directory
3. Backup and DR Infrastructure access
4. Highest patient-safety clinical systems
5. Communication channels
6. Monitoring and security visibility
7. Business support systems

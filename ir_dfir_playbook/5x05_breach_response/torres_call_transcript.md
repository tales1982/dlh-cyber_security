# Torres Call Transcript — 2026-04-20T19:43:18Z

**Caller:** Mike Torres, MedDefense Network Engineer
**Recipient:** On-call IR (student)
**Duration:** 4 min 22 sec
**Transcript source:** Signal call auto-transcription, reviewed and signed off by Torres at 2026-04-20T21:10Z during timeline preparation
**Classification:** Incident evidence — LH referenced under IR-2026-0420-01

---

**19:43:18 — Torres:**
I need you on a call right now. Something is wrong at Site A.

**19:43:22 — Torres:**
The on-call nurse at Main just paged me directly because she could not reach the SOC line. She says her workstation is crawling. She said — and I am quoting — "the files on my desktop look different." She thinks some of the filenames have changed. I have not logged in to verify.

**19:43:47 — Student:**
What host?

**19:43:50 — Torres:**
`CS-WS-101`. It is the clinical coordinator station at the ED charge desk. Before she called me I was already looking at something weird. The scheduling server at Main — `SCHED-SVR-01` — is hammering its disk. CPU is pinned. Disk queue is through the roof. I thought it was a stuck batch job but it has been doing this for about ninety minutes.

**19:44:20 — Torres:**
Then I pulled the SIEM. There is a service installation alert. Rule ID `wz-edr-200214`. It fired on three hosts I have never seen beacon before. `CS-WS-104`, `CS-WS-107`, `CS-WS-112`. All of them are clinical workstations at Main. All of them within the same twelve-minute window this afternoon.

**19:44:48 — Torres:**
The installed service name is `WinHealthSvc`. The image path is `C:\ProgramData\Microsoft\svchost32.exe`. That is not a Microsoft path. That is not a Microsoft name. I know that much.

**19:45:12 — Torres:**
I took one memory snapshot. Just on `CS-WS-101` because that is the one the nurse is on. I ran WinPmem at 19:38Z before I called you. I did not isolate the host. I did not touch the others. I did not touch the file server. I did not call James because I figured you would want to own the activation.

**19:46:04 — Torres:**
I do not know what I am looking at. I know it is bad. I do not know how bad. What do you want me to do.

**19:47:40 — Student:**
[student response begins the IR activation]

---

## Notes appended during handoff (19:52Z)

- Memory dump `cs-ws-101.mem` written to `\\evidence\share\IR-2026-0420-01\cs-ws-101.mem` at 19:41Z
- No hash computed at acquisition (repeat of the IR-2026-0414-01 issue — Torres flagged it himself)
- Torres remained on the bridge for the duration of the activation and continued as evidence acquirer for additional host memory captures
- The on-call nurse (name withheld pending HR acknowledgment) was instructed to stop touching `CS-WS-101` and leave the console unattended

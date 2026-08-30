# 3x00 Evidence Pipeline

MedDefense Health Systems — Module 3 capstone bridge project. Builds the evidence
pipeline (intake, parse, normalize, clean, enrich, index, validate) that turns
the raw exports dropped during the 48-hour SIEM migration window into
analyst-ready, structured evidence for every downstream Module 3 project.

## Lab Access

The lab runs on a per-student sandbox (region: US East - N. Virginia). Connect
as `student`, not `root` — the SSH configuration box shown in the sandbox
panel displays a `root@...` example, but that account rejects public key
authentication on this image. Only `student` accepts it.

Steps:

1. Generate a local SSH keypair if you don't already have one:
   ```
   ssh-keygen -t ed25519 -C "your.email@cyber.dlh.lu" -f ~/.ssh/dlh_cybersecurity
   ```
2. In the sandbox platform, open **My SSH Keys** and add the contents of
   `~/.ssh/dlh_cybersecurity.pub`. If the key doesn't show up in the list
   right after saving, reload the page — the UI sometimes doesn't refresh on
   its own.
3. Create a new sandbox from the **MedDefense-Soc** image (region US East).
   Wait for it to reach the `RUNNING` state.
4. Open the sandbox's **SSH** tab to get the current port (it changes every
   time a sandbox is created).
5. Connect:
   ```
   ssh -p <port> -i ~/.ssh/dlh_cybersecurity -o IdentitiesOnly=yes student@ssh.cod-us-east-1.hbtn.io
   ```
6. Verify the environment:
   ```
   whoami
   pwd
   m3-doctor
   source ~/m3_env.sh
   ```

A VPN connection is not required for SSH access — the sandbox is reachable
directly over the public gateway above. If you do use the platform's VPN
(e.g. to reach the sandbox's private IP directly), make sure the VPN
configuration you download matches the same region as your sandbox (US East).
A VPN profile from a different region (e.g. Europe - Paris) will connect
successfully but silently fail to route traffic to the sandbox, since it
lands in the wrong regional network.

### Evidence pack layout

```
evidence_pack_primary/
  windows/
  linux/
  network/
  context/
  student_telemetry/
```

Environment variable available after `source ~/m3_env.sh`:

```
HANDOFF_DIR=/home/student/3x00_handoff/evidence_handoff
```

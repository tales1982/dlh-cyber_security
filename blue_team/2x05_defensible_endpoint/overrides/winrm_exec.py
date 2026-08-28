#!/usr/bin/env python3
"""
winrm_exec.py - dispatches a single PowerShell command to a remote Windows
host over WinRM and mirrors its exit behavior locally, so 8-validate_all.sh
can treat a Windows check_type: command_exit_zero control exactly like a
local one.

Credentials are read from environment variables only (never hardcoded, never
committed): WINRM_HOST, WINRM_USER, WINRM_PASS. Requires pywinrm
(python3-winrm) and, on hosts where hashlib blocks md4, OPENSSL_CONF pointed
at a config with the legacy provider enabled (NTLM depends on MD4).

Usage: winrm_exec.py "<powershell command>"
Exit codes: mirrors the remote command's exit code (0 = pass). Exits 2 on a
connection/auth/environment failure, distinct from a genuine remote failure,
so the caller can tell "the control failed" apart from "I couldn't even ask".
"""
import hashlib
import os
import sys

# Self-contained legacy-provider workaround: NTLM (used for WinRM auth here)
# depends on MD4, which OpenSSL 3.x disables by default. Rather than rely on
# a user-specific $HOME/.config file - which silently points at the wrong
# place under sudo, since $HOME becomes /root - write and point at a config
# file next to this script, so the fix travels with the deployment instead
# of depending on which user/HOME is invoking it.
try:
    hashlib.new("md4", b"")
except ValueError:
    # OpenSSL reads its config at library init, so setting OPENSSL_CONF this
    # late in an already-running process would not retroactively reconfigure
    # it - re-exec the same interpreter/argv with the variable set in the
    # new process's environment from the start. The re-exec guard prevents
    # a loop if the legacy provider still doesn't fix it for some reason.
    if os.environ.get("_WINRM_EXEC_REEXECED") != "1":
        _script_dir = os.path.dirname(os.path.abspath(__file__))
        _legacy_cnf = os.path.join(_script_dir, "openssl_legacy.cnf")
        if not os.path.exists(_legacy_cnf):
            with open(_legacy_cnf, "w") as f:
                f.write(
                    "openssl_conf = openssl_init\n\n"
                    "[openssl_init]\n"
                    "providers = provider_sect\n\n"
                    "[provider_sect]\n"
                    "default = default_sect\n"
                    "legacy = legacy_sect\n\n"
                    "[default_sect]\n"
                    "activate = 1\n\n"
                    "[legacy_sect]\n"
                    "activate = 1\n"
                )
        new_env = os.environ.copy()
        new_env["OPENSSL_CONF"] = _legacy_cnf
        new_env["_WINRM_EXEC_REEXECED"] = "1"
        os.execve(sys.executable, [sys.executable] + sys.argv, new_env)
    else:
        print("Error: MD4 still unavailable even after re-exec with the legacy OpenSSL provider config.", file=sys.stderr)
        sys.exit(2)

try:
    import winrm
except ImportError:
    print("Error: pywinrm not installed (pip3 install pywinrm or apt install python3-winrm).", file=sys.stderr)
    sys.exit(2)

if len(sys.argv) < 2:
    print("Usage: winrm_exec.py \"<powershell command>\"", file=sys.stderr)
    sys.exit(2)

# $ProgressPreference = 'SilentlyContinue' is prepended to every command:
# several cmdlets (Get-NetFirewallProfile among them) emit progress-stream
# records that a known pywinrm bug fails to deserialize ("startswith first
# arg must be bytes or a tuple of bytes, not str"), even though the command
# itself succeeds. Suppressing progress output avoids the buggy code path
# entirely rather than working around it after the fact.
command = "$ProgressPreference = 'SilentlyContinue'; " + sys.argv[1]

host = os.environ.get("WINRM_HOST")
user = os.environ.get("WINRM_USER")
password = os.environ.get("WINRM_PASS")

if not (host and user and password):
    print("Error: WINRM_HOST, WINRM_USER and WINRM_PASS must all be set in the environment.", file=sys.stderr)
    sys.exit(2)

try:
    session = winrm.Session(host, auth=(user, password), transport="ntlm")
    result = session.run_ps(command)
except Exception as exc:
    print(f"Error: WinRM connection/execution failed: {exc}", file=sys.stderr)
    sys.exit(2)

sys.stdout.write(result.std_out.decode(errors="replace"))
sys.exit(result.status_code)

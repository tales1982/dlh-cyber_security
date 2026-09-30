# 3x00 – Evidence Pipeline

## Task - 0-source_inventory.sh

What it does: Walks the evidence pack's `windows/`, `linux/` and `network/` directories, computes size/hash/record-count and a best-effort timestamp range (one recipe per source format) for every file, and writes it all to `source_inventory.json`, along with a per-category summary printed to stdout.
How to use it: `./0-source_inventory.sh [pack_root]` (defaults to `$HOME/evidence_pack_primary`)
Commands:

- `command -v python3` — checks that Python is installed before trying to use it.
- `os.walk(directory)` — walks a directory tree recursively, used to discover each category's files without assuming a flat layout.
- `hashlib.sha256()` reading in 64KB chunks — hashes a file without loading the whole thing into memory at once.
- `json.loads` with an NDJSON fallback — first tries to parse the content as a single JSON array/object; on failure, falls back to processing it line by line, tolerating individually malformed lines.
- `re.match`/`re.search`, one pattern per timestamp format — five different recipes (already-ISO, bare epoch, US-format in CST, syslog with no year, auditd's embedded epoch), chosen by filename.
- `datetime.strptime`/`datetime.fromtimestamp` — do the actual conversion from each raw format into a date object, which then becomes the final ISO-8601 UTC string.

## Task - 2-windows_parse.sh

What it does: Merges `security.json`, `sysmon.json` and `powershell.json` into a single `windows_events.json` (NDJSON), checks that every record has the 8 minimum fields, preserves/sets `source_origin`, and appends the student telemetry (`student_telemetry/windows_events.json`), mapping equivalent fields where the name doesn't match.
How to use it: `./2-windows_parse.sh [pack_root]`
Commands:

- `command -v python3` — dependency check.
- `json.loads` line by line, inside `try`/`except` — reads each line of the source NDJSON, skipping (and warning on stderr about) any line that isn't valid JSON, instead of aborting the whole script.
- `dict.setdefault(field, None)` — guarantees the 8 minimum fields exist on every record, even when the source never had that piece of information.
- `rec.get(field)` as a fallback value — maps the student telemetry's fields (`timestamp`→`timestamp_raw`, `source_type`→`channel`) without overwriting a value that's already there.

## Task - 3-linux_parse.sh

What it does: Parses `auth.log`/`syslog` (classic syslog grammar) and `audit.log` (auditd's key=value grammar, grouping lines that share the same `audit(epoch:serial)` identifier) into structured records, appends the student telemetry, and writes everything to `linux_events.json`.
How to use it: `./3-linux_parse.sh [pack_root]`
Commands:

- `command -v python3` — dependency check.
- `re.compile(r'(\S+) ([^ \[:]+)(?:\[(\d+)\])?: ?(.*)$')` — recognizes hostname, program, an optional PID, and the rest of the message from a syslog line in one shot.
- A list of regexes tried in order (one per program family) — extracts the user mentioned in the message, covering the different ways `sudo`, `su`/`polkitd`/`login`/`CRON`, `systemd-logind`, and `sshd` each mention a user.
- `re.search(r'msg=audit\((\d+)\.(\d+):(\d+)\)')` — extracts the auditd event identifier (`epoch.ms:serial`), used as the grouping key.
- `re.findall(r'(\w+)=("[^"]*"|\'[^\']*\'|\S+)')` — extracts every key=value pair from an `audit.log` line, accepting a double-quoted, single-quoted, or bare value.
- Opening the file in binary mode (`"rb"`) with manual UTF-8→latin-1 decoding — reads each line trying UTF-8 first, and only falls back to latin-1 on the specific lines that actually fail, preserving the real character instead of losing it to a generic replacement character.

## Task - 5-normalize.sh

What it does: Reads `windows_events.json` and `linux_events.json`, applies category/severity/action lookup tables keyed by channel (Windows) and by program/audit type (Linux), converts every intermediate timestamp to ISO-8601 UTC, and writes the result to `normalized_events.json` — sending any record missing a required `event_schema.json` field to `quarantine.json`, with a reason.
How to use it: `./5-normalize.sh` (reads `event_schema.json` from the current directory)
Commands:

- `command -v python3` — dependency check.
- `json.load(schema_file)` plus a list comprehension over `fields` — reads `event_schema.json` and builds the required-field list dynamically instead of hard-coding it; changing `required` in the schema changes the quarantine behavior without editing this script.
- Dictionary-based lookup tables — decide `event_category`/`severity`/`action` from `event_id`/`channel` (Windows) or `program`/`audit_type` (Linux).
- `int(value)` guarded by `try`/`except` — converts a PID/port to a number only when the value is actually a digit, without crashing the script on missing fields.

## Task - 6-network_normalize.sh

What it does: Normalizes `firewall.csv`, `suricata_eve.json` and `pcap_summary.json` into the same unified schema (`event_category`, `severity`, `signature`, etc.), appends the result to `normalized_events.json`, and also writes a standalone `network_events.json`.
How to use it: `./6-network_normalize.sh [pack_root]`
Commands:

- `command -v python3` — dependency check.
- `csv.DictReader` — reads `firewall.csv` line by line already as a dictionary, using the first line's header to name each column.
- `datetime.fromtimestamp(epoch, tz=timezone.utc)` — converts the firewall's epoch column straight to UTC.
- `datetime.strptime(raw_ts, "%Y-%m-%dT%H:%M:%S.%f%z")` — parses Suricata's timestamp (ISO-8601 with microseconds and a numeric offset).
- `datetime.strptime(raw_ts, "%m/%d/%Y %I:%M:%S %p") + timedelta(hours=6)` — parses `pcap_summary.json`'s US-format 12h clock and adds 6 hours to convert from CST to UTC.
- Opening the output file in append mode (`"a"`) — folds the network events into the `normalized_events.json` Task 5 already wrote, without erasing what was already there.

## Task - 8-data_quality.sh

What it does: Reads `normalized_events.json` and repairs (or flags) the pack's known defects — malformed timestamps, duplicates, inconsistent hostname casing, encoding errors, and suspected-wrong-timezone timestamps — logging every correction to `cleaning_log.json` and writing the cleaned result to `cleaned_events.json`.
How to use it: `./8-data_quality.sh`
Commands:

- `command -v python3` — dependency check.
- A list of formats tried through `datetime.strptime` — tries strict ISO-8601 first, falls back to alternate formats before treating a timestamp as unrecoverable.
- A `dict` used as a "have I seen this combination" table (composite key of `timestamp`+`hostname`+`source_type`+`raw_message`) — the deduplication technique: the key is an event's "fingerprint," and the dict keeps lookup cheap even across hundreds of thousands of records.
- `sorted()` over the timestamps plus a percentile index (2nd/98th) — derives the "expected" date window from the data itself, instead of hard-coding dates, to flag anything more than 12 hours outside it.
- Checking for the Unicode replacement character (`�`) inside `raw_message` — detects whether a record already arrived with encoding information lost before this stage.

## Task - 9-enrich.sh

What it does: Cross-references every event in `cleaned_events.json` against `context/asset_inventory.json` (by hostname) and `context/network_zones.json` (by IP/CIDR), attaching an `asset` object and `src_zone`/`dst_zone` fields, and writes `enriched_events.json` — reporting the context coverage found.
How to use it: `./9-enrich.sh [pack_root]`
Commands:

- `command -v python3` — dependency check.
- `ipaddress.ip_network(cidr)` / `address in network` — Python's standard module for representing IP ranges and testing whether an address falls inside one, without hand-rolling CIDR arithmetic.
- A list of `(network, zone)` sorted by prefix length descending — ensures a more specific zone (`/24`) is checked before a generic one (`0.0.0.0/0`, which matches every IP), preventing everything from landing in the catch-all zone.
- A `dict` keyed by lowercased hostname — cross-references the asset inventory without caring about the exact casing of the hostname on the event.

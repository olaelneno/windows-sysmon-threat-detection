# Windows/Sysmon Threat Detection System — Week 2 MVP

CyberFox Society | Security Operations & Detection Engineering

## Scope
Offline prototype that reads **normalized JSON events**, detects repeated Windows failed logons (Security Event ID 4625), and flags selected PowerShell process arguments (Sysmon Event ID 1). No live Windows event collection, EVTX parsing, SIEM integration, or dashboard is implemented yet.

## Architecture
```text
Synthetic normalized Windows/Sysmon JSON
                |
                v
        Input validation / parser
                |
                v
        Rule-based detection engine
           /               \
  4625 failure threshold   Sysmon ID 1 PowerShell arguments
           \               /
                v
          JSON alert output
                |
                v
       Unit tests and manual review
```

## Tech stack
Python 3.9+ (standard library only), JSON, unittest. Intended future integration: authorized Windows/Sysmon event exports.

## Run
From the project root:
```bash
python src/detector.py --input data/sample_events.json --output output/alerts.json
python -m unittest discover -s tests -v
```

## Event schema (normalized)
Input is a JSON array. Each event needs `source`, `event_id`, `timestamp` (ISO-8601 with timezone), and detection-specific fields.

Security 4625: `host`, `ip_address`, `target_user_name`; optional `logon_type`. These map conceptually to `Computer`, `IpAddress`, `TargetUserName`, `LogonType` in Windows XML. Do not confuse `TargetUserName` with `SubjectUserName`.

Sysmon 1: `host`, `image`, `command_line`, `user`; these map to Sysmon process-creation fields.

**Important:** This prototype does NOT directly parse raw Windows Event XML, EVTX, or Event Viewer exports. A later adapter will be needed to convert real authorized events into this normalized schema.

## Rules
1. `REPEATED_FAILED_LOGINS`: 5+ failed logon events from same host, source IP, and targeted user in any 10-minute window. Local/blank source IPs are excluded. This is an experimental threshold, not a universal attack signature. Alert is rate-limited within a window.
2. `PS_SUSPICIOUS_ARGS`: Sysmon process creation of `powershell.exe`/`pwsh.exe` with `-EncodedCommand` or `-enc`, or both `-NoProfile` and `-WindowStyle Hidden`. These indicators are *suspicious*, not proof of malware.

## Week 2 demonstration
9 **synthetic** sample events -> 2 alerts (1 high repeated-login, 1 medium PowerShell). 8 automated tests pass. The sample has no ground-truth dataset suitable for estimating production precision or recall.

## Limitations and next steps
- Synthetic JSON input, not real Windows logs.
- Only two heuristic rules; no cross-host correlation, alert persistence, live monitoring, dashboard, or GUI.
- No production false-positive measurements; benign administrators may use encoded/hidden PowerShell.
- Current matching of `-enc` is intentionally simple; evasions and variations are not covered.
- Next: build raw XML export adapter, gather authorized lab samples, label benign/suspicious cases, measure precision/recall, tune rules, and optionally add a Streamlit dashboard.

## Ethics
Only use logs from devices you own or are explicitly authorized to monitor. Sample IP addresses use documentation-only `192.0.2.0/24` range. Do not upload real sensitive logs to public repositories.

## References
- Microsoft Event 4625: https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4625
- Microsoft Sysmon: https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon
- Sysmon events: https://learn.microsoft.com/en-us/windows/security/operating-system-security/sysmon/sysmon-events

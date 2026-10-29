# Week 3 — Further Development and Testing

## Objective
Address supervisor feedback: the Week 2 MVP only accepted synthetic JSON.

## Implemented
- Windows Event XML ingestion for Security Event 4625 and Sysmon Event 1.
- Handles namespaced single Event, Events container, and adjacent PowerShell `ToXml()` fragments.
- Normalizes XML fields into the existing detection pipeline.
- Preserves JSON compatibility and skips unsupported event IDs.
- Adds automated parser and detection tests.

## Test evidence and status
The bundled XML fixture is **synthetic, not collected from a Windows host**. Automated test results prove parser behavior against this fixture only. No real-lab validation or measured detection accuracy is claimed.

## Required authorized lab validation
1. On an authorized Windows lab system, enable appropriate Security auditing and install/configure Sysmon as required.
2. Generate benign and controlled test events (e.g. five failed logins from the same non-loopback source IP to one lab account; benign PowerShell command with encoded argument).
3. Export Security and Sysmon logs to XML using `docs/Windows_Lab_Export.ps1`.
4. Run `python src/detector.py --input data/lab_security.xml --output output/lab_security_alerts.json` and repeat for Sysmon.
5. Record event counts, alert IDs, observed false positives/negatives, command output, and screenshots.
6. Redact usernames, machine names, internal IPs, command-line secrets and other sensitive data before sharing.

## Limitations
- Parser only supports Windows Event XML; raw `.evtx` is not yet supported.
- Only Event ID 4625 and Sysmon Event ID 1 are used by the existing detector.
- Failed logon rule requires a non-loopback source IP and groups by host/IP/target user. Local logon failures may not trigger it.
- XML parser uses standard library, has a 25 MB file limit and expects normal exported Event XML.
- Detection rules are heuristic and need tuning with real, authorized lab logs.

## Next steps
Collect actual Windows/Sysmon exports, record reproducible lab results, adjust mappings and detection thresholds, and update evaluation with verified evidence.

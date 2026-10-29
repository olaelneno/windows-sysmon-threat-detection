# Week 4 — Real Windows/Sysmon Lab Validation

## Status
**NOT YET VERIFIED ON REAL LOGS.** Synthetic XML/JSON regression tests are not real-log evidence. Do not claim precision, recall, or successful lab detection until the procedure below is completed and recorded.

## Safe setup
Use only a Windows VM or machine you own/administer and are authorized to test. Enable Windows Security auditing as appropriate and install/configure Microsoft Sysmon if available. Use an elevated PowerShell terminal to export event ID 4625 and Sysmon ID 1 with `docs/Windows_Lab_Export.ps1`. Keep original logs private: they can include usernames, machine names, IPs and command lines. Do not upload raw logs to a public repository.

## Reproducible procedure
1. Record Windows version, Sysmon version/configuration, audit settings, UTC test start/end, machine alias, and exact commands run. Do not include credentials.
2. Create controlled negative cases (ordinary logons and ordinary PowerShell launches) and positive cases: intentionally enter an incorrect password five times on a lab account from the same non-loopback source within ten minutes; run `powershell.exe -NoProfile -WindowStyle Hidden -Command "Write-Output labtest"` in an authorized lab to generate a benign command line matching the heuristic. This is **not** a malicious payload; it tests whether a rule triggers.
3. Run `powershell -ExecutionPolicy Bypass -File docs/Windows_Lab_Export.ps1 -OutputDir lab_exports` in the lab. Verify the relevant events exist in Event Viewer and that the exported XML files are non-empty.
4. Run `python src/detector.py --input lab_exports/lab_security.xml --output output/lab_security_alerts.json` and similarly for `lab_sysmon.xml`.
5. Create **separate exports per scenario** and label each with expected rules in a private copy of `evaluation/lab_manifest_TEMPLATE.json`. Do not use mixed multi-scenario files for the scenario-level evaluation; otherwise one alert can be incorrectly attributed to another scenario.
6. Run `python evaluation/evaluate_lab.py --manifest evaluation/lab_manifest.json --output output/lab_evaluation.json`. The script compares **rule presence per scenario**, not per-event classification. Review all results manually against Event Viewer. Include timestamps and redacted screenshots.

## Evidence checklist
- [ ] Lab setup and permission documented
- [ ] Windows Event Viewer screenshot (4625)
- [ ] Sysmon Event Viewer screenshot (event 1)
- [ ] Sanitized XML event fields shown, without private identifiers
- [ ] CLI run and alerts screenshot for both sources
- [ ] Positive and negative cases with expected outcomes
- [ ] TP, FP, FN and precision/recall measured from labeled scenarios
- [ ] Known limitations and false-positive analysis recorded

## Limitations
The 4625 rule requires five failures sharing host, source IP and target username in ten minutes; local failures may omit a usable source IP. The PowerShell rule detects selected suspicious argument patterns and can alert on benign administrative activity. Sysmon Event ID 1 requires Sysmon installed and configured to capture process creation and command lines. The current parser supports exported XML for Security 4625 and Sysmon 1, not binary EVTX files, live subscriptions, or arbitrary event IDs. No real-log detection accuracy can be asserted before authorized lab evaluation.

## References
- Microsoft Sysmon: https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon
- Microsoft Get-WinEvent: https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.diagnostics/get-winevent

# Week 2 — Design & Initial Development
**CyberFox Society — Cybersecurity Research & Development Internship**

**Project Area:** Security Operations & Detection Engineering  
**Project Title:** Windows/Sysmon Threat Detection System  
**Submission date:** 15 October 2026

## 1. Objective
Design and implement an initial, testable proof-of-concept for identifying selected suspicious patterns in normalized Windows Security and Sysmon events. The focus is transparent rule logic and repeatable testing rather than claiming to replace a commercial SIEM.

## 2. System Design
**Architecture:** Normalized JSON Events → Validation & Parser → Detection Engine → Structured JSON Alerts → Test & Review.

**Inputs:** Windows Security Event ID 4625 (failed logon) and Sysmon Event ID 1 (process creation). **Outputs:** Alerts containing rule ID, timestamp, host, user, severity, reason, and evidence. **Technology:** Python standard library, JSON, unittest.

## 3. Initial Development
- Implemented schema validation for source, event ID, and timezone-aware timestamps.
- Implemented failed-login threshold rule: at least 5 events from the same host, source IP, and target user in a 10-minute window.
- Implemented PowerShell process argument rule for selected suspicious flags in Sysmon Event ID 1.
- Implemented JSON alert output and CLI parameters for threshold/window configuration.
- Created 9 synthetic sample events, automated tests, and documentation.

## 4. Testing & Results
**Environment:** Offline Python execution using synthetic, non-sensitive event records.  
**Automated tests:** 8 tests passed, covering positive and negative cases, grouping by source IP, time window, PowerShell indicators, and malformed input.  
**Sample run:** 9 events processed; 2 alerts generated (1 high-severity repeated failed login, 1 medium-severity suspicious PowerShell argument).

These are demonstration results on synthetic data, **not** evidence of accuracy on real enterprise logs. No production false-positive rate, precision, or recall has been established.

## 5. Challenges & Limitations
- Windows Security and Sysmon events use different fields and log channels; the MVP currently accepts normalized JSON rather than raw EVTX/XML.
- Suspicious PowerShell command-line flags can also appear in legitimate administration.
- Threshold selection is environment-dependent and requires tuning against labeled data.
- Live collection and dashboard are intentionally deferred to protect scope and prioritize a working detector.

## 6. Next Week's Plan
1. Implement an adapter for authorized Windows Event XML exports.
2. Generate and label more benign and suspicious lab examples.
3. Measure detection results using a labeled test set and tune the rules.
4. Add a basic dashboard only after detection and evaluation are stable.

## References
- Microsoft — Event 4625: https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4625
- Microsoft — Sysmon: https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon
- Microsoft — Sysmon Events: https://learn.microsoft.com/en-us/windows/security/operating-system-security/sysmon/sysmon-events

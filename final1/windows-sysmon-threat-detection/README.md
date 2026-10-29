# Windows / Sysmon Threat Detection — CyberFox Society Final MVP

Offline rule-based prototype for Windows Security **4625** and Sysmon **1** event exports. The MVP supports normalized JSON and Windows Event XML. **Real-log reliability is not yet verified**: the included samples and automated tests are synthetic.

## Quick start

```bash
python -m unittest discover -s tests -v
python src/detector.py --input data/sample_events.xml --output output/sample_alerts.json
python src/detector.py --input data/sample_events.json --output output/sample_json_alerts.json
```

## Real lab validation

Follow [`docs/Week4_Lab_Validation.md`](docs/Week4_Lab_Validation.md) and run `docs/Windows_Lab_Export.ps1` **only on an authorized Windows lab**. Use separate labeled scenario exports and `evaluation/evaluate_lab.py` to measure scenario-level TP/FP/FN; no real-log metrics are included here. **Do not commit raw logs, credentials or identifying event fields.**

## Rules
- `REPEATED_FAILED_LOGINS` (HIGH): >=5 Security 4625 events from one non-loopback IP against one user on one host within 10 minutes.
- `PS_SUSPICIOUS_ARGS` (MEDIUM): Sysmon process creation for PowerShell/pwsh with encoded-command or hidden/no-profile argument patterns.

## Final submission
- `docs/Week4_Lab_Validation.md`: hands-on real-log validation guide
- `docs/Final_Report.pdf`: two-page report, with evidence limitations disclosed
- `docs/Final_Presentation.pptx`: five-slide presentation
- `docs/Week3_Submission.md`: previous checkpoint
- `evaluation/`: scenario-label template and scoring utility

## Limitations
This is a demonstration prototype, not a production SIEM. The PowerShell rule can yield benign matches. The XML parser is not a native `.evtx` reader; export to XML first. Reliability against real logs remains an open validation requirement until the lab procedure is completed.

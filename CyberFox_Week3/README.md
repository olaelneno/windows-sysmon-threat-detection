# Windows/Sysmon Threat Detection System — Week 3

Python offline MVP that reads **Windows Event XML exports or normalized JSON** and detects repeated failed logons (Security 4625) and suspicious PowerShell arguments (Sysmon 1).

## Run
```powershell
python src/detector.py --input data/sample_events.xml --output output/week3_alerts.json
python -m unittest discover -s tests -v
```

## Real lab workflow
On an authorized Windows lab host, run `docs/Windows_Lab_Export.ps1` in elevated PowerShell. It exports `lab_security.xml` and `lab_sysmon.xml`. Copy exports to a local ignored folder and analyze them with the same `--input` CLI option. The export script does **not** create suspicious activity; it only exports existing events. For 4625 detection, generate at least five failures from the same non-loopback IP for one lab account within ten minutes.

**Important:** The included `data/sample_events.xml` is synthetic. Real-log effectiveness has **not** been verified; capture and test lab exports before claiming success. Do not commit unredacted real logs to a public repository.

## Supported XML formats
Single namespaced `<Event>`, `<Events>` container, and concatenated `Get-WinEvent` `ToXml()` fragments. Supported: Security 4625 and Sysmon 1. Other events are skipped. Raw EVTX unsupported.

## Week 3 report
See `docs/Week3_Submission.md` and `docs/Windows_Lab_Export.ps1`.

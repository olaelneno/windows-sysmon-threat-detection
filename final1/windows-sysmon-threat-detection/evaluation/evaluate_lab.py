"""Offline evaluation of lab scenarios against recorded expected rule IDs.

The manifest is authored by the lab operator; do not treat unlabelled logs as ground truth.
"""
import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from detector import detect, load_events


def evaluate(manifest):
    rows = []
    for case in manifest["scenarios"]:
        source = Path(manifest["_base"]) / case["file"]
        expected = set(case["expected_rules"])
        actual = {alert["rule_id"] for alert in detect(load_events(source))}
        rows.append({"scenario": case["name"], "file": str(source),
                     "expected_rules": sorted(expected), "detected_rules": sorted(actual),
                     "true_positives": len(expected & actual),
                     "false_positives": len(actual - expected),
                     "false_negatives": len(expected - actual)})
    tp = sum(r["true_positives"] for r in rows)
    fp = sum(r["false_positives"] for r in rows)
    fn = sum(r["false_negatives"] for r in rows)
    return {"scenarios": rows, "total": {"TP": tp, "FP": fp, "FN": fn,
            "precision": tp/(tp+fp) if tp+fp else None,
            "recall": tp/(tp+fn) if tp+fn else None}}


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--manifest", required=True)
    p.add_argument("--output", default="output/lab_evaluation.json")
    args = p.parse_args()
    path = Path(args.manifest).resolve()
    manifest = json.loads(path.read_text(encoding="utf-8"))
    manifest["_base"] = str(path.parent)
    result = evaluate(manifest)
    target = Path(args.output)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(result, indent=2), encoding="utf-8")
    print(json.dumps(result["total"], indent=2))

if __name__ == "__main__":
    main()

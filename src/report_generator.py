
import json
from pathlib import Path
from datetime import datetime, timezone


def save_report(events, invalid_lines, alerts, output_path):
    """Save analysis results as a JSON report."""

    report = {
        "project": "Python SOC Log Analyzer",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "summary": {
            "parsed_events": len(events),
            "rejected_lines": invalid_lines,
            "alerts_generated": len(alerts),
        },
        "alerts": alerts,
    }

    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    with output_path.open("w", encoding="utf-8") as file:
        json.dump(report, file, indent=4)

    return output_path

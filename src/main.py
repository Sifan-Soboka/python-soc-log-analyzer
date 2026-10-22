
from pathlib import Path

from log_parser import parse_log_line
from detections import detect_repeated_failures
from report_generator import save_report


PROJECT_ROOT = Path(__file__).resolve().parents[1]


def analyze_log_file(log_path, reference_year=2026):
    """Parse a log file and count lines that cannot be parsed."""
    events = []
    invalid_lines = 0

    with Path(log_path).open(
        "r", encoding="utf-8", errors="replace"
    ) as file:
        for line in file:
            if not line.strip():
                continue

            try:
                event = parse_log_line(
                    line, reference_year=reference_year
                )
                events.append(event)
            except ValueError:
                invalid_lines += 1

    return events, invalid_lines


def main():
    # Change this filename if your downloaded dataset has a different name.
    log_path = PROJECT_ROOT / "data" / "openssh_sk.log"
    report_path = PROJECT_ROOT / "reports" / "analysis_report.json"

    if not log_path.is_file():
        print(f"Dataset not found: {log_path}")
        print("Check the filename inside your data folder.")
        return

    events, invalid_lines = analyze_log_file(log_path)

    alerts = detect_repeated_failures(
        events,
        threshold=5,
        window_minutes=5,
    )

    save_report(events, invalid_lines, alerts, report_path)

    failed_count = sum(
        event["event"] == "FAILED_LOGIN"
        for event in events
    )
    successful_count = sum(
        event["event"] == "SUCCESSFUL_LOGIN"
        for event in events
    )

    print("\n=== Python SOC Log Analyzer ===")
    print(f"Log entries parsed: {len(events)}")
    print(f"Failed login events: {failed_count}")
    print(f"Successful login events: {successful_count}")
    print(f"Lines rejected: {invalid_lines}")
    print(f"Alerts generated: {len(alerts)}")

    for alert in alerts:
        print(f"\n[{alert['severity']}] {alert['type']}")
        print(f"IP address: {alert['ip']}")
        print(f"Failures in window: {alert['count']}")
        print(alert["message"])

    print(f"\nJSON report saved to: {report_path}")


if __name__ == "__main__":
    main()

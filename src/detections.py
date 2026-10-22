
from collections import defaultdict
from datetime import datetime, timedelta


def detect_repeated_failures(events, threshold=5, window_minutes=5):
    """
    Detect IP addresses with repeated failed logins.

    Returns one alert per IP, reporting the highest number of
    failed logins within any configured time window.
    """
    if threshold < 1:
        raise ValueError("threshold must be at least 1")

    if window_minutes < 0:
        raise ValueError("window_minutes cannot be negative")

    failures_by_ip = defaultdict(list)

    for event in events:
        if event.get("event") != "FAILED_LOGIN":
            continue

        ip = event.get("ip")
        timestamp_text = event.get("timestamp")

        if not ip or not timestamp_text:
            continue

        try:
            timestamp = datetime.fromisoformat(timestamp_text)
        except (ValueError, TypeError):
            continue

        failures_by_ip[ip].append(timestamp)

    alerts = []
    window = timedelta(minutes=window_minutes)

    for ip, timestamps in failures_by_ip.items():
        timestamps.sort()
        left = 0
        highest_count = 0

        for right, current_time in enumerate(timestamps):
            while current_time - timestamps[left] > window:
                left += 1

            count = right - left + 1
            highest_count = max(highest_count, count)

        if highest_count >= threshold:
            alerts.append({
                "type": "REPEATED_FAILED_LOGINS",
                "ip": ip,
                "count": highest_count,
                "window_minutes": window_minutes,
                "severity": "MEDIUM",
                "message": (
                    f"{highest_count} failed SSH login attempts "
                    f"from {ip} within {window_minutes} minutes."
                ),
            })

    return alerts

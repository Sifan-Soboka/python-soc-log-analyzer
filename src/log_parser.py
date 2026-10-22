
import re
import ipaddress
from datetime import datetime


TIMESTAMP_PATTERN = re.compile(
    r"^(?P<timestamp>[A-Z][a-z]{2}\s+\d{1,2}\s"
    r"\d{2}:\d{2}:\d{2})\s+"
)

FAILED_PASSWORD_PATTERN = re.compile(
    r"Failed password for (?:invalid user )?"
    r"(?P<username>\S+) from "
    r"(?P<ip>\d{1,3}(?:\.\d{1,3}){3})"
)

INVALID_USER_PATTERN = re.compile(
    r"Invalid user (?P<username>\S+) from "
    r"(?P<ip>\d{1,3}(?:\.\d{1,3}){3})"
)

SUCCESSFUL_LOGIN_PATTERN = re.compile(
    r"Accepted (?:password|publickey|keyboard-interactive(?:/pam)?) "
    r"for (?P<username>\S+) from "
    r"(?P<ip>\d{1,3}(?:\.\d{1,3}){3})"
)

AUTH_FAILURE_PATTERN = re.compile(r"authentication failure")
BREAK_IN_PATTERN = re.compile(r"POSSIBLE BREAK-IN ATTEMPT")


def parse_log_line(line, reference_year=2026):
    """Parse one OpenSSH syslog line into structured data."""
    line = line.strip()

    if not line:
        raise ValueError("Empty log entry")

    timestamp_match = TIMESTAMP_PATTERN.match(line)

    if not timestamp_match:
        raise ValueError("Unrecognized OpenSSH timestamp")

    timestamp_text = timestamp_match.group("timestamp")

    try:
        timestamp = datetime.strptime(
            f"{timestamp_text} {reference_year}",
            "%b %d %H:%M:%S %Y",
        )
    except ValueError as exc:
        raise ValueError("Invalid timestamp") from exc

    message = line[timestamp_match.end():]

    event = {
        "timestamp": timestamp.isoformat(sep=" "),
        "event": "OTHER",
        "username": None,
        "ip": None,
        "message": message,
    }

    match = FAILED_PASSWORD_PATTERN.search(message)

    if match:
        event["event"] = "FAILED_LOGIN"
        event["username"] = match.group("username")
        event["ip"] = match.group("ip")

    else:
        match = SUCCESSFUL_LOGIN_PATTERN.search(message)

        if match:
            event["event"] = "SUCCESSFUL_LOGIN"
            event["username"] = match.group("username")
            event["ip"] = match.group("ip")

        else:
            match = INVALID_USER_PATTERN.search(message)

            if match:
                event["event"] = "INVALID_USER"
                event["username"] = match.group("username")
                event["ip"] = match.group("ip")

            elif AUTH_FAILURE_PATTERN.search(message):
                event["event"] = "AUTH_FAILURE"

            elif BREAK_IN_PATTERN.search(message):
                event["event"] = "REVERSE_DNS_WARNING"

    if event["ip"] is not None:
        try:
            ipaddress.IPv4Address(event["ip"])
        except ipaddress.AddressValueError as exc:
            raise ValueError("Invalid IPv4 address") from exc

    return event

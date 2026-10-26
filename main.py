import argparse
import re
from collections import Counter, defaultdict
from pathlib import Path

# Original format used by our synthetic sample logs.
LOG_PATTERN = re.compile(
    r"^(?P<timestamp>\S+)\s+"
    r"(?P<status>FAILED|SUCCESS)\s+"
    r"user=(?P<user>\S+)\s+"
    r"ip=(?P<ip>\S+)$"
)

# Standard OpenSSH authentication events.
SSH_FAILED_PATTERN = re.compile(
    r"Failed password for (?:invalid user )?"
    r"(?P<user>\S+) from (?P<ip>\S+) port \d+ ssh2"
)

SSH_SUCCESS_PATTERN = re.compile(
    r"Accepted (?:password|publickey) for "
    r"(?P<user>\S+) from (?P<ip>\S+) port \d+ ssh2"
)

SSH_INVALID_USER_PATTERN = re.compile(
    r"Invalid user (?P<user>\S+) from (?P<ip>\S+)"
)

SSH_REPEATED_PATTERN = re.compile(
    r"message repeated (?P<count>\d+) times: \[ (?P<message>.*) \]"
)


def analyze_log(log_path, threshold):
    failed_by_ip = Counter()
    successful_by_ip = Counter()
    failed_by_user = Counter()
    usernames_by_ip = defaultdict(Counter)
    invalid_users_by_ip = Counter()

    failed = 0
    successful = 0
    invalid_user_events = 0
    ignored_lines = 0
    custom_format_lines = 0
    openssh_format_lines = 0

    def process_ssh_message(message, repetitions=1):
        """Count recognized SSH authentication events."""
        nonlocal failed, successful, invalid_user_events

        match = SSH_FAILED_PATTERN.search(message)
        if match:
            event = match.groupdict()
            failed += repetitions
            failed_by_ip[event["ip"]] += repetitions
            failed_by_user[event["user"]] += repetitions
            usernames_by_ip[event["ip"]][event["user"]] += repetitions
            return True

        match = SSH_SUCCESS_PATTERN.search(message)
        if match:
            event = match.groupdict()
            successful += repetitions
            successful_by_ip[event["ip"]] += repetitions
            return True

        match = SSH_INVALID_USER_PATTERN.search(message)
        if match:
            event = match.groupdict()
            invalid_user_events += repetitions
            invalid_users_by_ip[event["ip"]] += repetitions
            return True

        return False

    with log_path.open("r", encoding="utf-8", errors="replace") as log_file:
        for line in log_file:
            line = line.strip()
            if not line:
                continue

            # Support our original synthetic log format.
            match = LOG_PATTERN.match(line)
            if match:
                custom_format_lines += 1
                event = match.groupdict()
                ip = event["ip"]
                user = event["user"]

                if event["status"] == "FAILED":
                    failed += 1
                    failed_by_ip[ip] += 1
                    failed_by_user[user] += 1
                    usernames_by_ip[ip][user] += 1
                else:
                    successful += 1
                    successful_by_ip[ip] += 1
                continue

            # Count summarized repeated SSH messages without expanding them.
            repeated_match = SSH_REPEATED_PATTERN.search(line)
            if repeated_match:
                openssh_format_lines += 1
                count = int(repeated_match.group("count"))
                message = repeated_match.group("message")
                if not process_ssh_message(message, repetitions=count):
                    ignored_lines += 1
                continue

            # Parse ordinary OpenSSH messages.
            if "sshd" in line:
                if process_ssh_message(line):
                    openssh_format_lines += 1
                else:
                    ignored_lines += 1
            else:
                ignored_lines += 1

    alerts = {
        ip: count
        for ip, count in failed_by_ip.most_common()
        if count >= threshold
    }

    return {
        "failed": failed,
        "successful": successful,
        "invalid_user_events": invalid_user_events,
        "ignored_lines": ignored_lines,
        "custom_format_lines": custom_format_lines,
        "openssh_format_lines": openssh_format_lines,
        "failed_by_ip": failed_by_ip,
        "successful_by_ip": successful_by_ip,
        "failed_by_user": failed_by_user,
        "usernames_by_ip": usernames_by_ip,
        "invalid_users_by_ip": invalid_users_by_ip,
        "alerts": alerts,
    }


def build_report(log_path, threshold, results):
    lines = [
        "FAILED LOGIN LOG ANALYZER",
        "=" * 28,
        f"Log file: {log_path}",
        "",
        "SUMMARY",
        "-" * 28,
        f"Failed login attempts: {results['failed']}",
        f"Successful logins: {results['successful']}",
        f"Invalid-user events: {results['invalid_user_events']}",
        f"Other/unmatched lines: {results['ignored_lines']}",
        f"OpenSSH events parsed: {results['openssh_format_lines']}",
        f"Synthetic events parsed: {results['custom_format_lines']}",
        "",
        "TOP SOURCE IPs BY FAILED LOGINS",
        "-" * 28,
    ]

    if results["failed_by_ip"]:
        for ip, count in results["failed_by_ip"].most_common(15):
            lines.append(f"{ip}: {count} failed attempts")
            users = results["usernames_by_ip"][ip].most_common(5)
            if users:
                lines.append(
                    "  Targeted usernames: "
                    + ", ".join(f"{user} ({number})" for user, number in users)
                )
    else:
        lines.append("No failed-login events detected.")

    lines.extend([
        "",
        "TOP TARGETED USERNAMES",
        "-" * 28,
    ])

    if results["failed_by_user"]:
        for user, count in results["failed_by_user"].most_common(10):
            lines.append(f"{user}: {count} failed attempts")
    else:
        lines.append("No targeted usernames detected.")

    lines.extend([
        "",
        f"ALERTS (threshold: {threshold} failed attempts per IP)",
        "-" * 28,
    ])

    if results["alerts"]:
        for ip, count in results["alerts"].items():
            lines.append(
                f"[ALERT] {ip} had {count} failed login attempts"
            )
    else:
        lines.append("No IP addresses met the alert threshold.")

    return "\n".join(lines) + "\n"


def main():
    parser = argparse.ArgumentParser(
        description="Analyze synthetic or OpenSSH logs for repeated failed logins."
    )
    parser.add_argument(
        "--log",
        type=Path,
        default=Path("sample_logs/auth.log"),
        help="Path to the authentication log file",
    )
    parser.add_argument(
        "--threshold",
        type=int,
        default=4,
        help="Minimum failed attempts from one IP to flag (default: 4)",
    )
    parser.add_argument(
        "--report",
        type=Path,
        default=Path("reports/summary.txt"),
        help="Path to save the text report",
    )

    args = parser.parse_args()

    if args.threshold < 1:
        parser.error("--threshold must be at least 1")

    if not args.log.is_file():
        parser.error(f"Log file not found: {args.log}")

    results = analyze_log(args.log, args.threshold)
    report_text = build_report(args.log, args.threshold, results)

    print(report_text)

    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(report_text, encoding="utf-8")
    print(f"Report saved to: {args.report}")


if __name__ == "__main__":
    main()

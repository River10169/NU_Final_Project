# Import argparse so the script can accept command-line options like --profile, --csv, --html, and --log.
import argparse

# Import csv so the script can write audit results into a CSV report.
import csv

# Import datetime so the script can add timestamps to reports and logs.
import datetime

# NOTE: os is imported here, but it is not currently used anywhere in the script.
import os

# Import platform so the script can detect whether it is running on Windows, Linux, etc.
import platform

# Import re so the script can search configuration files using regular expressions.
import re

# Import subprocess so the script can run system commands such as PowerShell, ufw, or systemctl.
import subprocess

# NOTE: sys is imported here, but it is not currently used anywhere in the script.
import sys

# dataclass is used to create a clean structure for each audit rule.
from dataclasses import dataclass

# Path makes file paths easier and cleaner to work with across operating systems.
from pathlib import Path

# These typing imports help describe what type of data each function expects and returns.
from typing import Callable, Dict, List, Tuple


# This dataclass defines the structure of one security audit rule.
# Each rule has an ID, description, severity, remediation steps, supported platforms,
# supported benchmark profiles, and a check function that actually tests the setting.
@dataclass
class AuditRule:
    id: str
    description: str
    severity: str
    remediation: str
    platforms: List[str]
    profiles: List[str]
    check: Callable[[], Tuple[bool, str]]


# This helper function runs a system command and returns whether it worked and what it output.
# It is used by checks that need to ask the operating system for information.
def run_command(command: List[str]) -> Tuple[bool, str]:
    try:
        # Runs the command safely without using a shell, captures the output, and times out after 15 seconds.
        result = subprocess.run(command, capture_output=True, text=True, shell=False, timeout=15)
        return True, result.stdout.strip()
    except subprocess.SubprocessError as exc:
        # If the command fails or times out, the function returns False and the error message.
        return False, str(exc)


# This helper function reads a file and returns whether it worked and the file contents.
# It is used for Linux configuration files such as /etc/ssh/sshd_config and /etc/login.defs.
def read_file(path: Path) -> Tuple[bool, str]:
    try:
        return True, path.read_text(errors="ignore")
    except OSError as exc:
        # If the file cannot be read, return False with the reason why.
        return False, str(exc)


# This function searches the SSH configuration file text for a specific setting.
# For example, it can find the value of PermitRootLogin in /etc/ssh/sshd_config.
def parse_sshd_config(value: str, key: str) -> str:
    # This regex looks for a line that starts with the setting name and captures its value.
    pattern = re.compile(rf"^\s*{re.escape(key)}\s+(.*)$", re.MULTILINE | re.IGNORECASE)
    match = pattern.search(value)

    # If the setting is found, return its value. Otherwise, return an empty string.
    return match.group(1).strip() if match else ""


# This Linux check verifies whether SSH root login is disabled or restricted.
# Allowing direct root login is risky because attackers can target the root account directly.
def check_linux_ssh_root_login() -> Tuple[bool, str]:
    sshd = Path("/etc/ssh/sshd_config")
    ok, content = read_file(sshd)
    if not ok:
        return False, f"Cannot read {sshd}: {content}"

    # If PermitRootLogin is not found, the script assumes the common default value of prohibit-password.
    value = parse_sshd_config(content, "PermitRootLogin") or "prohibit-password"

    # The check passes if root login is disabled or only allowed without passwords.
    passed = value.lower() in {"no", "prohibit-password", "without-password"}
    return passed, f"PermitRootLogin={value}"


# This Linux check verifies that password maximum age is set to 90 days or less.
# This supports password policy requirements in many security benchmarks.
def check_linux_password_max_days() -> Tuple[bool, str]:
    login_defs = Path("/etc/login.defs")
    ok, content = read_file(login_defs)
    if not ok:
        return False, f"Cannot read {login_defs}: {content}"

    # Searches /etc/login.defs for the PASS_MAX_DAYS setting.
    match = re.search(r"^\s*PASS_MAX_DAYS\s+(\d+)", content, re.MULTILINE)
    if not match:
        return False, "PASS_MAX_DAYS not configured"

    # Converts the setting to a number and checks whether it is 90 days or lower.
    days = int(match.group(1))
    return days <= 90, f"PASS_MAX_DAYS={days}"


# This Linux check verifies whether UFW, the Uncomplicated Firewall, is installed and active.
# A firewall helps control inbound and outbound network traffic.
def check_linux_ufw_enabled() -> Tuple[bool, str]:
    # First, check whether the ufw command exists on the system.
    ok, output = run_command(["which", "ufw"])
    if not ok or not output:
        return False, "ufw not installed"

    # If UFW exists, check its status.
    ok, status = run_command(["ufw", "status"])
    if not ok:
        return False, f"Could not read ufw status: {status}"

    # The check passes only if the status output says UFW is active.
    active = "Status: active" in status
    return active, f"{status.splitlines()[0] if status else 'unknown'}"


# This Linux check looks at whether the SSH service is enabled.
# NOTE: This function is defined, but it is not currently added to build_rules(), so it will not run.
def check_running_services_linux() -> Tuple[bool, str]:
    ok, output = run_command(["systemctl", "is-enabled", "ssh"])
    if not ok:
        return False, f"Cannot determine SSH service state: {output}"

    # Checks whether the service is enabled at startup.
    enabled = "enabled" in output.lower()
    return enabled, f"ssh service is {output.strip()}"


# This Linux check reviews permissions on sensitive account files.
# These files store user, group, and password-related information.
def check_linux_sensitive_files() -> Tuple[bool, str]:
    file_paths = [Path("/etc/passwd"), Path("/etc/shadow"), Path("/etc/group")]
    messages = []
    passed = True

    for path in file_paths:
        # If a required file is missing, the check fails.
        if not path.exists():
            messages.append(f"{path} missing")
            passed = False
            continue

        # Gets only the permission bits from the file mode, such as 644 or 600.
        mode = path.stat().st_mode & 0o777

        # /etc/shadow should be very restricted because it contains password hash information.
        # This fails the check if group or other users have any permissions on /etc/shadow.
        if path == Path("/etc/shadow") and mode & 0o077:
            messages.append(f"{path} permissions too open: {oct(mode)}")
            passed = False

        # /etc/passwd should not be world-writable because that could allow account tampering.
        elif path == Path("/etc/passwd") and mode & 0o002:
            messages.append(f"{path} world-writable: {oct(mode)}")
            passed = False

    # If no problems were found, return a clean message. Otherwise, return the issues found.
    return passed, "; ".join(messages) if messages else "Permissions are acceptable"


# This Windows check verifies that Windows Firewall is enabled for all firewall profiles.
# The profiles are usually Domain, Private, and Public.
def check_windows_firewall_enabled() -> Tuple[bool, str]:
    ok, output = run_command(["powershell", "-NoProfile", "-Command", "(Get-NetFirewallProfile | Select-Object -ExpandProperty Enabled) -join ','"])
    if not ok:
        return False, f"Could not query firewall: {output}"

    # Splits the PowerShell output into separate True/False values.
    statuses = [item.strip() for item in output.split(",") if item.strip()]
    if not statuses:
        return False, "No firewall profiles returned"

    # The check passes only if every firewall profile is enabled.
    passed = all(status == "True" for status in statuses)
    return passed, f"Firewall profiles enabled: {statuses}"


# This Windows check verifies that the built-in Guest account is disabled.
# The Guest account should usually be disabled because it can create unnecessary access risk.
def check_windows_guest_disabled() -> Tuple[bool, str]:
    ok, output = run_command(["powershell", "-NoProfile", "-Command", "(Get-LocalUser -Name Guest).Enabled"])
    if not ok:
        return False, f"Could not query Guest account: {output}"

    # The check passes when PowerShell reports the Guest account is False, meaning disabled.
    return output.strip().lower() == "false", f"Guest enabled={output.strip()}"


# This Windows check counts enabled local users other than Administrator.
# NOTE: This function is defined, but it is not currently added to build_rules(), so it will not run.
# Also, it always returns True, so it is more informational than a real pass/fail policy check.
def check_windows_password_policy() -> Tuple[bool, str]:
    ok, output = run_command(["powershell", "-NoProfile", "-Command", "(Get-LocalUser | Where-Object { $_.Enabled -eq $true -and $_.Name -ne 'Administrator' } | Measure-Object).Count"])
    if not ok:
        return False, f"Could not query local users: {output}"
    return True, output.strip()


# This Windows check verifies that SMBv1 is disabled or removed.
# SMBv1 is outdated and is commonly disabled because of known security risks.
def check_windows_smb1_disabled() -> Tuple[bool, str]:
    ok, output = run_command([
        "powershell",
        "-NoProfile",
        "-Command",
        "(Get-WindowsOptionalFeature -Online -FeatureName SMB1Protocol).State"
    ])
    if not ok:
        return False, f"Could not query SMB1 state: {output}"

    # The check passes if SMB1 is either disabled or completely removed.
    return output.strip().lower() in {"disabled", "removed"}, f"SMB1 state={output.strip()}"


# This function builds the list of audit rules the script knows how to run.
# Each AuditRule connects a description and remediation step to the function that performs the check.
def build_rules() -> List[AuditRule]:
    return [
        AuditRule(
            id="LINUX-001",
            description="SSH root login should be disabled",
            severity="High",
            remediation="Set PermitRootLogin no in /etc/ssh/sshd_config and restart sshd.",
            platforms=["Linux"],
            profiles=["cis", "best-practices"],
            check=check_linux_ssh_root_login,
        ),
        AuditRule(
            id="LINUX-002",
            description="Password maximum age should be 90 days or less",
            severity="Medium",
            remediation="Set PASS_MAX_DAYS 90 or lower in /etc/login.defs.",
            platforms=["Linux"],
            profiles=["cis", "best-practices"],
            check=check_linux_password_max_days,
        ),
        AuditRule(
            id="LINUX-003",
            description="UFW firewall should be installed and active",
            severity="High",
            remediation="Install UFW and enable it with ufw enable.",
            platforms=["Linux"],
            profiles=["cis", "best-practices"],
            check=check_linux_ufw_enabled,
        ),
        AuditRule(
            id="LINUX-004",
            description="Sensitive system files should have restricted permissions",
            severity="High",
            remediation="Review permissions for /etc/passwd, /etc/shadow, and /etc/group.",
            platforms=["Linux"],
            profiles=["cis", "best-practices"],
            check=check_linux_sensitive_files,
        ),
        AuditRule(
            id="WINDOWS-001",
            description="Windows Firewall should be enabled for all profiles",
            severity="High",
            remediation="Enable Windows Firewall in Control Panel or with PowerShell Get-NetFirewallProfile.",
            platforms=["Windows"],
            profiles=["cis", "best-practices"],
            check=check_windows_firewall_enabled,
        ),
        AuditRule(
            id="WINDOWS-002",
            description="Guest account should be disabled",
            severity="Medium",
            remediation="Disable the Guest account using Local Users and Groups or PowerShell.",
            platforms=["Windows"],
            profiles=["cis", "best-practices"],
            check=check_windows_guest_disabled,
        ),
        AuditRule(
            id="WINDOWS-003",
            description="SMBv1 protocol should be disabled",
            severity="High",
            remediation="Disable SMB1 via Windows Features or PowerShell.",
            platforms=["Windows"],
            profiles=["cis", "best-practices"],
            check=check_windows_smb1_disabled,
        ),
    ]


# This function filters the full rule list so only rules for the selected profile and current operating system run.
# Example: on Windows, it skips Linux rules. On Linux, it skips Windows rules.
def filter_rules(rules: List[AuditRule], profile: str, current_platform: str) -> List[AuditRule]:
    return [
        rule for rule in rules
        if profile in rule.profiles and current_platform in rule.platforms
    ]


# This function turns one audit result into a dictionary row.
# The row can then be printed, saved to CSV, saved to HTML, or logged.
def format_report_row(rule: AuditRule, result: bool, detail: str) -> Dict[str, str]:
    return {
        "Rule ID": rule.id,
        "Description": rule.description,
        "Severity": rule.severity,
        "Status": "PASS" if result else "FAIL",
        "Detail": detail,
        "Remediation": rule.remediation,
    }


# This function writes the audit results to a CSV file.
# CSV files are useful because they can be opened in Excel or attached to reports.
def write_csv_report(rows: List[Dict[str, str]], path: Path) -> None:
    if not rows:
        return

    # Opens the output file and writes the column names followed by each audit result row.
    with path.open("w", newline="", encoding="utf-8") as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=list(rows[0].keys()))
        writer.writeheader()
        writer.writerows(rows)


# This function writes the audit results to an HTML report.
# HTML is useful because it gives a readable report with pass/fail row colors.
def write_html_report(rows: List[Dict[str, str]], path: Path, profile: str, system: str) -> None:
    # These lines build the HTML page, including basic styling and report metadata.
    lines = [
        "<!DOCTYPE html>",
        "<html lang=\"en\">",
        "<head>",
        "<meta charset=\"UTF-8\">",
        f"<title>Security Audit Report - {profile}</title>",
        "<style>",
        "body { font-family: Arial, sans-serif; margin: 20px; }",
        "table { width: 100%; border-collapse: collapse; margin-top: 16px; }",
        "th, td { border: 1px solid #bbb; padding: 10px; text-align: left; }",
        "th { background: #f4f4f4; }",
        ".pass { background: #e6ffed; }",
        ".fail { background: #ffe6e6; }",
        "</style>",
        "</head>",
        "<body>",
        f"<h1>Security Audit Report</h1>",
        f"<p><strong>Profile:</strong> {profile}</p>",
        f"<p><strong>System:</strong> {system}</p>",
        f"<p><strong>Generated:</strong> {datetime.datetime.now():%Y-%m-%d %H:%M:%S}</p>",
        "<table>",
        "<tr><th>Rule ID</th><th>Description</th><th>Severity</th><th>Status</th><th>Detail</th><th>Remediation</th></tr>",
    ]

    # Adds one table row for each audit result.
    # Passing rows get the pass CSS class, and failing rows get the fail CSS class.
    for row in rows:
        status_class = "pass" if row["Status"] == "PASS" else "fail"
        lines.append(
            f"<tr class=\"{status_class}\"><td>{row['Rule ID']}</td><td>{row['Description']}</td>"
            f"<td>{row['Severity']}</td><td>{row['Status']}</td><td>{row['Detail']}</td><td>{row['Remediation']}</td></tr>"
        )

    # Closes the HTML tags and writes the final report to the selected path.
    lines.extend(["</table>", "</body>", "</html>"])
    path.write_text("\n".join(lines), encoding="utf-8")


# This function writes audit results to a JSON log file.
# The log keeps a history of previous audits instead of only creating one report.
def write_log(rows: List[Dict[str, str]], path: Path, system: str) -> None:
    timestamp = datetime.datetime.now().isoformat()

    # Creates one log entry with the time, system information, and all findings.
    log_entry = {
        "timestamp": timestamp,
        "system": system,
        "findings": rows,
    }

    # If the log file already exists, try to load the older audit history first.
    existing = []
    if path.exists():
        try:
            import json
            existing = json.loads(path.read_text(encoding="utf-8"))
        except Exception:
            # If the existing log cannot be read, start a new log list instead of crashing.
            existing = []

    # Adds the newest audit result and writes the full history back to the file.
    existing.append(log_entry)
    path.write_text(__import__("json").dumps(existing, indent=2), encoding="utf-8")


# This function defines the command-line options the user can pass when running the script.
# Example: python audit.py --profile cis --csv report.csv --html report.html --log audit_log.json
def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Security automation audit script for CIS and best-practices benchmarks."
    )
    parser.add_argument(
        "--profile",
        choices=["cis", "best-practices"],
        default="cis",
        help="Benchmark profile to evaluate.",
    )
    parser.add_argument("--csv", help="Path to write a CSV compliance report.")
    parser.add_argument("--html", help="Path to write an HTML compliance report.")
    parser.add_argument("--log", help="Path to write an audit history log in JSON format.")
    return parser.parse_args()


# This is the main control function for the script.
# It reads the command-line options, builds the rules, runs the correct checks, prints results,
# creates reports if requested, and returns an exit code.
def main() -> int:
    # Gets the user's command-line choices.
    args = parse_args()

    # Detects the operating system and stores basic system information for the report.
    current_platform = platform.system()
    system_info = f"{current_platform} {platform.release()} ({platform.machine()})"

    # Builds all rules, then filters them to only the rules that apply to this system and profile.
    rules = build_rules()
    applicable_rules = filter_rules(rules, args.profile, current_platform)

    # If there are no matching rules, stop the script and return exit code 1.
    if not applicable_rules:
        print(f"No audit rules available for platform {current_platform} and profile {args.profile}.")
        return 1

    # These variables track the report rows and how many checks passed.
    rows = []
    passed_count = 0

    # Prints basic information before running the checks.
    print(f"Running security audit for profile: {args.profile}")
    print(f"Platform: {system_info}")
    print("-")

    # Runs each audit rule's check function and prints the result.
    for rule in applicable_rules:
        result, detail = rule.check()
        rows.append(format_report_row(rule, result, detail))
        status = "PASS" if result else "FAIL"
        if result:
            passed_count += 1

        print(f"[{status}] {rule.id}: {rule.description}")
        print(f"      Detail: {detail}")
        print(f"      Remediation: {rule.remediation}\n")

    # Calculates the compliance score as a percentage.
    score = int(passed_count / len(rows) * 100)
    print("=" * 60)
    print(f"Compliance score: {score}% ({passed_count}/{len(rows)} rules passed)")

    # Creates optional reports only if the user provided those command-line arguments.
    if args.csv:
        write_csv_report(rows, Path(args.csv))
        print(f"CSV report written to {args.csv}")
    if args.html:
        write_html_report(rows, Path(args.html), args.profile, system_info)
        print(f"HTML report written to {args.html}")
    if args.log:
        write_log(rows, Path(args.log), system_info)
        print(f"Audit log updated at {args.log}")

    # Exit code 0 means all checks passed. Exit code 2 means at least one check failed.
    return 0 if passed_count == len(rows) else 2


# This makes sure main() only runs when the file is executed directly.
# It prevents the audit from automatically running if this file is imported by another Python script.
if __name__ == "__main__":
    raise SystemExit(main())

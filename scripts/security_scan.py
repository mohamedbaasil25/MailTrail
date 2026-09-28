#!/usr/bin/env python3
"""
scripts/security_scan.py

Runs two independent security checks over the codebase and reports a clear,
CI-friendly summary:

  1. pip-audit  - checks installed dependencies against known CVE databases
                  (OSV/PyPI advisory data). Catches "you're running a
                  library version with a known vulnerability" - something
                  no amount of code review catches, since the vulnerable
                  code isn't yours.
  2. bandit     - static analysis over this repo's own Python source for
                  common insecure patterns (hardcoded secrets, use of
                  eval/exec, insecure deserialization, weak hashes, etc).

Usage:
    python scripts/security_scan.py                 # run both
    python scripts/security_scan.py --pip-audit-only
    python scripts/security_scan.py --bandit-only
    python scripts/security_scan.py --json           # machine-readable output

Exit code is non-zero if either tool reports a finding, so this can be
wired into CI directly (see .github/workflows/ci.yml's security-scan job).
"""

from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys

REPO_PYTHON_PATHS = ["main.py", "config.py", "database.py", "rate_limiter.py", "api", "services", "models"]


def _run(cmd: list[str]) -> tuple[int, str]:
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
        return result.returncode, (result.stdout + result.stderr)
    except FileNotFoundError:
        return 127, f"{cmd[0]}: command not found - is it installed? (pip install -r requirements-dev.txt)"
    except subprocess.TimeoutExpired:
        return 124, f"{' '.join(cmd)} timed out after 300s"


def run_pip_audit(as_json: bool) -> dict:
    print("== pip-audit: scanning installed dependencies for known CVEs ==")
    cmd = ["pip-audit", "--progress-spinner", "off"]
    if as_json:
        cmd += ["--format", "json"]
    code, output = _run(cmd)
    if code == 127:
        print(output)
        return {"tool": "pip-audit", "ran": False, "findings": 0, "output": output}

    if not as_json:
        print(output)

    findings = 0
    if as_json:
        try:
            parsed = json.loads(output)
            findings = sum(len(dep.get("vulns", [])) for dep in parsed.get("dependencies", parsed if isinstance(parsed, list) else []))
        except (json.JSONDecodeError, AttributeError):
            findings = 1 if code != 0 else 0
    else:
        findings = 1 if code != 0 else 0

    status = "CLEAN" if code == 0 else f"{findings or 'some'} finding(s)"
    print(f"-> pip-audit: {status}\n")
    return {"tool": "pip-audit", "ran": True, "findings": findings, "exit_code": code, "output": output}


def run_bandit(as_json: bool) -> dict:
    print("== bandit: static analysis of application source ==")
    existing_paths = [p for p in REPO_PYTHON_PATHS if shutil.os.path.exists(p)]
    cmd = ["bandit", "-r", *existing_paths, "-q"]
    # Low-confidence/low-severity noise isn't worth failing CI over; -ll
    # only surfaces medium+ severity findings at medium+ confidence.
    cmd += ["-ll"]
    if as_json:
        cmd += ["-f", "json"]
    code, output = _run(cmd)
    if code == 127:
        print(output)
        return {"tool": "bandit", "ran": False, "findings": 0, "output": output}

    if not as_json:
        print(output)

    findings = 0
    if as_json:
        try:
            parsed = json.loads(output)
            findings = len(parsed.get("results", []))
        except json.JSONDecodeError:
            findings = 1 if code != 0 else 0
    else:
        findings = 1 if code != 0 else 0

    status = "CLEAN" if code == 0 else f"{findings or 'some'} finding(s)"
    print(f"-> bandit: {status}\n")
    return {"tool": "bandit", "ran": True, "findings": findings, "exit_code": code, "output": output}


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--pip-audit-only", action="store_true")
    parser.add_argument("--bandit-only", action="store_true")
    parser.add_argument("--json", action="store_true", help="Machine-readable output (also used internally for finding counts)")
    args = parser.parse_args()

    results = []
    if args.bandit_only:
        results.append(run_bandit(args.json))
    elif args.pip_audit_only:
        results.append(run_pip_audit(args.json))
    else:
        results.append(run_pip_audit(args.json))
        results.append(run_bandit(args.json))

    total_findings = sum(r["findings"] for r in results if r["ran"])
    any_ran = any(r["ran"] for r in results)

    if args.json:
        print(json.dumps(results, indent=2))

    print("=" * 60)
    if not any_ran:
        print("No scanners were runnable - install requirements-dev.txt first.")
        sys.exit(2)
    print(f"Total findings across {len(results)} tool(s): {total_findings}")
    sys.exit(0 if total_findings == 0 else 1)


if __name__ == "__main__":
    main()

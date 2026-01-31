#!/usr/bin/env python3
"""
ThirdGen Smart Contract Security Scanner
Main orchestrator script - runs all tools, aggregates, enhances, and reports

Usage: python -m audit.run_audit [--config path/to/config.yaml]
"""

import argparse
import json
import logging
import os
import subprocess
import sys
from pathlib import Path
from typing import Optional

import requests
import yaml

from .aggregator import aggregate_findings
from .ai_enhancer import enhance_findings
from .github_inline import post_review_comments
from .models import AuditReport, Finding
from .parsers import parse_aderyn, parse_mythril, parse_slither, parse_solhint
from .report_generator import generate_pr_comment, generate_report

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)s | %(message)s",
    datefmt="%H:%M:%S"
)
log = logging.getLogger(__name__)

# GitHub environment variables
GITHUB_TOKEN = os.getenv("GITHUB_TOKEN")
GITHUB_REPOSITORY = os.getenv("GITHUB_REPOSITORY")
GITHUB_REF = os.getenv("GITHUB_REF", "")
GITHUB_API = "https://api.github.com"


def load_config(config_path: str = "audit/tools-config.yaml") -> dict:
    """Load configuration from YAML file and merge with user config"""
    path = Path(config_path)

    if not path.exists():
        # Try relative to script location
        script_dir = Path(__file__).parent
        path = script_dir / "tools-config.yaml"

    if path.exists():
        log.info(f"Loading config from {path}")
        with open(path) as f:
            config = yaml.safe_load(f)
    else:
        log.warning("No config file found, using defaults")
        config = {
            "contracts": {"path": "src/", "exclude_paths": ["lib/", "test/", "script/"]},
            "ai": {"enabled": False},
            "tools": {
                "slither": {"enabled": True},
                "aderyn": {"enabled": True},
                "mythril": {"enabled": False},
                "solhint": {"enabled": True}
            },
            "severity_map": {},
            "report": {"output": "results/report.md"}
        }

    # Check for user config in target directory (thirdgen.config.yaml)
    user_config_path = Path("thirdgen.config.yaml")
    if user_config_path.exists():
        log.info(f"Loading user config from {user_config_path}")
        try:
            with open(user_config_path) as f:
                user_config = yaml.safe_load(f) or {}

            # Merge user config into base config
            if "solc_version" in user_config:
                config.setdefault("contracts", {})["solc_version"] = user_config["solc_version"]

            if "exclude_paths" in user_config:
                config.setdefault("contracts", {})["exclude_paths"] = user_config["exclude_paths"]

            if "exclude_severities" in user_config:
                config["exclude_severities"] = user_config["exclude_severities"]

            if "mythril" in user_config:
                mythril_cfg = user_config["mythril"]
                if "enabled" in mythril_cfg:
                    config.setdefault("tools", {}).setdefault("mythril", {})["enabled"] = mythril_cfg["enabled"]
                if mythril_cfg.get("targets"):
                    config["mythril_targets"] = mythril_cfg["targets"]
                if mythril_cfg.get("remappings_file"):
                    config.setdefault("tools", {}).setdefault("mythril", {})["remappings_file"] = mythril_cfg["remappings_file"]

            if "ai" in user_config:
                ai_cfg = user_config["ai"]
                config.setdefault("ai", {})
                if "enabled" in ai_cfg:
                    config["ai"]["enabled"] = ai_cfg["enabled"]
                if "analyze_severities" in ai_cfg:
                    config["ai"]["analyze_only"] = ai_cfg["analyze_severities"]
                if "max_findings" in ai_cfg:
                    config["ai"]["max_findings"] = ai_cfg["max_findings"]

        except (yaml.YAMLError, IOError) as e:
            log.warning(f"Failed to load user config: {e}")

    return config


def run_command(cmd: list[str], timeout: Optional[int] = 120) -> Optional[str]:
    """Execute a command and return stdout"""
    try:
        if timeout:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        else:
            result = subprocess.run(cmd, capture_output=True, text=True)
        return result.stdout
    except subprocess.TimeoutExpired:
        log.warning(f"Command timed out: {cmd[0]}")
    except FileNotFoundError:
        log.error(f"Command not found: {cmd[0]}")
    except Exception as e:
        log.error(f"Command failed: {e}")
    return None


def run_slither(config: dict) -> list[Finding]:
    """Run Slither and parse results"""
    tool_config = config.get("tools", {}).get("slither", {})
    if not tool_config.get("enabled", True):
        log.info("Slither: disabled")
        return []

    log.info("Running Slither...")
    timeout = tool_config.get("timeout", 300)

    stdout = run_command(["slither", ".", "--json", "-"], timeout=timeout)

    if not stdout:
        log.warning("Slither: no output")
        return []

    findings = parse_slither(
        stdout,
        config.get("severity_map", {}),
        config.get("contracts", {}).get("exclude_paths", [])
    )
    log.info(f"Slither: {len(findings)} findings")
    return findings


def run_aderyn(config: dict) -> list[Finding]:
    """Run Aderyn and parse results"""
    tool_config = config.get("tools", {}).get("aderyn", {})
    if not tool_config.get("enabled", True):
        log.info("Aderyn: disabled")
        return []

    log.info("Running Aderyn...")
    timeout = tool_config.get("timeout", 120)

    output_path = tool_config.get("output", "results/aderyn.json")
    Path(output_path).parent.mkdir(parents=True, exist_ok=True)

    # Clean up old report
    if Path(output_path).exists():
        Path(output_path).unlink()

    exclude_paths = config.get("contracts", {}).get("exclude_paths", [])
    exclude_arg = ",".join(exclude_paths) if exclude_paths else ""

    cmd = ["aderyn", ".", "-o", output_path]
    if exclude_arg:
        cmd.extend(["-x", exclude_arg])

    run_command(cmd, timeout=timeout)

    if not Path(output_path).exists():
        log.warning("Aderyn: no output file")
        return []

    findings = parse_aderyn(
        output_path,
        config.get("severity_map", {}),
        exclude_paths
    )

    # Clean up
    try:
        Path(output_path).unlink()
    except:
        pass

    log.info(f"Aderyn: {len(findings)} findings")
    return findings


def run_mythril(config: dict) -> list[Finding]:
    """Run Mythril on specified targets"""
    tool_config = config.get("tools", {}).get("mythril", {})
    if not tool_config.get("enabled", False):
        log.info("Mythril: disabled")
        return []

    targets = config.get("mythril_targets", [])
    if not targets:
        log.info("Mythril: no targets specified")
        return []

    log.info(f"Running Mythril on {len(targets)} targets...")
    remappings_file = tool_config.get("remappings_file", "remappings.json")

    all_findings = []

    for target in targets:
        if not Path(target).exists():
            log.warning(f"  Target not found: {target}")
            continue

        log.info(f"  Analyzing {target}...")

        cmd = ["myth", "analyze", target, "-o", "json"]
        if Path(remappings_file).exists():
            cmd.extend(["--solc-json", remappings_file])

        # Mythril can be slow, no timeout by default
        stdout = run_command(cmd, timeout=tool_config.get("timeout"))

        if stdout:
            findings = parse_mythril(stdout, config.get("severity_map", {}), target)
            all_findings.extend(findings)

    log.info(f"Mythril: {len(all_findings)} findings")
    return all_findings


def run_solhint(config: dict) -> list[Finding]:
    """Run Solhint and parse results"""
    tool_config = config.get("tools", {}).get("solhint", {})
    if not tool_config.get("enabled", True):
        log.info("Solhint: disabled")
        return []

    log.info("Running Solhint...")
    timeout = tool_config.get("timeout", 120)

    contracts_path = config.get("contracts", {}).get("path", "src/")
    pattern = f"{contracts_path}**/*.sol"

    stdout = run_command(["solhint", pattern, "-f", "json"], timeout=timeout)

    if not stdout:
        log.warning("Solhint: no output")
        return []

    findings = parse_solhint(
        stdout,
        config.get("severity_map", {}),
        config.get("contracts", {}).get("exclude_paths", [])
    )
    log.info(f"Solhint: {len(findings)} findings")
    return findings


def post_to_github(report_content: str) -> bool:
    """Post report as PR comment"""
    if not all([GITHUB_TOKEN, GITHUB_REPOSITORY]):
        log.info("GitHub: missing credentials, skipping PR comment")
        return False

    if "/pull/" not in GITHUB_REF:
        log.info("GitHub: not a PR, skipping comment")
        return False

    try:
        pr_number = GITHUB_REF.split("/")[-2]
        comments_url = f"{GITHUB_API}/repos/{GITHUB_REPOSITORY}/issues/{pr_number}/comments"
        headers = {
            "Authorization": f"token {GITHUB_TOKEN}",
            "Accept": "application/vnd.github.v3+json"
        }

        # Check for existing comment to update
        response = requests.get(comments_url, headers=headers, timeout=15)
        if response.status_code == 200:
            for comment in response.json():
                if "Security Audit Report" in comment.get("body", ""):
                    update_url = f"{GITHUB_API}/repos/{GITHUB_REPOSITORY}/issues/comments/{comment['id']}"
                    requests.patch(
                        update_url,
                        json={"body": report_content},
                        headers=headers,
                        timeout=15
                    )
                    log.info("GitHub: updated existing PR comment")
                    return True

        # Create new comment
        response = requests.post(
            comments_url,
            json={"body": report_content},
            headers=headers,
            timeout=15
        )

        if response.status_code == 201:
            log.info("GitHub: posted new PR comment")
            return True

    except requests.RequestException as e:
        log.error(f"GitHub API error: {e}")

    return False


def main():
    parser = argparse.ArgumentParser(description="ThirdGen Security Scanner")
    parser.add_argument("--config", "-c", default="audit/tools-config.yaml", help="Config file path")
    parser.add_argument("--output", "-o", help="Output report path (overrides config)")
    parser.add_argument("--no-ai", action="store_true", help="Disable AI enhancement")
    parser.add_argument("--no-github", action="store_true", help="Skip GitHub PR comment")
    args = parser.parse_args()

    print("=" * 60)
    print("  THIRDGEN SMART CONTRACT SECURITY SCANNER")
    print("=" * 60)
    print()

    # Load configuration
    config = load_config(args.config)

    if args.no_ai:
        config["ai"]["enabled"] = False

    # Step 1: Run all tools
    print("\n[1/4] Running security tools...\n")
    all_findings: list[Finding] = []
    tools_run: list[str] = []

    # Run tools
    slither_findings = run_slither(config)
    if slither_findings:
        all_findings.extend(slither_findings)
        tools_run.append("Slither")

    aderyn_findings = run_aderyn(config)
    if aderyn_findings:
        all_findings.extend(aderyn_findings)
        tools_run.append("Aderyn")

    mythril_findings = run_mythril(config)
    if mythril_findings:
        all_findings.extend(mythril_findings)
        tools_run.append("Mythril")

    solhint_findings = run_solhint(config)
    if solhint_findings:
        all_findings.extend(solhint_findings)
        tools_run.append("Solhint")

    print(f"\nTotal raw findings: {len(all_findings)}")

    # Step 2: Aggregate and deduplicate
    print("\n[2/4] Aggregating findings...")
    deduped_findings = aggregate_findings(all_findings)

    # Step 3: AI enhancement
    print("\n[3/4] AI enhancement...")
    enhanced_findings = enhance_findings(deduped_findings, config)

    # Step 4: Generate report
    print("\n[4/4] Generating report...")
    report = AuditReport(findings=enhanced_findings, tools_run=tools_run)

    # Print summary
    print(f"""
Summary:
  - Critical: {len(report.critical)}
  - High:     {len(report.high)}
  - Medium:   {len(report.medium)}
  - Low:      {len(report.low)}
  - Info:     {len(report.informational)}
  - Total:    {report.total}
""")

    # Print findings as JSON for ThirdGen dashboard to parse from logs
    all_findings = report.critical + report.high + report.medium + report.low + report.informational
    findings_json = []
    for f in all_findings:
        severity = f.severity.lower()
        if severity == "informational":
            severity = "info"
        findings_json.append({
            "severity": severity,
            "title": f.title,
            "detector_id": f.id,
            "file_path": f.file,
            "line_start": f.line,
            "line_end": f.end_line or f.line,
            "tool": f.tool,
            "description": f.description,
            "ai_analysis": f.impact if f.ai_analyzed else "",
            "attack_scenario": f.attack_scenario,
            "suggested_fix": f.suggested_fix,
            "is_false_positive": f.is_false_positive,
        })

    print("\n" + "=" * 60)
    print("THIRDGEN_FINDINGS_START")
    print(json.dumps({
        "summary": {
            "critical": len(report.critical),
            "high": len(report.high),
            "medium": len(report.medium),
            "low": len(report.low),
            "info": len(report.informational),
        },
        "findings": findings_json
    }))
    print("THIRDGEN_FINDINGS_END")
    print("=" * 60)

    # Generate and save full report
    full_report = generate_report(report, config)

    output_path = args.output or config.get("report", {}).get("output", "results/report.md")
    Path(output_path).parent.mkdir(parents=True, exist_ok=True)

    with open(output_path, "w", encoding="utf-8") as f:
        f.write(full_report)

    log.info(f"Report saved to: {output_path}")

    # Post to GitHub
    if not args.no_github and config.get("github", {}).get("post_comment", True):
        pr_comment = generate_pr_comment(report, config)
        post_to_github(pr_comment)

        # Post inline comments on specific lines
        if config.get("github", {}).get("inline_comments", True):
            github_token = os.getenv("GITHUB_TOKEN")
            if github_token:
                post_review_comments(report, github_token)

    print("\n" + "=" * 60)
    print("  SCAN COMPLETE")
    print("=" * 60)

    sys.exit(0)


if __name__ == "__main__":
    main()

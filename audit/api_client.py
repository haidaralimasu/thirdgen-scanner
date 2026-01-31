#!/usr/bin/env python3
"""
ThirdGen API Client
Sends scan results to the ThirdGen dashboard
"""

import logging
import os
from typing import Optional

import requests

from .models import AuditReport

log = logging.getLogger(__name__)

# Environment variables
THIRDGEN_API_KEY = os.getenv("THIRDGEN_API_KEY")
THIRDGEN_API_URL = os.getenv("THIRDGEN_API_URL", "https://api.thirdgen.security/api")
GITHUB_REPOSITORY = os.getenv("GITHUB_REPOSITORY")
GITHUB_SHA = os.getenv("GITHUB_SHA")
GITHUB_REF = os.getenv("GITHUB_REF", "")
GITHUB_ACTOR = os.getenv("GITHUB_ACTOR", "")


def get_pr_number() -> Optional[int]:
    """Extract PR number from GITHUB_REF if this is a pull request"""
    if "/pull/" in GITHUB_REF:
        try:
            return int(GITHUB_REF.split("/")[-2])
        except (ValueError, IndexError):
            pass
    return None


def get_branch() -> str:
    """Extract branch name from GITHUB_REF"""
    if GITHUB_REF.startswith("refs/heads/"):
        return GITHUB_REF.replace("refs/heads/", "")
    elif GITHUB_REF.startswith("refs/pull/"):
        # For PRs, try to get the head branch from env
        return os.getenv("GITHUB_HEAD_REF", "")
    return GITHUB_REF


def get_trigger_type() -> str:
    """Determine the trigger type based on GITHUB_REF"""
    event_name = os.getenv("GITHUB_EVENT_NAME", "")
    if event_name == "pull_request":
        return "pull_request"
    elif event_name == "push":
        return "push"
    elif event_name == "schedule":
        return "scheduled"
    elif event_name == "workflow_dispatch":
        return "manual"
    return "push"


def send_results_to_dashboard(report: AuditReport) -> bool:
    """
    Send scan results to ThirdGen dashboard.

    Returns True if successful, False otherwise.
    """
    if not THIRDGEN_API_KEY:
        log.info("ThirdGen: No API key provided, skipping dashboard integration")
        return False

    if not GITHUB_REPOSITORY:
        log.warning("ThirdGen: GITHUB_REPOSITORY not set, cannot send results")
        return False

    if not GITHUB_SHA:
        log.warning("ThirdGen: GITHUB_SHA not set, cannot send results")
        return False

    # Build findings payload
    all_findings = (
        report.critical + report.high + report.medium +
        report.low + report.informational
    )

    findings_payload = []
    for f in all_findings:
        severity = f.severity.lower()
        if severity == "informational":
            severity = "info"

        findings_payload.append({
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

    # Build request payload
    payload = {
        "api_key": THIRDGEN_API_KEY,
        "repo": GITHUB_REPOSITORY,
        "commit_sha": GITHUB_SHA,
        "branch": get_branch(),
        "pr_number": get_pr_number(),
        "trigger": get_trigger_type(),
        "triggered_by": GITHUB_ACTOR,
        "summary": {
            "critical": len(report.critical),
            "high": len(report.high),
            "medium": len(report.medium),
            "low": len(report.low),
            "info": len(report.informational),
        },
        "findings": findings_payload,
    }

    # Send to dashboard
    webhook_url = f"{THIRDGEN_API_URL.rstrip('/')}/scans/webhook/"

    try:
        log.info(f"ThirdGen: Sending {len(findings_payload)} findings to dashboard...")

        response = requests.post(
            webhook_url,
            json=payload,
            headers={"Content-Type": "application/json"},
            timeout=30,
        )

        if response.status_code == 201:
            data = response.json()
            scan_id = data.get("scan_id", "unknown")
            log.info(f"ThirdGen: Results sent successfully (scan_id: {scan_id})")
            print(f"\n[ThirdGen] View results: https://app.thirdgen.security/scans/{scan_id}")
            return True
        else:
            error_msg = response.text[:200] if response.text else "Unknown error"
            log.error(f"ThirdGen: Failed to send results ({response.status_code}): {error_msg}")
            return False

    except requests.Timeout:
        log.error("ThirdGen: Request timed out")
        return False
    except requests.RequestException as e:
        log.error(f"ThirdGen: Request failed: {e}")
        return False

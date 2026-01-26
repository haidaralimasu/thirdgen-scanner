"""
ThirdGen Security Scanner - GitHub Inline Comments
Posts comments directly on the lines where issues are found
"""

import logging
import os
import re
from typing import Optional

import requests

from .models import Finding, AuditReport

log = logging.getLogger(__name__)

GITHUB_API = "https://api.github.com"


def get_pr_info() -> Optional[tuple[str, str, int]]:
    """Extract owner, repo, and PR number from environment"""
    github_repo = os.getenv("GITHUB_REPOSITORY")  # owner/repo
    github_ref = os.getenv("GITHUB_REF", "")  # refs/pull/123/merge

    if not github_repo or "/pull/" not in github_ref:
        return None

    try:
        owner, repo = github_repo.split("/")
        pr_number = int(github_ref.split("/")[2])
        return owner, repo, pr_number
    except (ValueError, IndexError):
        return None


def get_changed_files(owner: str, repo: str, pr_number: int, token: str) -> dict[str, str]:
    """Get files changed in the PR with their SHA"""
    url = f"{GITHUB_API}/repos/{owner}/{repo}/pulls/{pr_number}/files"
    headers = {
        "Authorization": f"token {token}",
        "Accept": "application/vnd.github.v3+json"
    }

    try:
        response = requests.get(url, headers=headers, timeout=15)
        if response.status_code == 200:
            files = {}
            for f in response.json():
                files[f["filename"]] = f.get("sha", "")
            return files
    except requests.RequestException as e:
        log.warning(f"Failed to get PR files: {e}")

    return {}


def get_commit_sha() -> str:
    """Get the current commit SHA"""
    return os.getenv("GITHUB_SHA", "")


def post_review_comments(report: AuditReport, token: str) -> bool:
    """Post inline comments on PR for each finding"""
    pr_info = get_pr_info()
    if not pr_info:
        log.info("GitHub inline: not a PR, skipping inline comments")
        return False

    owner, repo, pr_number = pr_info
    commit_sha = get_commit_sha()

    if not commit_sha:
        log.warning("GitHub inline: no commit SHA found")
        return False

    # Get changed files in PR
    changed_files = get_changed_files(owner, repo, pr_number, token)
    if not changed_files:
        log.warning("GitHub inline: couldn't get changed files")
        return False

    # Collect comments for findings in changed files
    comments = []

    all_findings = report.critical + report.high + report.medium + report.low

    for finding in all_findings:
        # Normalize file path (remove leading ./ or src/ variations)
        file_path = finding.file.lstrip("./")

        # Check if file was changed in this PR
        matched_file = None
        for changed_file in changed_files:
            if changed_file.endswith(file_path) or file_path.endswith(changed_file):
                matched_file = changed_file
                break

        if not matched_file:
            continue

        if finding.line <= 0:
            continue

        # Build comment body
        severity_emoji = {
            "critical": "🔴",
            "high": "🟠",
            "medium": "🟡",
            "low": "⚪"
        }.get(finding.severity.lower(), "ℹ️")

        body = f"{severity_emoji} **{finding.severity.upper()}:** {finding.title}\n\n"
        body += f"**Tool:** {finding.tool}\n\n"

        if finding.description:
            desc = finding.description[:300]
            if len(finding.description) > 300:
                desc += "..."
            body += f"{desc}\n\n"

        if finding.attack_scenario and finding.attack_scenario != "N/A":
            body += f"**Attack Scenario:** {finding.attack_scenario[:200]}\n\n"

        if finding.suggested_fix:
            body += f"**Suggested Fix:**\n```solidity\n{finding.suggested_fix[:300]}\n```\n"

        comments.append({
            "path": matched_file,
            "line": finding.line,
            "body": body
        })

    if not comments:
        log.info("GitHub inline: no findings in changed files")
        return True

    # Post as a review with all comments
    url = f"{GITHUB_API}/repos/{owner}/{repo}/pulls/{pr_number}/reviews"
    headers = {
        "Authorization": f"token {token}",
        "Accept": "application/vnd.github.v3+json"
    }

    # Limit to 20 comments max to avoid spam
    comments = comments[:20]

    review_body = f"🔒 **ThirdGen Security Scanner** found {len(comments)} issue(s) in changed files."

    payload = {
        "commit_id": commit_sha,
        "body": review_body,
        "event": "COMMENT",
        "comments": comments
    }

    try:
        response = requests.post(url, json=payload, headers=headers, timeout=30)
        if response.status_code == 200:
            log.info(f"GitHub inline: posted {len(comments)} inline comments")
            return True
        else:
            log.warning(f"GitHub inline: failed to post review - {response.status_code}: {response.text[:200]}")
    except requests.RequestException as e:
        log.error(f"GitHub inline: API error - {e}")

    return False

"""
ThirdGen Security Scanner - Finding Aggregator
Combines and deduplicates findings from multiple tools
"""

import logging
from typing import Any

from .models import Finding

log = logging.getLogger(__name__)


def aggregate_findings(all_findings: list[Finding]) -> list[Finding]:
    """
    Aggregate findings from multiple tools:
    1. Deduplicate by file + line + id
    2. Keep higher severity when duplicates found
    3. Sort by severity (critical first)
    """
    if not all_findings:
        return []

    # Deduplicate by key
    seen: dict[str, Finding] = {}

    for finding in all_findings:
        key = finding.dedup_key()

        if key not in seen:
            seen[key] = finding
        else:
            # Keep the one with higher severity
            existing = seen[key]
            if finding.severity_rank > existing.severity_rank:
                seen[key] = finding
            elif finding.severity_rank == existing.severity_rank:
                # Same severity - merge tool info
                if finding.tool not in existing.tool:
                    existing.tool = f"{existing.tool}, {finding.tool}"

    deduped = list(seen.values())

    # Sort by severity (highest first), then by file/line
    deduped.sort(key=lambda x: (-x.severity_rank, x.file, x.line))

    log.info(f"Aggregated: {len(all_findings)} raw -> {len(deduped)} deduplicated")

    return deduped


def filter_by_severity(findings: list[Finding], exclude: list[str]) -> list[Finding]:
    """Filter out findings with specified severities"""
    if not exclude:
        return findings

    exclude_lower = [s.lower() for s in exclude]
    return [f for f in findings if f.severity.lower() not in exclude_lower]


def group_by_file(findings: list[Finding]) -> dict[str, list[Finding]]:
    """Group findings by file path"""
    grouped: dict[str, list[Finding]] = {}

    for finding in findings:
        if finding.file not in grouped:
            grouped[finding.file] = []
        grouped[finding.file].append(finding)

    return grouped


def group_by_severity(findings: list[Finding]) -> dict[str, list[Finding]]:
    """Group findings by severity level"""
    grouped: dict[str, list[Finding]] = {
        "critical": [],
        "high": [],
        "medium": [],
        "low": [],
        "informational": []
    }

    for finding in findings:
        sev = finding.severity.lower()
        if sev in grouped:
            grouped[sev].append(finding)
        else:
            grouped["informational"].append(finding)

    return grouped


def get_statistics(findings: list[Finding]) -> dict[str, Any]:
    """Calculate statistics about findings"""
    grouped = group_by_severity(findings)

    tools_used = set(f.tool for f in findings)
    files_affected = set(f.file for f in findings)

    return {
        "total": len(findings),
        "by_severity": {k: len(v) for k, v in grouped.items()},
        "tools_used": list(tools_used),
        "files_affected": len(files_affected),
        "critical_count": len(grouped["critical"]),
        "high_count": len(grouped["high"]),
    }

"""
Slither output parser
"""

import json
from typing import Any

from ..models import Finding


def parse_slither(output: str, severity_map: dict[str, str], exclude_paths: list[str]) -> list[Finding]:
    """Parse Slither JSON output"""
    if not output:
        return []

    findings = []

    try:
        # Find JSON in output (Slither may include other text)
        json_start = output.find("{")
        json_end = output.rfind("}") + 1

        if json_start == -1 or json_end == 0:
            return []

        data = json.loads(output[json_start:json_end])
        detectors = data.get("results", {}).get("detectors", [])

        for detector in detectors:
            elements = detector.get("elements", [])
            if not elements:
                continue

            source_mapping = elements[0].get("source_mapping", {})
            file_path = source_mapping.get("filename_relative", "")

            # Skip excluded paths
            if any(exc in file_path for exc in exclude_paths):
                continue

            lines_list = source_mapping.get("lines", [0])
            start_line = lines_list[0] if lines_list else 0
            end_line = lines_list[-1] if lines_list else start_line

            raw_severity = detector.get("impact", "Low")
            normalized_severity = severity_map.get(raw_severity, "medium")

            findings.append(Finding(
                id=detector.get("check", "unknown"),
                title=detector.get("check", "").replace("-", " ").title(),
                severity=normalized_severity,
                file=file_path,
                line=start_line,
                end_line=end_line,
                tool="slither",
                description=detector.get("description", "").strip(),
                raw=detector
            ))

    except json.JSONDecodeError:
        pass

    return findings

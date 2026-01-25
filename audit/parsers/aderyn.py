"""
Aderyn output parser
"""

import json
from pathlib import Path
from typing import Any

from ..models import Finding


def parse_aderyn(filepath: str, severity_map: dict[str, str], exclude_paths: list[str]) -> list[Finding]:
    """Parse Aderyn JSON output file"""
    if not filepath or not Path(filepath).exists():
        return []

    findings = []

    try:
        data = json.loads(Path(filepath).read_text())

        severity_mapping = {
            "critical_issues": "Critical",
            "high_issues": "High",
            "medium_issues": "Medium",
            "low_issues": "Low",
        }

        for key, raw_severity in severity_mapping.items():
            section = data.get(key, {})
            items = section.get("issues", []) if isinstance(section, dict) else []

            for item in items:
                instances = item.get("instances", [])
                if not instances:
                    continue

                first_instance = instances[0]
                file_path = first_instance.get("contract_path", "")

                # Skip excluded paths
                if any(exc in file_path for exc in exclude_paths):
                    continue

                line_num = first_instance.get("line_no", 0)
                normalized_severity = severity_map.get(raw_severity, "medium")

                findings.append(Finding(
                    id=item.get("detector_name", item.get("title", "unknown")),
                    title=item.get("title", ""),
                    severity=normalized_severity,
                    file=file_path,
                    line=line_num,
                    end_line=line_num,
                    tool="aderyn",
                    description=item.get("description", "").strip(),
                    raw=item,
                    instances=len(instances)
                ))

    except (json.JSONDecodeError, IOError):
        pass

    return findings

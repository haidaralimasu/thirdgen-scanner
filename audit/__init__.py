"""
ThirdGen Smart Contract Security Scanner
Multi-tool audit pipeline with AI enhancement
"""

from .models import AuditReport, Finding
from .aggregator import aggregate_findings
from .ai_enhancer import enhance_findings
from .report_generator import generate_report, generate_pr_comment

__version__ = "2.0.0"
__all__ = [
    "AuditReport",
    "Finding",
    "aggregate_findings",
    "enhance_findings",
    "generate_report",
    "generate_pr_comment",
]

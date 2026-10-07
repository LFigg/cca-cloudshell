"""
Report generation modules for CCA CloudShell.

Each module generates one Excel/JSON deliverable from collected CCA
inventory/summary JSON:
- assessment: Full assessment report (Excel, all clouds)
- m365: M365-specific report (Excel)
- cost: Cost report (Excel)
- sizer: Cohesity Reverse Sizer JSON generation

Usage:
    from lib.reports import (
        generate_assessment_report,
        generate_m365_report,
        generate_cost_report,
        generate_sizer_json,
    )
"""

from .assessment import generate_report as generate_assessment_report
from .cost import generate_excel_report as generate_cost_report
from .m365 import generate_report as generate_m365_report
from .sizer import generate_sizer_json

__all__ = [
    'generate_assessment_report',
    'generate_m365_report',
    'generate_cost_report',
    'generate_sizer_json',
]

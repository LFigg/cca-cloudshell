"""Raw Data tab: full resource inventory for reference."""
from typing import Dict, List

from openpyxl import Workbook
from openpyxl.styles import Font

from ..analysis import (
    get_provider,
)
from ..excel_helpers import (
    set_column_widths,
    write_data_row,
    write_header_row,
)
from ..styles import (
    PROVIDER_COLORS,
    TITLE_FONT,
)


def generate_raw_data(wb: Workbook, resources: List[Dict]) -> None:
    """Generate Raw Data tab."""
    ws = wb.create_sheet(title="Raw Data")

    row = 1

    # Title
    ws.cell(row=row, column=1, value="Raw Resource Inventory").font = TITLE_FONT
    ws.cell(row=row + 1, column=1, value=f"Total resources: {len(resources)}")
    row += 3

    # Headers
    headers = [
        "Provider", "Account", "Region", "Resource Type", "Resource Name",
        "Resource ID", "Size (GB)", "Service Family", "Created", "Tags"
    ]
    write_header_row(ws, row, headers)
    row += 1

    # Sort resources by provider, then type
    sorted_resources = sorted(
        resources,
        key=lambda x: (get_provider(x.get('resource_type', '')), x.get('resource_type', ''))
    )

    for r in sorted_resources:
        tags = r.get('tags', {}) or {}
        tags_str = '; '.join(f"{k}={v}" for k, v in tags.items()) if tags else ''

        metadata = r.get('metadata', {}) or {}
        created = metadata.get('created', metadata.get('creation_date',
                   metadata.get('launch_time', '')))

        write_data_row(ws, row, [
            get_provider(r.get('resource_type', '')),
            r.get('account_id', ''),
            r.get('region', ''),
            r.get('resource_type', ''),
            r.get('name', ''),
            r.get('resource_id', ''),
            r.get('size_gb', ''),
            r.get('service_family', ''),
            created,
            tags_str[:200]  # Truncate long tags
        ])

        # Color by provider
        provider = get_provider(r.get('resource_type', ''))
        if provider in PROVIDER_COLORS:
            ws.cell(row=row, column=1).fill = PROVIDER_COLORS[provider]
            ws.cell(row=row, column=1).font = Font(color="FFFFFF")

        row += 1

    # Set column widths
    set_column_widths(ws, {
        'A': 12, 'B': 20, 'C': 15, 'D': 30, 'E': 30,
        'F': 45, 'G': 12, 'H': 15, 'I': 20, 'J': 60
    })

    ws.freeze_panes = 'A4'
    if resources:
        ws.auto_filter.ref = f"A3:J{row - 1}"



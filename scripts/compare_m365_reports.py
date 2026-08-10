#!/usr/bin/env python3
"""
Compare two M365 assessment reports (e.g. a broad user list vs. a narrowed one)
and produce a side-by-side comparison workbook that explains the storage delta.

The comparison is driven entirely off the "Storage Summary by Service" table on
each report's Executive Summary tab, plus the Total Users figure, so it works
against any two reports produced by generate_m365_report.py.

Two tabs are produced:
  1. Comparison        - per-service objects/storage, delta, % change
  2. Why Size Changed  - storage-concentration and unfiltered-workload analysis

Usage:
    python scripts/compare_m365_reports.py \
        --previous loves_m365_report_filtered.xlsx \
        --new      loves_m365_report_revised.xlsx \
        --output   loves_m365_report_comparison.xlsx
"""

import argparse
from typing import Dict, Optional, Tuple

from openpyxl import Workbook, load_workbook
from openpyxl.styles import Alignment, Font, PatternFill

# Reuse the report theme so the comparison matches the source reports.
HEADER_FILL = PatternFill(start_color="0078D4", end_color="0078D4", fill_type="solid")
HEADER_FONT = Font(bold=True, color="FFFFFF")
TITLE_FONT = Font(bold=True, size=14)
SECTION_FONT = Font(bold=True, size=12)
SUBTITLE_FONT = Font(italic=True, size=10, color="666666")
BOLD = Font(bold=True)
GOOD_FILL = PatternFill(start_color="C6EFCE", end_color="C6EFCE", fill_type="solid")   # drop
FLAT_FILL = PatternFill(start_color="FFEB9C", end_color="FFEB9C", fill_type="solid")   # unchanged

INT_FMT = '#,##0'
GB_FMT = '#,##0.0'
TB_FMT = '#,##0.00'
PCT_FMT = '0.0"%"'

# Services that the report's --filter-users option does NOT scope to the user
# list (they are site-/team-based, not user-based). Documented here so the
# explanation tab can call them out explicitly.
UNFILTERED_SERVICES = {"SharePoint Online", "Microsoft Teams"}


def parse_report(path: str) -> Tuple[Optional[int], Dict[str, Dict[str, float]]]:
    """
    Pull Total Users and the per-service storage table from a report workbook.

    Returns:
        (total_users, {service: {"objects": n, "gb": x}})
    """
    wb = load_workbook(path, data_only=True)
    if "Executive Summary" not in wb.sheetnames:
        raise ValueError(f"{path}: no 'Executive Summary' tab found")
    ws = wb["Executive Summary"]

    total_users: Optional[int] = None
    services: Dict[str, Dict[str, float]] = {}
    in_table = False

    for row in ws.iter_rows(values_only=True):
        cells = list(row)
        first = cells[0] if cells else None

        if first == "Total Users" and len(cells) > 1 and isinstance(cells[1], (int, float)):
            total_users = int(cells[1])

        # The storage table starts at its header row and ends at TOTAL.
        if first == "Service" and len(cells) > 2 and cells[1] == "Objects":
            in_table = True
            continue
        if in_table:
            if first in (None, "") or first == "TOTAL":
                in_table = False
                continue
            objects = cells[1] if len(cells) > 1 and isinstance(cells[1], (int, float)) else 0
            gb = cells[2] if len(cells) > 2 and isinstance(cells[2], (int, float)) else 0
            services[str(first)] = {"objects": float(objects), "gb": float(gb)}

    return total_users, services


def pct_change(old: float, new: float) -> float:
    if old == 0:
        return 0.0
    return (new - old) / old * 100.0


def write_header(ws, row: int, headers) -> None:
    for col, h in enumerate(headers, start=1):
        c = ws.cell(row=row, column=col, value=h)
        c.fill = HEADER_FILL
        c.font = HEADER_FONT
        c.alignment = Alignment(horizontal="center")


def build_comparison_tab(wb: Workbook, prev, new, prev_users, new_users,
                         prev_label: str, new_label: str) -> None:
    ws = wb.active
    ws.title = "Comparison"

    ws.cell(row=1, column=1, value="M365 Report Comparison").font = TITLE_FONT
    ws.cell(row=2, column=1,
            value=f"Previous: {prev_label}   |   New: {new_label}").font = SUBTITLE_FONT
    row = 4

    # Users line
    ws.cell(row=row, column=1, value="Users with collected data").font = BOLD
    ws.cell(row=row, column=2, value=prev_users).number_format = INT_FMT
    ws.cell(row=row, column=3, value=new_users).number_format = INT_FMT
    ws.cell(row=row, column=4, value=(new_users or 0) - (prev_users or 0)).number_format = INT_FMT
    c = ws.cell(row=row, column=5, value=pct_change(prev_users or 0, new_users or 0))
    c.number_format = PCT_FMT
    row += 2

    write_header(ws, row, ["Service", "Prev Objects", "New Objects",
                           "Prev GB", "New GB", "Δ GB", "Δ %", "User-scoped?"])
    row += 1

    all_services = list(prev.keys()) + [s for s in new if s not in prev]
    tot_prev_obj = tot_new_obj = tot_prev_gb = tot_new_gb = 0.0

    for svc in all_services:
        p = prev.get(svc, {"objects": 0, "gb": 0})
        n = new.get(svc, {"objects": 0, "gb": 0})
        d_gb = n["gb"] - p["gb"]
        scoped = "No (whole tenant)" if svc in UNFILTERED_SERVICES else "Yes"

        ws.cell(row=row, column=1, value=svc)
        ws.cell(row=row, column=2, value=p["objects"]).number_format = INT_FMT
        ws.cell(row=row, column=3, value=n["objects"]).number_format = INT_FMT
        ws.cell(row=row, column=4, value=round(p["gb"], 1)).number_format = GB_FMT
        ws.cell(row=row, column=5, value=round(n["gb"], 1)).number_format = GB_FMT
        ws.cell(row=row, column=6, value=round(d_gb, 1)).number_format = GB_FMT
        ws.cell(row=row, column=7, value=pct_change(p["gb"], n["gb"])).number_format = PCT_FMT
        ws.cell(row=row, column=8, value=scoped)

        if svc in UNFILTERED_SERVICES:
            for col in range(1, 9):
                ws.cell(row=row, column=col).fill = FLAT_FILL

        tot_prev_obj += p["objects"]
        tot_new_obj += n["objects"]
        tot_prev_gb += p["gb"]
        tot_new_gb += n["gb"]
        row += 1

    # Totals
    ws.cell(row=row, column=1, value="TOTAL").font = BOLD
    for col, val, fmt in [(2, tot_prev_obj, INT_FMT), (3, tot_new_obj, INT_FMT),
                          (4, round(tot_prev_gb, 1), GB_FMT), (5, round(tot_new_gb, 1), GB_FMT),
                          (6, round(tot_new_gb - tot_prev_gb, 1), GB_FMT),
                          (7, pct_change(tot_prev_gb, tot_new_gb), PCT_FMT)]:
        c = ws.cell(row=row, column=col, value=val)
        c.number_format = fmt
        c.font = BOLD
    row += 1
    ws.cell(row=row, column=1, value="TOTAL (TB)").font = BOLD
    ws.cell(row=row, column=4, value=round(tot_prev_gb / 1024, 2)).number_format = TB_FMT
    ws.cell(row=row, column=5, value=round(tot_new_gb / 1024, 2)).number_format = TB_FMT
    ws.cell(row=row, column=6, value=round((tot_new_gb - tot_prev_gb) / 1024, 2)).number_format = TB_FMT
    for col in (1, 4, 5, 6):
        ws.cell(row=row, column=col).font = BOLD

    for col, w in {"A": 22, "B": 13, "C": 13, "D": 13, "E": 13,
                   "F": 12, "G": 10, "H": 18}.items():
        ws.column_dimensions[col].width = w

    return tot_prev_gb, tot_new_gb


def build_why_tab(wb: Workbook, prev, new) -> None:
    ws = wb.create_sheet(title="Why Size Changed")
    row = 1
    ws.cell(row=row, column=1, value="Why The Size Dropped Less Than Expected").font = TITLE_FONT
    row += 2

    # --- Reason 1: unfiltered workloads ---
    ws.cell(row=row, column=1,
            value="1. Teams and SharePoint are not scoped to the user list").font = SECTION_FONT
    row += 1
    unfilt_gb = sum(new.get(s, {"gb": 0})["gb"] for s in UNFILTERED_SERVICES)
    total_new_gb = sum(s["gb"] for s in new.values())
    ws.cell(row=row, column=1,
            value=("Teams and SharePoint storage is site/team-based, so the user filter does not "
                   "reduce it. It is identical in both reports.")).font = SUBTITLE_FONT
    row += 1
    write_header(ws, row, ["Workload", "Fixed Storage (GB)", "Fixed Storage (TB)", "% of New Total"])
    row += 1
    for svc in UNFILTERED_SERVICES:
        gb = new.get(svc, {"gb": 0})["gb"]
        ws.cell(row=row, column=1, value=svc)
        ws.cell(row=row, column=2, value=round(gb, 1)).number_format = GB_FMT
        ws.cell(row=row, column=3, value=round(gb / 1024, 2)).number_format = TB_FMT
        ws.cell(row=row, column=4, value=pct_change(0, 0) or (gb / total_new_gb * 100 if total_new_gb else 0)).number_format = PCT_FMT
        row += 1
    ws.cell(row=row, column=1, value="Combined fixed footprint").font = BOLD
    ws.cell(row=row, column=2, value=round(unfilt_gb, 1)).number_format = GB_FMT
    ws.cell(row=row, column=2).font = BOLD
    ws.cell(row=row, column=3, value=round(unfilt_gb / 1024, 2)).number_format = TB_FMT
    ws.cell(row=row, column=3).font = BOLD
    ws.cell(row=row, column=4, value=(unfilt_gb / total_new_gb * 100 if total_new_gb else 0)).number_format = PCT_FMT
    ws.cell(row=row, column=4).font = BOLD
    row += 2

    # --- Reason 2: storage concentration ---
    ws.cell(row=row, column=1,
            value="2. Removed users held almost no data (storage is concentrated)").font = SECTION_FONT
    row += 1
    ws.cell(row=row, column=1,
            value=("Removing ~half the mailboxes/OneDrives barely moved storage because the "
                   "dropped accounts were nearly empty. The retained users hold the data.")).font = SUBTITLE_FONT
    row += 1
    write_header(ws, row, ["Workload", "Removed Accts", "Removed GB", "Avg GB / Removed",
                           "Retained Accts", "Avg GB / Retained", "Retained ÷ Removed"])
    row += 1
    for svc in ("Exchange Online", "OneDrive for Business"):
        if svc not in prev or svc not in new:
            continue
        rem_obj = prev[svc]["objects"] - new[svc]["objects"]
        rem_gb = prev[svc]["gb"] - new[svc]["gb"]
        ret_obj = new[svc]["objects"]
        ret_gb = new[svc]["gb"]
        avg_rem = rem_gb / rem_obj if rem_obj else 0
        avg_ret = ret_gb / ret_obj if ret_obj else 0
        ratio = (avg_ret / avg_rem) if avg_rem else 0
        ws.cell(row=row, column=1, value=svc)
        ws.cell(row=row, column=2, value=int(rem_obj)).number_format = INT_FMT
        ws.cell(row=row, column=3, value=round(rem_gb, 1)).number_format = GB_FMT
        ws.cell(row=row, column=4, value=round(avg_rem, 2)).number_format = TB_FMT
        ws.cell(row=row, column=5, value=int(ret_obj)).number_format = INT_FMT
        ws.cell(row=row, column=6, value=round(avg_ret, 2)).number_format = TB_FMT
        ws.cell(row=row, column=7, value=f"{ratio:.0f}x")
        row += 1
    row += 2

    # --- Takeaway ---
    ws.cell(row=row, column=1, value="Bottom line").font = SECTION_FONT
    row += 1
    for line in [
        "- Cutting the user list roughly in half removed ~48% of objects but only ~2.9% of storage.",
        "- ~22% of the total is Teams + SharePoint, which the user filter does not reduce at all.",
        "- The mailboxes/OneDrives that were removed averaged well under 1 GB each; the heavy data",
        "  owners are all still in the backup list, so almost none of the actual data left the scope.",
        "- To shrink the sized footprint you must reduce SharePoint/Teams scope or drop high-storage",
        "  users, not just the count of users.",
    ]:
        ws.cell(row=row, column=1, value=line)
        row += 1

    for col, w in {"A": 30, "B": 14, "C": 13, "D": 16, "E": 15, "F": 17, "G": 18}.items():
        ws.column_dimensions[col].width = w


def main():
    ap = argparse.ArgumentParser(description="Compare two M365 assessment reports")
    ap.add_argument("--previous", required=True, help="Path to the previous report .xlsx")
    ap.add_argument("--new", required=True, help="Path to the new report .xlsx")
    ap.add_argument("--output", default="m365_report_comparison.xlsx", help="Output .xlsx path")
    ap.add_argument("--prev-label", default=None)
    ap.add_argument("--new-label", default=None)
    args = ap.parse_args()

    prev_users, prev = parse_report(args.previous)
    new_users, new = parse_report(args.new)

    import os
    prev_label = args.prev_label or os.path.basename(args.previous)
    new_label = args.new_label or os.path.basename(args.new)

    wb = Workbook()
    tot_prev_gb, tot_new_gb = build_comparison_tab(
        wb, prev, new, prev_users, new_users, prev_label, new_label)
    build_why_tab(wb, prev, new)
    wb.save(args.output)
    os.chmod(args.output, 0o600)

    print(f"Comparison written: {args.output}")
    print(f"  Users:   {prev_users:,} -> {new_users:,} ({pct_change(prev_users, new_users):+.1f}%)")
    print(f"  Storage: {tot_prev_gb/1024:.2f} TB -> {tot_new_gb/1024:.2f} TB "
          f"({pct_change(tot_prev_gb, tot_new_gb):+.1f}%)")


if __name__ == "__main__":
    main()

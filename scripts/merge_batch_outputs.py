#!/usr/bin/env python3
"""
CCA CloudShell - Merge Batch Outputs

Merges multiple batch collection outputs into a single unified output.
Use this when collections were split into batches due to credential timeouts
or large account counts.

Usage:
    # Merge all batches in subdirectories into parent folder
    python scripts/merge_batch_outputs.py ./org-folder/
    
    # Merge specific batch folders
    python scripts/merge_batch_outputs.py ./batch1/ ./batch2/ ./batch3/ -o ./merged/
    
    # Dry run to see what would be merged
    python scripts/merge_batch_outputs.py ./org-folder/ --dry-run
    
    # Process multiple orgs at once
    python scripts/merge_batch_outputs.py ./customer-org1/ ./customer-org2/ --per-folder
"""

import argparse
import json
import os
import sys
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Dict, Any, Optional, Tuple

# Add parent to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))
from lib.utils import generate_run_id, get_timestamp, write_json, write_csv


def find_inventory_files(folder: Path) -> List[Path]:
    """Find all inventory JSON files in folder and subfolders."""
    inv_files = []
    
    # Check root folder - match both cca_*_inv_*.json and cca_inv_*.json patterns
    for pattern in ["cca_*_inv_*.json", "cca_inv_*.json"]:
        for f in folder.glob(pattern):
            if f not in inv_files:
                inv_files.append(f)
    
    # Check subfolders (batch folders)
    for subfolder in folder.iterdir():
        if subfolder.is_dir() and not subfolder.name.startswith('.'):
            for pattern in ["cca_*_inv_*.json", "cca_inv_*.json"]:
                for f in subfolder.glob(pattern):
                    if f not in inv_files:
                        inv_files.append(f)
    
    return sorted(inv_files)


def find_summary_files(folder: Path) -> List[Path]:
    """Find all summary JSON files in folder and subfolders."""
    sum_files = []
    
    # Check root folder
    for pattern in ["cca_*_sum_*.json", "cca_sum_*.json"]:
        for f in folder.glob(pattern):
            if f not in sum_files:
                sum_files.append(f)
    
    # Check subfolders
    for subfolder in folder.iterdir():
        if subfolder.is_dir() and not subfolder.name.startswith('.'):
            for pattern in ["cca_*_sum_*.json", "cca_sum_*.json"]:
                for f in subfolder.glob(pattern):
                    if f not in sum_files:
                        sum_files.append(f)
    
    return sorted(sum_files)


def find_cost_files(folder: Path) -> List[Path]:
    """Find all cost JSON files in folder and subfolders."""
    cost_files = []
    
    # Check root folder
    for pattern in ["cca_*_cost_*.json", "cca_cost_*.json", "*cost*.json"]:
        for f in folder.glob(pattern):
            if f not in cost_files:
                cost_files.append(f)
    
    # Check subfolders
    for subfolder in folder.iterdir():
        if subfolder.is_dir() and not subfolder.name.startswith('.'):
            for pattern in ["cca_*_cost_*.json", "cca_cost_*.json", "*cost*.json"]:
                for f in subfolder.glob(pattern):
                    if f not in cost_files:
                        cost_files.append(f)
    
    return sorted(cost_files)


def load_json_file(filepath: Path) -> Optional[Dict[str, Any]]:
    """Load a JSON file, returning None on error."""
    try:
        with open(filepath, 'r') as f:
            return json.load(f)
    except (json.JSONDecodeError, IOError) as e:
        print(f"  WARNING: Could not load {filepath}: {e}")
        return None


def merge_inventory_files(inv_files: List[Path]) -> Tuple[Dict[str, Any], Dict[str, int]]:
    """
    Merge multiple inventory JSON files into one.
    
    Returns:
        Tuple of (merged_data, stats_dict)
    """
    if not inv_files:
        return {}, {}
    
    merged = {
        "run_id": generate_run_id(),
        "timestamp": get_timestamp(),
        "provider": None,
        "account_id": [],
        "accounts": [],
        "regions": set(),
        "resource_count": 0,
        "total_capacity_gb": 0.0,
        "resources": [],
        "merge_info": {
            "merged_at": get_timestamp(),
            "source_files": [],
            "batch_count": len(inv_files)
        }
    }
    
    stats = {
        "files_processed": 0,
        "files_skipped": 0,
        "total_resources": 0,
        "duplicate_resources": 0,
        "accounts_found": 0
    }
    
    seen_resource_ids = set()
    seen_account_ids = set()
    
    for inv_file in inv_files:
        data = load_json_file(inv_file)
        if not data:
            stats["files_skipped"] += 1
            continue
        
        stats["files_processed"] += 1
        merged["merge_info"]["source_files"].append(str(inv_file))
        
        # Set provider from first file
        if merged["provider"] is None:
            merged["provider"] = data.get("provider", "aws")
        
        # Merge account IDs
        acct_ids = data.get("account_id", [])
        if isinstance(acct_ids, str):
            acct_ids = [acct_ids]
        for acct_id in acct_ids:
            if acct_id and acct_id not in seen_account_ids:
                seen_account_ids.add(acct_id)
                merged["account_id"].append(acct_id)
                stats["accounts_found"] += 1
        
        # Merge accounts array (with details)
        for acct in data.get("accounts", []):
            acct_id = acct.get("account_id")
            if acct_id and acct_id not in [a.get("account_id") for a in merged["accounts"]]:
                merged["accounts"].append(acct)
        
        # Merge regions
        regions = data.get("regions", [])
        if isinstance(regions, list):
            merged["regions"].update(regions)
        
        # Merge resources (deduplicate by resource_id)
        for resource in data.get("resources", []):
            resource_id = resource.get("resource_id", "")
            # Create a unique key using account + resource_id to handle cross-account
            unique_key = f"{resource.get('account_id', '')}:{resource_id}"
            
            if unique_key and unique_key not in seen_resource_ids:
                seen_resource_ids.add(unique_key)
                merged["resources"].append(resource)
                stats["total_resources"] += 1
            else:
                stats["duplicate_resources"] += 1
    
    # Convert regions set to sorted list
    merged["regions"] = sorted(merged["regions"])
    
    # Update totals
    merged["resource_count"] = len(merged["resources"])
    merged["total_capacity_gb"] = sum(
        r.get("size_gb", 0) or 0 for r in merged["resources"]
    )
    
    return merged, stats


def merge_summary_files(sum_files: List[Path], inv_data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Merge summary files by re-aggregating from merged inventory.
    
    This is more accurate than trying to merge summaries directly,
    as we need to re-sum resource counts per type.
    """
    if not inv_data or not inv_data.get("resources"):
        return {}
    
    # Aggregate summaries from merged inventory
    summary_map = defaultdict(lambda: {"count": 0, "total_gb": 0.0})
    
    for resource in inv_data.get("resources", []):
        resource_type = resource.get("resource_type", "unknown")
        service_family = resource.get("service_family", "Unknown")
        key = (resource_type, service_family)
        
        summary_map[key]["count"] += 1
        summary_map[key]["total_gb"] += resource.get("size_gb", 0) or 0
    
    # Build summaries array
    summaries = []
    for (resource_type, service_family), data in sorted(summary_map.items()):
        summaries.append({
            "provider": inv_data.get("provider", "aws"),
            "service_family": service_family,
            "resource_type": resource_type,
            "resource_count": data["count"],
            "total_gb": round(data["total_gb"], 2)
        })
    
    merged_summary = {
        "run_id": inv_data.get("run_id"),
        "timestamp": inv_data.get("timestamp"),
        "provider": inv_data.get("provider", "aws"),
        "account_id": inv_data.get("account_id", []),
        "accounts": inv_data.get("accounts", []),
        "total_resources": inv_data.get("resource_count", 0),
        "total_capacity_gb": round(inv_data.get("total_capacity_gb", 0), 2),
        "summaries": summaries,
        "merge_info": inv_data.get("merge_info")
    }
    
    return merged_summary


def merge_cost_files(cost_files: List[Path]) -> Tuple[Dict[str, Any], Dict[str, int]]:
    """
    Merge multiple cost JSON files into one.
    """
    if not cost_files:
        return {}, {}
    
    merged = {
        "run_id": generate_run_id(),
        "timestamp": get_timestamp(),
        "provider": None,
        "account_id": [],
        "start_date": None,
        "end_date": None,
        "total_cost": 0.0,
        "currency": "USD",
        "cost_by_service": defaultdict(float),
        "cost_by_account": defaultdict(float),
        "daily_costs": [],
        "merge_info": {
            "merged_at": get_timestamp(),
            "source_files": [],
            "batch_count": len(cost_files)
        }
    }
    
    stats = {
        "files_processed": 0,
        "files_skipped": 0
    }
    
    seen_account_ids = set()
    daily_cost_map = defaultdict(float)
    
    for cost_file in cost_files:
        data = load_json_file(cost_file)
        if not data:
            stats["files_skipped"] += 1
            continue
        
        stats["files_processed"] += 1
        merged["merge_info"]["source_files"].append(str(cost_file))
        
        # Set provider from first file
        if merged["provider"] is None:
            merged["provider"] = data.get("provider", "aws")
        
        # Track date range
        start = data.get("start_date")
        end = data.get("end_date")
        if start:
            if merged["start_date"] is None or start < merged["start_date"]:
                merged["start_date"] = start
        if end:
            if merged["end_date"] is None or end > merged["end_date"]:
                merged["end_date"] = end
        
        # Merge account IDs
        acct_ids = data.get("account_id", [])
        if isinstance(acct_ids, str):
            acct_ids = [acct_ids]
        for acct_id in acct_ids:
            if acct_id and acct_id not in seen_account_ids:
                seen_account_ids.add(acct_id)
                merged["account_id"].append(acct_id)
        
        # Sum costs by service
        for service, cost in data.get("cost_by_service", {}).items():
            merged["cost_by_service"][service] += cost
        
        # Sum costs by account
        for acct, cost in data.get("cost_by_account", {}).items():
            merged["cost_by_account"][acct] += cost
        
        # Aggregate daily costs
        for daily in data.get("daily_costs", []):
            date = daily.get("date")
            cost = daily.get("cost", 0)
            if date:
                daily_cost_map[date] += cost
    
    # Convert defaultdicts to regular dicts
    merged["cost_by_service"] = dict(merged["cost_by_service"])
    merged["cost_by_account"] = dict(merged["cost_by_account"])
    
    # Convert daily costs map to sorted list
    merged["daily_costs"] = [
        {"date": date, "cost": round(cost, 2)}
        for date, cost in sorted(daily_cost_map.items())
    ]
    
    # Calculate total
    merged["total_cost"] = round(sum(merged["cost_by_account"].values()), 2)
    
    return merged, stats


def generate_sizing_csv(inv_data: Dict[str, Any], output_path: Path) -> None:
    """Generate sizing CSV from merged inventory."""
    if not inv_data or not inv_data.get("resources"):
        return
    
    provider = inv_data.get("provider", "aws")
    
    # Prepare CSV rows
    rows = []
    for resource in inv_data.get("resources", []):
        rows.append({
            "provider": provider,
            "account_id": resource.get("account_id", ""),
            "region": resource.get("region", ""),
            "resource_type": resource.get("resource_type", ""),
            "service_family": resource.get("service_family", ""),
            "resource_id": resource.get("resource_id", ""),
            "name": resource.get("name", ""),
            "size_gb": resource.get("size_gb", 0),
        })
    
    # Sort by account, region, type
    rows.sort(key=lambda r: (r["account_id"], r["region"], r["resource_type"]))
    
    write_csv(rows, str(output_path))


def process_folder(
    folder: Path,
    output_dir: Optional[Path] = None,
    dry_run: bool = False
) -> Dict[str, Any]:
    """
    Process a single folder, merging all batch outputs found.
    
    Returns dict with processing results.
    """
    folder = Path(folder)
    if not folder.exists():
        return {"error": f"Folder not found: {folder}"}
    
    print(f"\n{'='*60}")
    print(f"Processing: {folder}")
    print(f"{'='*60}")
    
    # Find all files
    inv_files = find_inventory_files(folder)
    sum_files = find_summary_files(folder)
    cost_files = find_cost_files(folder)
    
    print(f"\nFound:")
    print(f"  - {len(inv_files)} inventory files")
    print(f"  - {len(sum_files)} summary files")
    print(f"  - {len(cost_files)} cost files")
    
    if not inv_files:
        print("  No inventory files found to merge.")
        return {"warning": "No inventory files found"}
    
    # List source files
    print(f"\nSource files:")
    for f in inv_files:
        print(f"  - {f.relative_to(folder)}")
    
    if dry_run:
        print(f"\n[DRY RUN] Would merge {len(inv_files)} files")
        return {"dry_run": True, "files": len(inv_files)}
    
    # Determine output directory
    if output_dir is None:
        output_dir = folder
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    
    results = {"folder": str(folder)}
    
    # Merge inventory files
    print(f"\nMerging inventory files...")
    merged_inv, inv_stats = merge_inventory_files(inv_files)
    
    if merged_inv:
        # Determine provider for filename
        provider = merged_inv.get("provider", "aws")
        timestamp = datetime.now(timezone.utc).strftime("%H%M%S")
        
        inv_path = output_dir / f"cca_{provider}_inv_{timestamp}_merged.json"
        write_json(merged_inv, str(inv_path))
        print(f"  Wrote: {inv_path.name}")
        print(f"  - {inv_stats['total_resources']} resources from {inv_stats['accounts_found']} accounts")
        if inv_stats['duplicate_resources'] > 0:
            print(f"  - {inv_stats['duplicate_resources']} duplicate resources removed")
        
        results["inventory"] = {
            "file": str(inv_path),
            "resources": inv_stats['total_resources'],
            "accounts": inv_stats['accounts_found'],
            "duplicates_removed": inv_stats['duplicate_resources']
        }
        
        # Generate summary from merged inventory
        print(f"\nGenerating summary...")
        merged_sum = merge_summary_files(sum_files, merged_inv)
        if merged_sum:
            sum_path = output_dir / f"cca_{provider}_sum_{timestamp}_merged.json"
            write_json(merged_sum, str(sum_path))
            print(f"  Wrote: {sum_path.name}")
            results["summary"] = {"file": str(sum_path)}
        
        # Generate sizing CSV
        print(f"\nGenerating sizing CSV...")
        csv_path = output_dir / f"cca_{provider}_sizing_merged.csv"
        generate_sizing_csv(merged_inv, csv_path)
        print(f"  Wrote: {csv_path.name}")
        results["sizing_csv"] = {"file": str(csv_path)}
    
    # Merge cost files if present
    if cost_files:
        print(f"\nMerging cost files...")
        merged_cost, cost_stats = merge_cost_files(cost_files)
        if merged_cost:
            provider = merged_cost.get("provider", "aws")
            timestamp = datetime.now(timezone.utc).strftime("%H%M%S")
            cost_path = output_dir / f"cca_{provider}_cost_{timestamp}_merged.json"
            write_json(merged_cost, str(cost_path))
            print(f"  Wrote: {cost_path.name}")
            print(f"  - Total cost: ${merged_cost.get('total_cost', 0):,.2f}")
            results["cost"] = {
                "file": str(cost_path),
                "total_cost": merged_cost.get('total_cost', 0)
            }
    
    print(f"\n✓ Merge complete for {folder.name}")
    return results


def main():
    parser = argparse.ArgumentParser(
        description="Merge batched CCA collection outputs into unified files",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Merge all batch subfolders in an org folder
  python scripts/merge_batch_outputs.py ./customer-org/
  
  # Merge and output to specific directory  
  python scripts/merge_batch_outputs.py ./org/ -o ./merged/
  
  # Process multiple org folders independently
  python scripts/merge_batch_outputs.py ./org1/ ./org2/ ./org3/ --per-folder
  
  # See what would be merged without writing files
  python scripts/merge_batch_outputs.py ./org/ --dry-run
"""
    )
    
    parser.add_argument(
        "folders",
        nargs="+",
        help="Folder(s) containing batch outputs to merge"
    )
    
    parser.add_argument(
        "-o", "--output",
        help="Output directory for merged files (default: same as input folder)"
    )
    
    parser.add_argument(
        "--per-folder",
        action="store_true",
        help="Process each folder independently (one merged output per folder)"
    )
    
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Show what would be merged without writing files"
    )
    
    args = parser.parse_args()
    
    folders = [Path(f) for f in args.folders]
    output_dir = Path(args.output) if args.output else None
    
    all_results = []
    
    if args.per_folder or len(folders) == 1:
        # Process each folder independently
        for folder in folders:
            out = output_dir if output_dir else folder
            result = process_folder(folder, out, args.dry_run)
            all_results.append(result)
    else:
        # Merge all folders together into single output
        print(f"Merging {len(folders)} folders into single output...")
        
        # Collect all files from all folders
        all_inv_files = []
        all_sum_files = []
        all_cost_files = []
        
        for folder in folders:
            all_inv_files.extend(find_inventory_files(Path(folder)))
            all_sum_files.extend(find_summary_files(Path(folder)))
            all_cost_files.extend(find_cost_files(Path(folder)))
        
        print(f"Found {len(all_inv_files)} inventory files across all folders")
        
        if not args.dry_run:
            merged_inv, stats = merge_inventory_files(all_inv_files)
            if merged_inv:
                out = output_dir or Path(".")
                out.mkdir(parents=True, exist_ok=True)
                
                provider = merged_inv.get("provider", "aws")
                timestamp = datetime.now(timezone.utc).strftime("%H%M%S")
                
                inv_path = out / f"cca_{provider}_inv_{timestamp}_merged.json"
                write_json(merged_inv, str(inv_path))
                print(f"Wrote: {inv_path}")
                
                # Summary and CSV
                merged_sum = merge_summary_files(all_sum_files, merged_inv)
                if merged_sum:
                    sum_path = out / f"cca_{provider}_sum_{timestamp}_merged.json"
                    write_json(merged_sum, str(sum_path))
                    print(f"Wrote: {sum_path}")
                
                csv_path = out / f"cca_{provider}_sizing_merged.csv"
                generate_sizing_csv(merged_inv, csv_path)
                print(f"Wrote: {csv_path}")
    
    # Final summary
    print(f"\n{'='*60}")
    print("MERGE SUMMARY")
    print(f"{'='*60}")
    
    for result in all_results:
        if "error" in result:
            print(f"  ERROR: {result['error']}")
        elif "inventory" in result:
            inv = result["inventory"]
            print(f"  {result['folder']}")
            print(f"    - {inv['resources']} resources from {inv['accounts']} accounts")
            if result.get("cost"):
                print(f"    - Total cost: ${result['cost']['total_cost']:,.2f}")


if __name__ == "__main__":
    main()

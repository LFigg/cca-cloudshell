"""Data loading and validation for the assessment report.

Loads and merges CCA inventory/summary/cost JSON files.
"""
import glob
import json
import os
from typing import Any, Dict, List, Optional, Tuple


def load_json_file(filepath: str) -> Optional[Dict[str, Any]]:
    """Load and parse a JSON file."""
    try:
        with open(filepath, 'r') as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError) as e:
        print(f"Warning: Could not load {filepath}: {e}")
        return None


def find_latest_files(directory: str, pattern: str) -> Optional[str]:
    """Find the most recent file matching a pattern in a directory."""
    matches = glob.glob(os.path.join(directory, pattern))
    if not matches:
        return None
    # Sort by modification time, newest first
    return max(matches, key=os.path.getmtime)


def load_inventory_files(paths: List[str]) -> Tuple[List[Dict], Dict[str, Any]]:
    """
    Load and merge multiple inventory files.

    Returns:
        Tuple of (merged_resources, metadata_dict)
    """
    all_resources = []
    metadata = {
        'run_ids': [],
        'timestamps': [],
        'providers': set(),
        'accounts': set(),
        'orgs': set(),  # Orgs (AWS) or Tenants (Azure) based on parent directory
    }

    for path in paths:
        data = load_json_file(path)
        if not data:
            continue

        # Track org/tenant from parent directory name
        from pathlib import Path
        parent_dir = Path(path).parent.name
        if parent_dir:
            metadata['orgs'].add(parent_dir)

        # Extract resources
        resources = data.get('resources', [])
        all_resources.extend(resources)

        # Collect metadata
        if data.get('run_id'):
            metadata['run_ids'].append(data['run_id'])
        if data.get('timestamp'):
            metadata['timestamps'].append(data['timestamp'])
        if data.get('provider'):
            metadata['providers'].add(data['provider'])

        # Extract accounts from resources (account_id for AWS, subscription_id for Azure)
        for r in resources:
            if r.get('account_id'):
                metadata['accounts'].add(r['account_id'])
            elif r.get('subscription_id'):
                metadata['accounts'].add(r['subscription_id'])

    metadata['providers'] = list(metadata['providers'])
    metadata['accounts'] = list(metadata['accounts'])
    metadata['orgs'] = list(metadata['orgs'])

    return all_resources, metadata


def load_summary_files(paths: List[str]) -> Dict[str, Any]:
    """Load and merge summary files."""
    merged = {
        'total_resources': 0,
        'total_size_gb': 0,
        'by_provider': {},
        'by_region': {},
        'by_type': {},
    }

    for path in paths:
        data = load_json_file(path)
        if not data:
            continue

        summary = data.get('summary', {})
        merged['total_resources'] += summary.get('total_resources', 0)
        merged['total_size_gb'] += summary.get('total_size_gb', 0)

        # Merge by_region
        for region, stats in summary.get('by_region', {}).items():
            if region not in merged['by_region']:
                merged['by_region'][region] = {'count': 0, 'size_gb': 0}
            merged['by_region'][region]['count'] += stats.get('count', 0)
            merged['by_region'][region]['size_gb'] += stats.get('size_gb', 0)

    return merged


def load_cost_files(paths: List[str]) -> Dict[str, Any]:
    """Load and merge cost data files."""
    merged = {
        'total_cost': 0,
        'currency': 'USD',
        'by_provider': {},
        'by_category': {},
        'records': [],
    }

    for path in paths:
        data = load_json_file(path)
        if not data:
            continue

        # Handle top-level total_cost (actual cost_collect.py format)
        if 'total_cost' in data and isinstance(data['total_cost'], (int, float)):
            merged['total_cost'] += data['total_cost']

        # Handle summaries array format (actual cost_collect.py format)
        if 'summaries' in data:
            for summary in data['summaries']:
                provider = summary.get('provider', 'unknown')
                category = summary.get('category', 'other')
                cost = summary.get('total_cost', 0)

                if provider not in merged['by_provider']:
                    merged['by_provider'][provider] = {'total': 0, 'categories': {}}
                merged['by_provider'][provider]['total'] += cost

                if category not in merged['by_provider'][provider]['categories']:
                    merged['by_provider'][provider]['categories'][category] = 0
                merged['by_provider'][provider]['categories'][category] += cost

                # Also track service breakdown
                for service, svc_cost in summary.get('service_breakdown', {}).items():
                    svc_key = f"{category}:{service}"
                    if svc_key not in merged['by_category']:
                        merged['by_category'][svc_key] = 0
                    merged['by_category'][svc_key] += svc_cost

        # Handle older summary.providers format (test fixtures)
        if 'summary' in data:
            summary = data['summary']
            merged['total_cost'] += summary.get('total_cost', 0)

            for provider, pdata in summary.get('providers', {}).items():
                if provider not in merged['by_provider']:
                    merged['by_provider'][provider] = {'total': 0, 'categories': {}}
                merged['by_provider'][provider]['total'] += pdata.get('total_cost', 0)

                for cat, cost in pdata.get('categories', {}).items():
                    if cat not in merged['by_provider'][provider]['categories']:
                        merged['by_provider'][provider]['categories'][cat] = 0
                    merged['by_provider'][provider]['categories'][cat] += cost

        if 'records' in data:
            merged['records'].extend(data['records'])

    return merged


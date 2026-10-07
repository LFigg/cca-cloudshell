# Assessment Report

The assessment report (`lib/reports/assessment/`) combines inventory, cost, and change-rate JSON from any
collector (AWS, Azure, GCP, M365) into one 12-tab Excel workbook for Cohesity sizing and TCO analysis.
This doc exists to answer the question every reader eventually asks about a number in the workbook:
**where did that come from, and what exactly does it count?**

For what the input JSON itself contains (resource types, `size_gb` semantics per type), see
[docs/collectors/aws.md](../collectors/aws.md), [azure.md](../collectors/azure.md), [gcp.md](../collectors/gcp.md).
This doc covers what the report *does* with that input.

## Basic Usage

```bash
# Auto-discover inventory/cost/change-rate files in the current directory
python scripts/generate_assessment_report.py

# Specify input directory (searches recursively)
python scripts/generate_assessment_report.py --directory ./cca_output

# Specify output filename
python scripts/generate_assessment_report.py -o my_assessment.xlsx

# Specify individual files (supports shell globs)
python scripts/generate_assessment_report.py \
  --inventory cca_aws_inv_*.json \
  --cost cca_aws_costs_*.json
```

## Inputs and File Discovery (Read This Before Trusting a Number)

`find_data_files()` (`lib/reports/assessment/report.py`) auto-discovers three kinds of file under
`--directory`, every pattern using a **recursive** `**/...` glob so nested per-account folders (e.g.
`cca_output_.../023/cca_aws_inv_*.json`) are found regardless of depth:

| File kind | Patterns searched | Recursive? |
|---|---|---|
| Inventory | `cca_inv_*.json`, `cca_aws_inv_*.json`, `cca_azure_inv_*.json`, `cca_gcp_inv_*.json`, `cca_m365_inv_*.json` | Yes |
| Change rate | `cca_change_rates_*.json`, `cca_aws_change_rates_*.json`, `cca_azure_change_rates_*.json`, `cca_gcp_change_rates_*.json` | Yes |
| Cost | `cca_cost_sum_*.json` **only** | Yes |

⚠️ **Cost files are not auto-discovered from a raw collector run.** The AWS/Azure/GCP collectors write
`cca_<cloud>_costs_<timestamp>.json` (see each collector's doc), but `find_data_files()` only looks for
`cca_cost_sum_*.json`, the output of a separate summarization step, not the collector's raw cost file. Point
`--cost` at the real files explicitly, e.g. `--cost $(find . -name "cca_aws_costs_*.json")`, or call
`generate_report()` directly from Python with an explicit file list. Otherwise the report will run with
**silently zero cost data** and every cost-dependent tab (Executive Summary's cost section, TCO Inputs) will
just be empty, with no error.

⚠️ **There is no deduplication across input files, by account or otherwise.** `load_inventory_files()`
(`loader.py`) concatenates every resource from every file you hand it. If the same account's inventory file
shows up twice (say, a resumed/retried batch collection run, or the same output directory zipped and unzipped
into two places), **every resource, cost record, and change-rate entry for that account is double-counted**,
and every total in the workbook (resource counts, size, cost, protection coverage) is inflated accordingly. Before
pointing this report at a directory that contains more than one collection *run* for the same accounts,
dedupe by `account_id` (or `subscription_id`) yourself, pick one copy per account, and pass that explicit
list via `--inventory`/`--cost`.

⚠️ **The `Orgs/Tenants` metadata field is not what it sounds like.** `load_inventory_files()` builds it from
each inventory file's **parent directory name** (`metadata['orgs'].add(Path(path).parent.name)`), not from any
real AWS Organization ID or Azure Tenant ID inside the file. In a typical single-account-per-folder batch
layout (`cca_output_.../<account_number>/cca_aws_inv_*.json`), this ends up counting *accounts*, not
organizations. If you collected 93 accounts that all belong to one AWS Organization, `Orgs/Tenants` will
still read 93. Don't use this number to answer "how many AWS Organizations/Azure Tenants did we assess."
Use the distinct `account_id`/`subscription_id` values instead (which is what `Accounts/Subscriptions`,
`analyze_accounts()`, and the Account Detail tab actually do).

## How Each Tab's Values Are Determined

### 1. Executive Summary (`tabs/executive_summary.py`)

- **Total Resources**: `len(resources)`, every resource from every inventory file handed in, unfiltered. Not deduplicated (see above).
- **Total Orgs/Tenants** / **Total Accounts/Subscriptions**: see the metadata caveats above.
- **Provider breakdown**: counted by `get_provider()`, which just reads the resource type's string prefix (`aws:`, `azure:`, `gcp:`, `m365:`, `k8s:`).
- **Sizing Summary table**: `categorize_resources()` (see Sizing Inputs §1 below for the exact rules), excluding the `Snapshots`/`Backup Services`/`Other` buckets from the TOTAL row.
- **Data-quality caveat note**: shown only when `compute_data_quality_summary_from_dicts()` finds any resource with `metadata.size_source == 'unavailable'`. This is not an error state: it means some resource type's real usage genuinely can't be measured via that cloud's API (see the Data Quality tab and each collector doc's "Size Data" column), and its `size_gb` is reported as `0`, not estimated.
- **Protection Status section**: directly from `analyze_protection_status()`. See Protection Analysis below for the exact per-resource-type rules.
- **Current Backup/Storage Costs**: only rendered if `cost_data['total_cost'] > 0`. This is the sum of every cost record's `total_cost` field across every cost file passed in. See the cost-file caveat above if this section is unexpectedly missing.

### 2. Sizing Inputs (`tabs/sizing_inputs.py`)

This tab is the densest in the workbook: six sections, each re-deriving its own categorization (not sharing one categorized set), so it's worth knowing the rules differ slightly by section.

**Disk-to-VM attribution (used throughout this tab and most others):** `resolve_vm_attached_storage()` sums a disk's `size_gb` into its VM's total by matching `parent_resource_id`, deliberately *not* the VM's own `attached_volumes`/`attached_disks` metadata list, because Azure's collector only populates that list with data disks (excluding the OS disk, a separate `azure:disk` resource), which would silently undercount every Azure VM's storage by its OS disk size.

- **Option 1, Complete Coverage**: every non-snapshot, non-read-replica resource, categorized by: specific DB engine group (via `_get_db_engine_group()`) if it's a database; else VM category (`Virtual Machines` or `Kubernetes/Containers` if `_is_kubernetes_node()` tags match); else `Block Storage (Unattached)` for disks not matched to a VM; else File/Object Storage, Kubernetes cluster types, Cache, or the generic `get_workload_category()` fallback. **This is the "everything we found" number.** Feed it into the Cohesity sizing calculator as the upper bound.
- **Option 2, Currently Protected Only**: identical categorization, but filtered to `analyze_protection_status()['protected_resources']` only. This is the "apples-to-apples" number: sizing against exactly what's backed up today (see Backup Policies tab for what counts as "protected" per policy).
- **Option 3, Regional Breakdown**: same categorization, grouped by `_get_region_group()` (a hardcoded lookup table collapsing e.g. `us-east-1`/`us-east-2` into one "US East" group, `eu-west-1/2/3` into "Europe West", etc.; see `analysis.py` for the full table; an unrecognized region falls back to being its own group). Intended to size one Cohesity cluster per geographic group. Groups under 100 GB are dropped from the recommendation table.
- **Option 4, By Encryption Status** and **Encryption Summary**: `is_encrypted` is **not** "is server-side encryption on." AWS KMS, Azure platform-managed keys, and GCP default encryption are all treated as transparent (`is_encrypted = False`) because they don't affect Cohesity's deduplication ratio. Only TDE (`metadata.tde_enabled`, defaulted to `True` for Azure SQL since Microsoft turns it on by default) and non-platform Azure Disk Encryption are counted as "encrypted" here, because those *do* reduce dedupe.
- **Database Sizing Details**: data size per engine group comes straight from inventory; the **transaction-log generation rate** is `"Actual"` (from `change_rate_data`, i.e. the `--change-rate-days` CloudWatch/Monitor sample) only when the engine group has a matching key in `engine_to_cr_keys`; otherwise it falls back to a hardcoded industry-estimate percentage of data size per day (e.g. PostgreSQL 15%, MySQL/MariaDB 10%). Check the "Source" column per row before treating this number as measured.
- **Detailed Resource Breakdown**: every resource type, unfiltered, unlike every section above. This is the only place in the tab that still includes snapshots, backup-service resources, and read replicas.

### 3. Regional Distribution (`tabs/regional_distribution.py`)

Straight pass-through of `analyze_regions()` (count/size per raw `region` string, no grouping) for the "Summary by Region" table, then the same `_get_region_group()` grouping as Sizing Inputs Option 3 for the cluster-placement recommendations (`>50 TB` → primary cluster, `>10 TB` → dedicated cluster, else → "protect from primary cluster"; groups under 100 GB are dropped entirely).

### 4. Protection Analysis (`tabs/protection_analysis.py`)

Direct presentation of `analyze_protection_status()` and `analyze_snapshots()`: no new logic. The protection determination itself (`analysis.py`) is the most consequential function in this report; here's exactly what it checks, in order, per resource type:

- **Protectable set**: only resource types listed in `WORKLOAD_CATEGORIES` (`lib/constants.py`) count toward "total protectable" at all. Raw backup artifacts (snapshots, backup plans/vaults) are never counted as protectable resources themselves. Database read replicas are explicitly excluded (they replicate from a primary, which is the thing that actually gets backed up).
- **AWS EC2 volumes**: protected if any of: an `aws:backup:source-resource` tag on a matching snapshot, a `aws:dlm:lifecycle-policy-id` tag on a matching snapshot, or *any* snapshot for that volume with `start_time` within the last 30 days (hardcoded window, not configurable).
- **AWS EC2 instances**: protected if the instance has attached volumes and **all** of them individually satisfy the volume rule above. If only *some* volumes are covered, the instance is still marked protected (there's a dead `f'Partial (...)'` string in the code, written but never used, so there's currently no way to see "partially protected" from the output; it reads as fully protected).
- **AWS RDS instances/clusters**: protected if `metadata.backup_retention_period > 0`, OR a matching AWS-Backup-tagged snapshot exists, OR a matching automated/awsbackup-type snapshot exists (matched by resource ID first, then by name as a fallback).
- **Azure resources**: matched against `azure:backup:protecteditem` resources' `source_resource_id`, in three passes: exact lowercased ID match, then subscription+resource-name match (to tolerate resource-group casing/hash differences), then resource-name-only as a last resort. A resource with no matching protected item is unprotected. There is no retention-based Azure rule analogous to RDS's `backup_retention_period`.
- **Everything else** (`metadata.backup_plan`, `metadata.recovery_vault`, `metadata.protected_by`, or an `aws:backup:source-resource` tag directly on the resource): protected if any of those fields/tags is truthy.
- **Coverage %** = `protected_count / total_protectable * 100`, by resource *count*. The separate size-based coverage section recomputes the same split by summed `size_gb` instead. The two percentages can differ meaningfully if your biggest unprotected resources aren't your most numerous ones.

### 5. Snapshot Analysis (`tabs/snapshot_analysis.py`)

Presentation of `analyze_snapshot_patterns()`. Snapshot source categorization is a priority-ordered, string-matching cascade over each EBS snapshot's `description` field and tags. First match wins, in this order: AWS Backup (tag or description text) → DLM (tag) → AMI artifact (description mentions `CreateImage`/`for ami-`/`DestinationAmi`) → cross-region/account copy (description mentions "copied") → daily/weekly/monthly script pattern (description contains that word) → other automated pattern (description mentions hourly/backup/snapshot) → manual (anything else, including blank descriptions). This is inherently a heuristic over free-text AWS-generated descriptions, not a reliable source-of-truth field. A hand-written description that happens to contain "weekly" will be bucketed as a weekly script snapshot.

The "likely scheduled" flag and detected schedule time fire when more than 30% of a category's snapshots share the same creation hour (UTC); also a heuristic, not a read of an actual cron/schedule definition. Retention-policy inference works the same way: it looks at the age-bucket distribution of existing snapshots and guesses a retention window from it (e.g. >15% of snapshots aged 7-14 days → "~7 day retention (daily backups)"), rather than reading any config value. It works only as well as the snapshot age distribution reflects a real policy.

### 6. Backup Policies (`tabs/backup_policies.py`)

Lists the actual policy definitions (AWS Backup plans + selections, AWS DLM policies + schedules, Azure Backup policies), not inferred like the Snapshot Analysis tab. These come straight from each provider's backup-config API (`aws:backup:plan`, `aws:backup:selection`, `aws:dlm:lifecycle-policy`, `azure:backup:policy` resource types). One nuance: AWS Backup *selections* are keyed by `(plan_id, account_id, region)`, not by `plan_id` alone. An org-managed plan deployed identically to every member account shares one `plan_id` across all of them, so without the account/region key every account's selections would incorrectly fan out under every other account sharing that plan. This tab is the authoritative scope definition for Sizing Inputs' Option 2 ("Currently Protected Only"). Read its "Apples-to-Apples Scope Note" section for what counts as in/out of scope per policy type.

### 7. Unprotected Resources (`tabs/unprotected_resources.py`)

The `unprotected_resources` list from `analyze_protection_status()`, sorted by `size_gb` descending. ⚠️ **Silently capped at 500 rows.** If there are more, the sheet says so in a trailing row (`"... and N more resources"`), but if you're scripting against this sheet rather than reading it, that cap is easy to miss. Rows tagged `Environment`/`environment`/`Env`/`env` = `prod`/`production`/`prd` (case-insensitive) are highlighted, but this is purely visual. It doesn't affect sort order or which rows get truncated by the 500-row cap.

### 8. TCO Inputs (`tabs/tco_inputs.py`)

Current costs: straight from `cost_data` (subject to the cost-file caveat above). Sizing inputs (change rate %, retention days, replica count) are **hardcoded placeholder text**, not computed: "2-5% (typical)", "30 (adjust as needed)", "1-2 (disaster recovery)" are literal strings in the code, not derived from actual change-rate data even when it was collected (contrast with Sizing Inputs' Database Sizing Details section, which does use actual change-rate data when available). Projected Annual/3yr/5yr costs are a flat `monthly_cost × 12/36/60`. No growth, inflation, or discount-tier modeling.

### 9. Account Detail (`tabs/account_detail.py`)

Direct presentation of `analyze_accounts()`: grouped by `account_id` (AWS) or `subscription_id` (Azure), falling back to the literal string `'unknown'` if a resource has neither field set. The no-deduplication caveat applies here most visibly: if an account's inventory file was loaded twice, it will not appear as two rows. Its single row's counts and sizes will just be roughly double the truth.

### 10. VM Detail (`tabs/vm_detail.py`)

One row per VM/instance (`aws:ec2:instance`, `azure:vm`, `gcp:compute:instance`) across all three clouds. "Actual Size (GB)" is the VM's own `size_gb` plus attached-disk storage from `resolve_vm_attached_storage()` (same attribution logic as Sizing Inputs). SKU/OS Type/Power State are read from a per-cloud fallback chain of metadata keys (e.g. SKU tries `vm_size` → `instance_type` → `machine_type` in order). A blank cell means none of that chain's keys were present for that resource, which is expected for fields a cloud genuinely doesn't expose (e.g. AWS has no "Resource Group" concept, so that column is always blank for AWS rows). Protection Status is a simple set-membership check against the same `protected_resources` list used everywhere else.

### 11. Raw Data (`tabs/raw_data.py`)

Every resource, one row each, sorted by provider then resource type: the closest thing in the workbook to the literal JSON input. Tags are flattened to a single `key=value; key=value` string and truncated to 200 characters, so a resource with many or long tag values will show a cut-off tag list here (the full tags are still in the original JSON, just not in this cell).

### 12. Data Quality (`tabs/data_quality.py`)

The only tab whose entire purpose is to document the limits of the other eleven. Built from `compute_data_quality_summary_from_dicts()` (`lib/data_quality.py`), which reads each resource's `metadata.size_source` field: `'usage'` (real measured usage), `'unavailable'` (couldn't be measured, reported as 0 GB everywhere else in this workbook, **not** a provisioned/allocated estimate standing in for real usage), or `'not_applicable'` (this resource type has no size concept, e.g. an EC2 instance itself). Resource types with no `size_source` at all aren't part of this policy and don't appear here. This tab is always generated, even when there are zero gaps, specifically so its absence is never mistaken for "data quality wasn't checked." See each collector doc's "Size Data" column for which resource types currently fall into `'unavailable'` and why.

## Known Limitations Checklist

Before handing this report to a customer, check:

- [ ] Did you dedupe input files by account before pointing `--directory`/`--inventory` at them, if the source directory could contain more than one collection run?
- [ ] Did you pass `--cost` explicitly with the collector's real cost filenames (`cca_<cloud>_costs_*.json`), not relying on auto-discovery?
- [ ] Does the data-quality caveat note appear on Executive Summary / does the Data Quality tab show any gaps? If so, every size total in the workbook is a floor, not a ceiling, for those resource types.
- [ ] Did "Unprotected Resources" get truncated at 500 rows? Check the trailing note.
- [ ] Are the protection-coverage numbers based on the heuristics in §4 above (snapshot age, tag presence, description text matching) rather than a direct "is this resource in a backup policy" read for every provider? Only AWS Backup/DLM and Azure Recovery Services vault-registered resources have a hard, non-heuristic signal; the 30-day-snapshot-existence rule for EC2 volumes is a proxy, not a policy read.

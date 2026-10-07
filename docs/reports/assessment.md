# Assessment Report

The assessment report (`lib/reports/assessment/`) combines inventory, cost, and change-rate JSON from any
collector (AWS, Azure, GCP, M365) into one 12-tab Excel workbook for Cohesity sizing and TCO analysis. This
doc exists to answer the question every reader eventually asks about a number in the workbook: where did
that come from, and what exactly does it count?

For what the input JSON itself contains (resource types, what `size_gb` means for each one), see
[docs/collectors/aws.md](../collectors/aws.md), [azure.md](../collectors/azure.md), and
[gcp.md](../collectors/gcp.md). This doc covers what the report *does* with that input once it's loaded.

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
`--directory`. Every pattern searches recursively, so nested per-account folders (for example
`cca_output_.../023/cca_aws_inv_*.json`) get picked up no matter how deep they're nested:

| File kind | Patterns searched | Recursive? |
|---|---|---|
| Inventory | `cca_inv_*.json`, `cca_aws_inv_*.json`, `cca_azure_inv_*.json`, `cca_gcp_inv_*.json`, `cca_m365_inv_*.json` | Yes |
| Change rate | `cca_change_rates_*.json`, `cca_aws_change_rates_*.json`, `cca_azure_change_rates_*.json`, `cca_gcp_change_rates_*.json` | Yes |
| Cost | `cca_cost_sum_*.json` **only** | Yes |

⚠️ **Cost files from a raw collector run are not auto-discovered.** The AWS, Azure, and GCP collectors each
write their own `cca_<cloud>_costs_<timestamp>.json` (see each collector's doc), but `find_data_files()`
only looks for `cca_cost_sum_*.json`, which is the output of a separate summarization step, not what the
collectors themselves produce. Point `--cost` at the real files explicitly, for example
`--cost $(find . -name "cca_aws_costs_*.json")`, or call `generate_report()` directly from Python with an
explicit file list. Skip this and the report still runs, just with silently zero cost data: the Executive
Summary's cost section and the TCO Inputs tab both go quietly empty, with no error to flag it.

⚠️ **Nothing here deduplicates across input files, by account or otherwise.** `load_inventory_files()`
(`loader.py`) simply concatenates every resource from every file you hand it. If the same account's
inventory shows up twice, say from a resumed or retried batch collection, or the same output directory
zipped and unzipped into two places, every resource, cost record, and change-rate entry for that account
gets counted twice, and every total in the workbook inflates to match: resource counts, size, cost,
protection coverage, all of it. Before pointing this report at a directory that might contain more than one
collection *run* for the same accounts, dedupe by AWS account ID (or Azure subscription ID) yourself, keep
one copy per account, and pass that explicit list via `--inventory`/`--cost`.

⚠️ **The `Orgs/Tenants` field doesn't mean what it sounds like.** `load_inventory_files()` builds it from
each inventory file's parent directory name, not from an actual AWS Organizations ID or Azure AD tenant ID
inside the file. In the typical layout this tool produces, one folder per AWS account, that ends up counting
*accounts*, not organizations. Collect 93 accounts that all live under one AWS Organization and `Orgs/Tenants`
will still read 93. If you need to know how many AWS Organizations or Azure tenants were actually assessed,
don't use this field; use the distinct account/subscription IDs instead, which is what `Accounts/Subscriptions`,
`analyze_accounts()`, and the Account Detail tab already do correctly.

## How Each Tab's Values Are Determined

### 1. Executive Summary (`tabs/executive_summary.py`)

- **Total Resources** is `len(resources)`: every resource from every inventory file handed in, counted once each, with no deduplication (see above).
- **Total Orgs/Tenants** and **Total Accounts/Subscriptions** carry the metadata caveats described above.
- **Provider breakdown** comes from `get_provider()`, which just reads the resource type string's prefix (`aws:`, `azure:`, `gcp:`, `m365:`, `k8s:`) rather than anything in the resource's own account metadata.
- **Sizing Summary table** uses `categorize_resources()`, the same categorization Sizing Inputs' Option 1 uses (details below), excluding Snapshots, Backup Services, and Other from the TOTAL row.
- **The data-quality caveat note** appears only when `compute_data_quality_summary_from_dicts()` finds a resource whose `metadata.size_source` is `'unavailable'`. That's not an error state: it means that particular resource type's real usage genuinely can't be measured through that cloud's API (see the Data Quality tab, and the "Size Data" column in each collector's doc), so its `size_gb` is reported as `0` rather than guessed at.
- **Protection Status** is lifted straight from `analyze_protection_status()`; see the Protection Analysis section below for exactly how each resource type earns a "protected" verdict.
- **Current Backup/Storage Costs** only renders when `cost_data['total_cost'] > 0`, and is the sum of every cost record's `total_cost` across every cost file passed in. If this section is missing when you expected it, check the cost-file caveat above first.

### 2. Sizing Inputs (`tabs/sizing_inputs.py`)

This is the densest tab in the workbook: six sections, and each one re-derives its own categorization rather
than sharing one. Worth knowing going in that the rules shift slightly section to section.

**Disk-to-VM attribution**, used throughout this tab and most others, works by matching an Amazon EBS
volume, Azure managed disk, or GCP persistent disk to its instance via `parent_resource_id`
(`resolve_vm_attached_storage()`), and summing that disk's `size_gb` into the instance's total. This is
deliberately *not* based on the instance's own `attached_volumes`/`attached_disks` metadata list: Azure's
collector only populates that list with data disks, leaving out the OS disk (which the collector reports as
its own separate `azure:disk` resource), so reading storage off the VM's own list would silently undercount
every Azure VM by the size of its OS disk.

- **Option 1, Complete Coverage**, is every resource except snapshots and database read replicas, run through one categorization pass: a specific database engine group if it's a database (via `_get_db_engine_group()`); otherwise Virtual Machines, or Kubernetes/Containers if the instance looks like an EKS, AKS, or GKE worker node; otherwise Block Storage (Unattached) for any disk that didn't match an instance; otherwise File Storage, Object Storage, a Kubernetes cluster type, Cache, or whatever `get_workload_category()`'s generic fallback decides. This is the "everything we found" number, the upper bound to feed into the Cohesity sizing calculator.
- **Option 2, Currently Protected Only**, runs the identical categorization but filters first to `analyze_protection_status()['protected_resources']`. This is the apples-to-apples number: size against exactly what's backed up today, not the whole environment. See the Backup Policies tab for what "protected" means under each policy type.
- **Option 3, Regional Breakdown**, groups the same categorized data by `_get_region_group()`, a hardcoded lookup table that collapses nearby AWS regions together (`us-east-1` and `us-east-2` both become "US East," `eu-west-1/2/3` all become "Europe West," and so on; see `analysis.py` for the full table). An AWS region this table doesn't recognize just becomes its own group. The intent is one Cohesity cluster per geographic group, which is also why groups under 100 GB get dropped from the recommendation table entirely.
- **Option 4, By Encryption Status**, and the **Encryption Summary** section right after it, both hinge on a narrower definition of `is_encrypted` than "is encryption turned on." Server-side encryption at rest, AWS KMS on an EBS volume, an Azure platform-managed key, GCP's default encryption, is treated as transparent (`is_encrypted = False`) because it doesn't change how well Cohesity can deduplicate the data. Only Transparent Data Encryption (TDE) on a database (`metadata.tde_enabled`, which defaults to `True` for Azure SQL Database since Microsoft turns it on by default) and non-platform Azure Disk Encryption count as "encrypted" here, because those genuinely do reduce dedupe ratios.
- **Database Sizing Details** pulls data size per engine group straight from inventory. The transaction-log generation rate is only labeled "Actual" when `change_rate_data` (from a `--change-rate-days` sample against Amazon CloudWatch or Azure Monitor) has a matching entry for that engine group; otherwise it falls back to a flat industry-estimate percentage of data size per day, 15% for PostgreSQL, 10% for MySQL/MariaDB, and so on. Check the "Source" column in each row before treating a transaction-log figure as measured rather than guessed.
- **Detailed Resource Breakdown** is the one section in this tab that doesn't filter anything out: every resource type, snapshots and read replicas included, unlike every section above it.

### 3. Regional Distribution (`tabs/regional_distribution.py`)

The "Summary by Region" table is a direct pass-through of `analyze_regions()`, one row per raw region
string with no grouping applied. The cluster-placement recommendations below it switch to the same
`_get_region_group()` grouping Sizing Inputs' Option 3 uses, and bucket each group by size: over 50 TB
suggests a primary cluster, over 10 TB a dedicated cluster, otherwise "protect from primary cluster." Groups
under 100 GB are dropped from this table entirely, same as in Sizing Inputs.

### 4. Protection Analysis (`tabs/protection_analysis.py`)

This tab is a direct presentation of `analyze_protection_status()` and `analyze_snapshots()`, with no logic
of its own. The protection determination behind it, in `analysis.py`, is the single most consequential piece
of logic in this report, so it's worth knowing exactly what it checks, per resource type, in order:

- **What counts as protectable at all**: only resource types listed in `WORKLOAD_CATEGORIES` (`lib/constants.py`). Backup artifacts themselves, snapshots, backup plans, vaults, are never counted as protectable resources. Database read replicas are excluded too, since they replicate from a primary, and it's the primary that actually gets backed up.
- **Amazon EBS volumes** count as protected if any of the following holds: a matching snapshot carries the `aws:backup:source-resource` tag (AWS Backup created it), a matching snapshot carries the `aws:dlm:lifecycle-policy-id` tag (Amazon Data Lifecycle Manager created it), or the volume simply has *any* snapshot taken within the last 30 days, a hardcoded window with no config to change it.
- **Amazon EC2 instances** count as protected only if every one of their attached EBS volumes individually satisfies the rule above. There's an unused code path meant to report a volume as "Partial" when only some of an instance's volumes are protected, but it's dead: the f-string gets built and immediately discarded, so a partially-protected instance currently reads as fully protected with no way to tell from the output.
- **Amazon RDS instances and clusters** (Aurora or Multi-AZ DB Cluster) count as protected if `metadata.backup_retention_period` is greater than zero (automated backups are on), or a matching snapshot carries the AWS Backup tag, or a matching snapshot's type is `automated`/`awsbackup` (matched first by resource ID, then by name as a fallback).
- **Azure resources** are matched against `azure:backup:protecteditem` resources by `source_resource_id`, trying an exact lowercased ID match first, then a subscription-plus-resource-name match (to tolerate resource-group casing or hash inconsistencies), then a name-only match as a last resort. No match means unprotected; there's no Azure equivalent of the RDS retention-period check.
- **Everything else** is protected if `metadata.backup_plan`, `metadata.recovery_vault`, `metadata.protected_by`, or an `aws:backup:source-resource` tag is set directly on the resource itself.
- **Coverage percentage** is `protected_count / total_protectable * 100`, by resource count. The size-based coverage section further down recomputes that same split by summed `size_gb` instead, and the two percentages can diverge meaningfully if your largest unprotected resources aren't also your most numerous ones.

### 5. Snapshot Analysis (`tabs/snapshot_analysis.py`)

This tab presents `analyze_snapshot_patterns()`, which sorts every Amazon EBS snapshot into a source
category by pattern-matching its description and tags. First match wins, checked in this order: AWS Backup
(tag or description text) → Amazon DLM (tag) → Amazon Machine Image (AMI) artifact (description mentions
`CreateImage`, `for ami-`, or `DestinationAmi`) → a cross-region or cross-account copy (description mentions
"copied") → a daily, weekly, or monthly scripted pattern (description contains that word) → some other
automated pattern (description mentions hourly, backup, or snapshot) → manual, the catch-all for anything
else, including a blank description. This whole scheme is a heuristic over free text that AWS itself writes
into the description field, not a reliable source-of-truth lookup. A hand-written description that happens
to contain the word "weekly" gets bucketed as a weekly script snapshot whether or not that's true.

The "likely scheduled" flag, and the schedule time it reports, fire when more than 30% of a category's
snapshots share the same creation hour in UTC. That's also a heuristic, not a read of any actual cron
expression or schedule definition. Retention-policy inference works the same way: it looks at how snapshot
ages are distributed across buckets and guesses a retention window from the shape of that distribution (for
example, more than 15% of snapshots aged 7 to 14 days suggests "~7 day retention (daily backups)") rather
than reading a configured value anywhere. It's only as reliable as the actual age distribution happens to
look like a real policy.

### 6. Backup Policies (`tabs/backup_policies.py`)

Unlike the Snapshot Analysis tab, nothing here is inferred. This tab lists the actual policy definitions,
AWS Backup plans and selections, Amazon DLM policies and their schedules, Azure Backup policies, read
straight from each provider's own backup configuration API. One nuance worth knowing: AWS Backup
*selections* are keyed by plan ID, account, and region together, not by plan ID alone, because an
organization-managed plan deployed identically across every member account shares one plan ID across all of
them. Without that account/region key, every account's selections would incorrectly fan out under every
other account sharing the same plan. This tab is also the authoritative scope definition behind Sizing
Inputs' Option 2 ("Currently Protected Only"); its own "Apples-to-Apples Scope Note" section spells out
exactly what's in and out of scope for each policy type.

### 7. Unprotected Resources (`tabs/unprotected_resources.py`)

This is the `unprotected_resources` list from `analyze_protection_status()`, sorted by `size_gb` largest
first. ⚠️ It's silently capped at 500 rows: if there are more, a trailing row says so (`"... and N more
resources"`), but that's easy to miss if you're scripting against the sheet rather than reading it directly.
Rows tagged `Environment`, `environment`, `Env`, or `env` equal to `prod`, `production`, or `prd`
(case-insensitive) get highlighted, purely as a visual cue; it has no effect on sort order or on which rows
get cut by the 500-row cap.

### 8. TCO Inputs (`tabs/tco_inputs.py`)

Current costs come straight from `cost_data`, subject to the same cost-file caveat as everywhere else in
this report. The sizing inputs below that, change rate percentage, retention days, replica count, are
hardcoded placeholder text, not computed values: "2-5% (typical)," "30 (adjust as needed)," and "1-2
(disaster recovery)" are literal strings in the code, never replaced by real change-rate data even when
it was collected. That's a real gap compared to Sizing Inputs' Database Sizing Details section, which does
use actual change-rate data when it's available. Projected Annual, 3-year, and 5-year costs are a flat
`monthly_cost × 12/36/60`, with no growth, inflation, or discount-tier modeling applied.

### 9. Account Detail (`tabs/account_detail.py`)

A direct presentation of `analyze_accounts()`, grouped by AWS account ID or Azure subscription ID, falling
back to the literal string `'unknown'` if a resource carries neither field. The no-deduplication caveat is
most visible right here: if one account's inventory file got loaded twice, it won't show up as two rows,
it'll show up as one row whose counts and sizes are roughly double the truth.

### 10. VM Detail (`tabs/vm_detail.py`)

One row per compute instance, Amazon EC2, Azure VM, or GCP Compute Engine, across all three clouds.
"Actual Size (GB)" is the instance's own `size_gb` plus whatever attached-disk storage
`resolve_vm_attached_storage()` attributes to it (the same logic Sizing Inputs uses). SKU, OS Type, and
Power State each come from a per-cloud chain of metadata keys, tried in order until one has a value (SKU,
for instance, tries `vm_size`, then `instance_type`, then `machine_type`). A blank cell just means none of
that chain's keys were present for that particular resource, which is expected for anything a given cloud
genuinely doesn't expose: AWS has no "Resource Group" concept at all, for example, so that column is always
blank on every AWS row. Protection Status is a simple membership check against the same `protected_resources`
list every other tab uses.

### 11. Raw Data (`tabs/raw_data.py`)

Every resource, one row each, sorted by provider and then resource type: the closest thing in this workbook
to the literal JSON you fed it. Tags are flattened into one `key=value; key=value` string and truncated to
200 characters, so a resource with a lot of tags, or a few very long ones, will show a visibly cut-off list
here even though the full tag set is still intact in the original JSON.

### 12. Data Quality (`tabs/data_quality.py`)

This tab's entire purpose is documenting the limits of the other eleven. It's built from
`compute_data_quality_summary_from_dicts()` (`lib/data_quality.py`), which reads each resource's
`metadata.size_source` field: `'usage'` means real, measured usage; `'unavailable'` means usage genuinely
couldn't be measured, and is reported as 0 GB everywhere in this workbook, never a provisioned or allocated
estimate standing in for the real number; `'not_applicable'` means this resource type has no size concept to
begin with, an EC2 instance itself, for example, as opposed to its attached volumes. Resource types that
don't carry a `size_source` at all aren't part of this policy and simply don't appear here. This tab is
generated even when there are zero gaps to report, specifically so its absence is never mistaken for "data
quality wasn't checked." See the "Size Data" column in each collector's doc for which resource types
currently fall into `'unavailable'`, and why.

## Known Limitations Checklist

Before handing this report to a customer, check:

- [ ] Did you dedupe input files by account before pointing `--directory`/`--inventory` at them, in case the source directory holds more than one collection run?
- [ ] Did you pass `--cost` explicitly with the collector's real cost filenames (`cca_<cloud>_costs_*.json`), rather than relying on auto-discovery?
- [ ] Does the data-quality caveat note appear on Executive Summary, or does the Data Quality tab show any gaps? If so, every size total in the workbook is a floor, not a ceiling, for those resource types.
- [ ] Did "Unprotected Resources" get truncated at 500 rows? Check the trailing note.
- [ ] Are the protection-coverage numbers you're citing based on the heuristics in section 4 above (snapshot age, tag presence, description-text matching), rather than a direct "is this resource in a backup policy" read? Only AWS Backup, Amazon DLM, and Azure Recovery Services vault registration give a hard, non-heuristic signal; the 30-day-snapshot rule for EBS volumes is a proxy, not a policy read.

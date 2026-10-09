# Changelog

All notable changes to CCA CloudShell will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [2.3.0] - 2026-10-09

### Added

- **`scripts/collect_parallel_profiles.sh`**: runs N accounts' `collect.py` invocations concurrently (via `xargs -P`) for SSO setups where no single identity can assume a role into every account, so `--org-role`/`--role-arns` can't build a multi-account target list and collection has to be one `--profile` invocation per account. A single-instance lock (`mkdir`, portable to macOS which has no `flock(1)`) refuses to start a second run against the same output directory, and re-running the same command resumes by skipping any account that already has a real inventory file. Documented in `docs/admin-machine-setup.md`.

### Fixed

- **`collect_account()`**: `get_enabled_regions()` and `collect_s3_buckets()` both ran unguarded at the top of the function, before Backup region settings even got a chance to run - either one raising (e.g. a denied `ec2:DescribeRegions` or `s3:ListBuckets`) still took out the whole account's collection the same way the Backup region-settings bug did. Both are now caught and logged instead.
- **Backup region-settings selection**: the real collection picked its probe region from `regions[0]` of an alphabetically-sorted enabled-region list, almost never `us-east-1` (codes like `ap-northeast-1` sort first) - while the mandatory preflight check always probes that exact API in `us-east-1`. Same account, same credentials, same API action, passed preflight and failed real collection. Since this data is account-wide (identical from any region), `collect_account()` now prefers `us-east-1` when it's enabled, which should recover this data for most/all accounts rather than just stop the failure from being fatal.
- **`merge_batch_outputs.py`**: `find_inventory_files()`/`find_summary_files()`/`find_cost_files()` only recognized `batchNN/` subdirectories or flat root files, not nested per-account folders from an external per-account orchestration loop - pointing the script at a real multi-account collection found and merged nothing. Added a recursive fallback that only engages when the existing two modes find nothing.

## [2.2.1] - 2026-10-07

### Changed

- **`docs/reports/assessment.md`**: reworded to use AWS's actual service names (Amazon EBS, Amazon RDS, Amazon Data Lifecycle Manager, Amazon Machine Image) instead of generic/internal phrasing, and rewritten as readable paragraphs instead of semicolon-chained, code-reference-heavy bullets. No factual changes beyond fixing one inaccuracy: `aws:rds:cluster` covers Multi-AZ DB Clusters as well as Aurora, not just Aurora.

## [2.2.0] - 2026-10-07

### Added

- **`docs/reports/{assessment,cost,m365}.md`**: documentation for every value in these three reports, naming the exact function/logic behind each tab's numbers and the real gotchas in each report's inputs (file-discovery patterns, a required-but-unused CLI flag, the M365 report's summary-file pairing convention, duplicate-account double-counting).

### Removed

- **Protection Report** (`lib/reports/protection.py`, `scripts/generate_protection_report.py`, and its tests/docs): removed entirely. It predated the Assessment Report, duplicated AWS-only protection logic under different (and disagreeing) rules, and covered a narrower scope - AWS EC2/EBS/RDS only, with just a flat multi-cloud overview for everything else, no protection determination at all for Azure/GCP. Use the Assessment Report's Protection Analysis and Unprotected Resources tabs instead.

### Fixed

- Several documented `generate_assessment_report.py`/`generate_cost_report.py` example commands across the README and docs/ were missing required flags (`--inventory`, `--summary`) or pointed `--cost` at a cost-file naming pattern no collector actually writes, and would fail exactly as written. Corrected.

## [2.1.2] - 2026-10-02

### Fixed

- **AWS collector: a single denied API call could erase an entire account's or region's inventory**: `collect_backup_region_settings()` (called once per account, before any region is processed) and each resource-type collector inside `collect_region()` raised `AuthError` with no enclosing try/except at those call sites. When an SCP denied one call, `backup:DescribeRegionSettings` for the whole account, or `ec2:DescribeInstances` in a single region, the exception propagated past every sibling collector queued behind it, discarding resources already gathered (such as S3 buckets) and skipping every untried resource type or region. In one customer run this zeroed out 64% of accounts entirely and limited most "successful" accounts to only a handful of their ~17 regions. Each call site now catches and logs the failure instead of letting it escalate, and the sequential per-region loop (`parallel_regions=1`, the CloudShell default) is now isolated the same way the parallel path already was.

## [2.1.0] - 2026-08-14

### Added

- **`--parallel-subscriptions N` for the Azure collector**: collects subscriptions concurrently (resource inventory, change-rate metrics, and cost collection each run through a `ThreadPoolExecutor`) instead of one at a time, cutting wall-clock time substantially on large tenants (a real 117-subscription tenant took ~113 minutes across these phases sequentially). Default is tiered by subscription count - `1` under 50, `4` from 50-99, `8` at 100 or more (hard-capped regardless of tenant size, since every subscription shares one credential's Azure Resource Manager throttling budget) - always overridable by passing the flag explicitly. Per-subscription failure isolation is unchanged: one subscription's `AuthError` or other exception is logged and recorded without aborting collection for the rest.

## [2.0.4] - 2026-08-14

### Fixed

- **Cost data collection failing for every subscription**: `azure-mgmt-costmanagement`'s pinned `5.0.0` renamed `QueryComparisonExpression`'s `values` constructor kwarg to `values_property`. Every run failed with `QueryComparisonExpression.__init__() got an unexpected keyword argument 'values'` before any cost data could be collected.
- **Misleading "Bearer token authentication is not permitted for non-TLS...URLs" error**: `CostManagementClient(credential, subscription_id)` passed `subscription_id` into what is actually the client's `base_url` parameter (Cost Management has no client-level subscription; it scopes via the `scope` string passed to `query.usage()`). That silently corrupted the ARM endpoint into a scheme-less string, which is what actually tripped the bearer-token-over-https guard - not a network or proxy issue as it first appeared. Fixed in both the real cost collector and the cost-management permission preflight probe.
- **Remaining "invalid time interval" Monitor errors**: the permission preflight's own `monitor_metrics()`/`monitor_activity_log()` probes built their timespan/filter strings with `datetime.isoformat()` directly, missing the `+00:00`-decoded-as-space fix already applied to the real collector in 2.0.2. Generalized the fix into `lib.utils.isoformat_z()` and applied it here too.

## [2.0.3] - 2026-08-14

### Added

- **`--skip-permission-failures` for the Azure collector**: excludes (rather than aborts on) subscriptions that fail the permission preflight, logging each one. Every subscription that remains is still fully verified before collection starts; the run still exits if every subscription fails.

## [2.0.2] - 2026-08-14

### Fixed

- **Redis permission preflight crashing collection**: the check called `client.redis.list()`, which doesn't exist on `RedisOperations` (only `list_by_subscription()`/`list_by_resource_group()` do). Every Azure run failed the preflight with `'RedisOperations' object has no attribute 'list'` before collection could start.
- **Azure Monitor rejecting change-rate metric requests**: `lib/change_rate.py` built the Monitor `timespan` query parameter with `datetime.isoformat()`, whose `+00:00` UTC offset is sent unencoded and decoded by Azure's endpoint as a literal space, producing a malformed interval Azure Monitor rejected with `BadRequest`. Now renders the offset as `Z` instead.

## [2.0.1] - 2026-08-14

### Fixed

- **Azure-only installs crashing on collection**: `lib/change_rate.py` (shared by all four cloud collectors) unconditionally imported `boto3` at module load just for a type hint, so any Azure-only setup (no `boto3` installed) failed immediately with `No module named 'boto3'` once `lib/azure/collector.py` pulled the module in. Fixed by deferring the import under `TYPE_CHECKING` with `from __future__ import annotations`.

### Added

- **`--exclude-subscriptions` for the Azure collector**: comma-separated list of subscription IDs to skip, applied alongside the existing `--subscription-id` filtering.

## [2.0.0] - 2026-08-10

### Security

- **`cryptography` bumped to 50.0.0**: resolves a high-severity Bleichenbacher timing oracle in PKCS#7 EnvelopedData decryption (CVE-2026-69247 / GHSA-g6cj-pr64-35w5, affecting 44.0.0–49.x). `msal` bumped to 1.37.0 in the same pass — the older pin capped `cryptography<49`, blocking the fix.

### Changed (Standards remediation)

- **Public API exports**: `lib/aws/__init__.py`, `lib/azure/__init__.py`, `lib/gcp/__init__.py`, `lib/reports/__init__.py` now re-export their package's actual public surface (`run_collection`, `build_parser`, cost/permission functions, report generators), matching the pattern `lib/m365/__init__.py` already used. Also removed a dead `get_graph_client_default_credential` reference from `lib/m365/__init__.py` that pointed at a function which never existed.
- **`lib/reports/assessment.py` split into a package** (`lib/reports/assessment/`): the single 3782-line, 44-function file mixing file I/O, categorization/protection/snapshot analysis, generic openpyxl helpers, and 11 report-tab generators is now one file per concern — `loader.py`, `analysis.py`, `excel_helpers.py`/`styles.py`, `tabs/*.py` (one per tab), and `report.py` (orchestration). All existing imports (`from lib.reports.assessment import ...`) keep working unchanged via the package's `__init__.py`.
- **Removed module-level global state**: `lib/m365/helpers.py`'s `_graph_credential` (mutated via `global`, read implicitly by ~9 scattered call sites) is now threaded explicitly as a `credential` parameter alongside `graph_client` through every function that needs it, following the same explicit-passing convention the codebase already used for `graph_client` itself. `get_graph_client()` now returns `(client, credential)` instead of storing the credential as a side effect. `lib/utils.py`'s `_LOG_REDACT_PATTERNS` lazy-init global replaced with `functools.lru_cache`. (`lib/m365/helpers.py`'s `_persistent_loop` intentionally left as-is — it's process-level event-loop infrastructure bound to `GraphServiceClient`'s connection pool lifecycle, not the kind of hidden data-coupling the "no global state" guideline targets.)
- **Type hints and docstrings**: filled in missing return/parameter type annotations and docstrings (with usage examples on primary entry points) across `lib/change_rate.py`, `lib/utils.py`, `lib/reports/m365.py`, `lib/reports/assessment/`, and the `lib/{aws,azure,gcp,m365}/*.py` collector modules, per this repo's own "Module Design Guidelines" in `docs/v2-refactor-plan.md`.

### Changed (Breaking)

- **Single entry point**: All collection now runs through `collect.py --cloud <cloud> [options]`. The root scripts `aws_collect.py`, `azure_collect.py`, `gcp_collect.py`, `m365_collect.py`, and `cost_collect.py` have been removed.
- **Cost collection is default ON**: Data protection cost collection runs automatically alongside inventory. Use `--no-costs` to opt out. Previously cost collection required a separate `cost_collect.py` invocation.
- **Cost output per cloud**: Each cloud now writes `cca_<cloud>_costs_<time>.json` as part of its normal collection run (not a shared `cca_cost_*.json`).

### Added

- **`lib/aws/collector.py`**: Orchestration module with `run_collection(args)` and `build_parser()`. Replaces the root `aws_collect.py`.
- **`lib/azure/collector.py`**: Same pattern for Azure.
- **`lib/gcp/collector.py`**: Same pattern for GCP. Accepts `--billing-table` for BigQuery cost collection.
- **`lib/m365/collector.py`**: Same pattern for M365.
- **`lib/aws/cost.py`**: AWS Cost Explorer integration (`collect_aws_costs()`).
- **`lib/azure/cost.py`**: Azure Cost Management integration (`collect_azure_costs()`).
- **`lib/gcp/cost.py`**: GCP BigQuery billing export integration (`collect_gcp_costs()`).
- **`lib/models.py`**: `CostRecord` and `CostSummary` dataclasses for structured cost output.
- **`lib/utils.py`**: `get_last_full_month()` and `aggregate_costs()` helpers.
- **`lib/reports/`**: Report generation logic extracted from scripts into importable modules (`assessment.py`, `protection.py`, `m365.py`, `cost.py`).
- **`scripts/generate_*.py`**: Now thin CLI wrappers that import from `lib/reports/`.
- **`--no-costs` flag**: Available on `collect.py` and all cloud-specific parsers.
- **`--billing-table` flag**: GCP-specific; required for GCP cost collection.
- **RDS tag collection** (`lib/aws/databases.py`): All RDS resource types now collect actual tags from the `TagList` API field.
- **Redshift storage via CloudWatch** (`lib/aws/databases.py`): Uses `PercentageDiskSpaceUsed` metric from CloudWatch instead of a naive node × capacity estimate.
- **Mandatory permission preflight, all four clouds** (`lib/{aws,azure,gcp,m365}/permissions.py`): every permission the parsed CLI flags require is verified with a live read-only probe — the same call the real collection step will make, not a static role/policy lookup — before any resource collection starts. Bails the run with a full per-account/subscription/project/tenant report if anything is missing. Not bypassable; no `--skip-check`-style flag exists for any of the four. `lib/azure/permissions.py` was the reference implementation; AWS assumes each account's role first (a distinct session per account, unlike Azure/GCP's shared credential) before running its checks; GCP scopes Application Default Credentials per-call via `project_id`; M365 is always single-tenant, so its check returns a single result rather than a list.
- **Mandatory dependency preflight, Azure and GCP** (`lib/{azure,gcp}/dependencies.py`): both clouds split services across many separate optional packages (`azure-mgmt-*`, `google-cloud-*`); every one of them is checked importable before any credentials are touched, refusing to start (no bypass flag, same philosophy as the permission preflight above) if any is missing. Found via a real customer collection (two Azure environments) where the collector silently ran with several packages missing — no error, just several resource types and every real-usage lookup (blob capacity, file share usage, change rates) quietly skipped with an easy-to-miss log warning. AWS (`boto3` covers everything in one package) and M365 (hard top-level SDK imports that fail loudly, not silently) don't have this failure mode, so neither needed the check. `tests/test_cloudshell_compat.py`'s per-cloud dependency check now shares the exact same package list as the real preflight, rather than checking a couple of packages and calling it "ready."
- **Collection completeness scoring, AWS/Azure/GCP** (`lib/collection_completeness.py`): every collector already tracked which accounts/subscriptions/projects failed outright, but only ever reported a raw count ("Collection failed for 4 subscription(s)"). Now weighted by estimated materiality (average resource count of units that succeeded, not just a unit count — 4 of 95 subscriptions failing is a very different signal at 4% of resources than at 40%) and checked for a shared root cause (2+ failed units with the *identical* error string get flagged as one likely systemic issue — e.g. an expired credential — rather than N unrelated failures). Printed to console every run (not just when something's wrong) and stamped into `cca_*_sum_*.json` as `collection_completeness`. Never gates or aborts a run — this scores and reports, it doesn't decide the run failed on the operator's behalf.
- **`lib/data_quality.py`**: cloud-agnostic collection-gap tracker. Aggregates the new `size_source` metadata convention (`'usage'` / `'unavailable'` / `'not_applicable'`) into a per-resource-type rollup, included in each cloud's summary JSON as `data_quality` and printed to console/log. Now wired into all four collectors (Azure, AWS, GCP, M365).
- **`lib/reports/sizer.py` data-quality awareness**: the Cohesity Reverse Sizer JSON now flags, per workload, whether any resource folded into that workload's `data_size_tb` had `size_source='unavailable'` (real usage couldn't be measured, so it contributed 0 GB rather than a fabricated estimate) — new `accurate_data_size`/`unmeasured_context_gb` fields per workload, a top-level `data_quality` section mirroring the assessment/protection reports' resource-type breakdown, and matching WARNING/INFO notes. Previously `sizer.py` had zero awareness of the `size_source` convention at all, meaning an SE could unknowingly key an understated capacity number into WST.

### Fixed

- **Azure File Share sizing**: shares were reporting their provisioned quota (occasionally 100+ TiB) instead of actual usage. Root cause: the fix that introduced Azure Monitor-based capacity lookup was built on an incorrect claim that no ARM API exposes real per-share usage. `file_shares.get(..., expand='stats')` (the singular get, not list) returns real usage via `share_usage_bytes` and always did — verified against the REST API reference and the installed SDK. `lib/azure/storage.py` now uses this directly; no Monitor dependency for file shares at all.
- **Azure "actuals or nothing" policy**: no Azure resource type may report an allocated/provisioned/quota/SKU-guessed value as `size_gb` when real usage was expected. Storage accounts, file shares, SQL databases keep their existing real-usage sources with the fallback removed (0.0 + `size_source='unavailable'` instead of the old estimate). SQL Managed Instances, CosmosDB, PostgreSQL/MySQL/MariaDB flexible servers, Synapse SQL pools, Redis caches, and NetApp volumes never had any real-usage collection at all — these are zeroed and flagged `unavailable` for now; real Monitor-based collection for each is tracked in `docs/v2-refactor-plan.md` (Phase 4.5).
- **Azure real-usage collection landed** for the 7 resource types deferred above: SQL Managed Instance, CosmosDB, PostgreSQL/MySQL flexible servers, Redis (non-clustered only), and NetApp volumes now report real Azure Monitor-sourced usage instead of `unavailable`, each metric verified against official Microsoft Learn docs before implementation. MariaDB (service retired 2025-09-19) and Synapse dedicated SQL pools (no storage metric exists in that Monitor namespace) stay `unavailable` permanently.
- **M365 Teams collection failure** (`RuntimeError: Event loop is closed`): `lib/m365/helpers.py`'s `run_sync()` opened and closed a fresh asyncio event loop on every call, orphaning `GraphServiceClient`'s single long-lived `httpx.AsyncClient` connection pool from the loop it was created on. Now reuses one persistent event loop for the process lifetime.
- **AWS "actuals or nothing" policy**: audited every `lib/aws/*.py` collector for `size_gb` sources. Fixed an active anti-pattern in `collect_rds_instances()` that computed real usage via CloudWatch `FreeStorageSpace` but deliberately kept `AllocatedStorage` as `size_gb` anyway "for backward compatibility" (same anti-pattern in the Redshift and non-Aurora RDS-cluster fallback paths). Zeroed and flagged `unavailable`: EBS snapshots, FSx, RDS/cluster snapshots, ElastiCache, DocumentDB, Neptune, OpenSearch, MemoryDB (a hardcoded node-type→GB guess table), Timestream. Confirmed and tagged already-correct sources: EFS, DynamoDB, AWS Backup recovery points, Lambda.
- **AWS Timestream collection returned zero resources on every run**: `collect_timestream_databases()` called `get_paginator()` on two operations that don't support botocore pagination at all, so every real call raised and was silently swallowed. Fixed with manual `NextToken` pagination.
- **AWS DLM lifecycle policies were never actually collected**: `collect_dlm_lifecycle_policies()` called `describe_lifecycle_policies()`, which isn't a real operation on the boto3 DLM client (`get_lifecycle_policies()` is the real list call, and only returns summaries — the `PolicyDetails`/`ExecutionRoleArn`/`PolicyArn` fields this function already parsed need a separate `get_lifecycle_policy()` call per policy). Every real invocation raised `AttributeError`, silently swallowed. Fixed to the real two-call shape.
- **GCP "actuals or nothing" policy**: same audit for `lib/gcp/*.py`. Fixed `collect_compute_instances()` double-counting attached-disk sizes into the VM's own `size_gb` (each disk is also collected separately as its own `gcp:compute:disk` resource, with no cross-type dedup in `aggregate_sizing()`). Fixed `collect_backups()` reading two non-existent field names via `getattr(..., 0)`, so `size_gb` had silently been `0.0` for every GCP Backup & DR backup; now reads the real field, `resource_size_bytes`. Zeroed and flagged `unavailable`: Cloud SQL, Memorystore Redis, Spanner, Bigtable, AlloyDB, GCS buckets, Filestore, Cloud Functions.
- **GCP change-rate collection returned nothing for every resource, every run**: `lib/gcp/monitoring.py`'s dispatch branched on `service_family` values (`'PersistentDisk'`, `'CloudSQL'`) that no collector ever actually sets (they're `'Compute'`/`'SQL'`), plus a second bug reading a truncated zone field in the (now-reachable) disk branch. Both fixed.
- **M365 sizing sweep**: audited every `lib/m365/*.py` collector. Applied `size_source` to Exchange/SharePoint/OneDrive (usage-report and Graph `quota.used` fallback paths — `quota.used` is real measured usage, not an allocation). Fixed a silent-always-zero bug in Teams: `getTeamsTeamActivityDetail` has no storage column at all, so team `size_gb` had always been `0.0`. Teams now correctly report `size_gb=0.0` / `size_source='not_applicable'` — a Team's files live in the same SharePoint site already collected as its own `m365:sharepoint:teamsite` resource, so giving Teams its own non-zero size would double-count that capacity, not fix a gap. Also fixed two dead-field bugs in the same Teams report parsing (`'Active Guests'` vs the real `'Guests'` column; a `'Total Channels'` column that doesn't exist).
- **`is_auth_error()` had no branch for `httpx.HTTPStatusError`**: M365's direct-REST permission checks (and, retroactively, the existing Exchange/SharePoint/OneDrive/Teams usage-report collection paths) couldn't classify a 401/403 from a raw `httpx` call as an auth error. Added the missing branch.
- **M365 `total_user_count` silently capped at 100,000 for large tenants**: `get_total_user_count()` paginated `/users` via `collect_all_pages_sync()`'s default 1,000-page safety limit (100 items/page), returning exactly 100,000 with no indication the real count was higher — found on a real ~100k-plus-user tenant. Now uses Graph's `/users/$count` endpoint (`ConsistencyLevel: eventual`) for an exact count in one call with no page-based ceiling at all, falling back to the old pagination only if that endpoint fails; the fallback path (and any other `collect_all_pages_sync()` caller) now also flags `total_user_count_truncated: true` in the summary JSON and a console warning if it hits the cap, instead of returning a silently-wrong number. Safety cap itself raised from 1,000 pages to 100,000 as a second layer of defense.

## [1.0.22] - 2026-07-28

### Fixed
- **Azure File Share sizing** (`azure_collect.py`, `lib/change_rate.py`): `file_shares.list()`'s `expand` parameter only supports `deleted`/`snapshots`, not `stats` — the collector's `expand='stats'` call always failed, and every file share silently reported its provisioned quota (usually the 100 TiB default max) as its size instead of actual usage, wildly inflating File Storage totals. Now pulls real usage from Azure Monitor's `FileCapacity` metric on `/fileServices/default`, filtered per-share via the `FileShare` dimension — the same approach already used for Blob capacity.

## [1.0.21] - 2026-07-28

### Fixed
- **M365 report crash** (`scripts/generate_m365_report.py`): `AttributeError: 'NoneType' object has no attribute 'get'` when generating a report from inventory data with no change-rate history. `summary_data.get('change_rates', {})` only substitutes the default when the key is missing, not when its value is `None`.
- **Dependency CVEs**: bumped `aiohttp`, `cryptography`, `idna`, `httplib2`, `pyjwt`, and `pyasn1` to clear 27 known vulnerabilities flagged by `pip-audit`.
- **CodeQL workflow**: added the `actions: read` permission the `analyze` step needs to upload SARIF results (was failing with "Resource not accessible by integration"); replaced the failing `Autobuild` step with `build-mode: none`, which is what CodeQL actually needs for an interpreted language like Python.
- **Lint**: resolved 50 pre-existing `ruff` findings across the collector scripts (import ordering, stray whitespace, an unused import/variable, missing exception chaining).

### Changed (Breaking)
- **Dropped Python 3.9 support** (now requires `>=3.10`): the `aiohttp` release that fixes the CVEs above requires Python 3.10+. Python 3.9 reached upstream end-of-life in October 2025.

## [1.0.20] - 2026-05-20

### Fixed
- **Azure region normalization** (`azure_collect.py`): Azure SDK returns `location` as canonical ID (`eastus`) on some paths and display name (`East US`) on others, causing the same region to appear twice in groupings. Added `_normalize_region()` and applied it at every `region=` site plus the `--regions` filter.
- **Azure VM size double-counting** (`azure_collect.py`): VM `size_gb` was the OS disk size, but disks were also emitted as separate `azure:disk` records, so OS disk capacity was counted twice in `total_capacity_gb`. ~40% of VMs additionally reported 0 because `disk_size_gb` returns `None` for marketplace images. VMs now report `size_gb=0` with `os_disk_size_gb` preserved in metadata; all capacity lives on `azure:disk` records (matches the AWS EC2/EBS pattern).
- **Hyperscale SQL `-0.0` bug** (`azure_collect.py`): Hyperscale databases return `max_size_bytes = -1` ("unlimited"), which fell through to `format_bytes_to_gb(-1) = -0.0`. Guarded with `max_size_bytes > 0`; Hyperscale capacity is then populated via the Monitor `storage` metric.
- **Azure blob capacity + object counts** (`lib/change_rate.py`): `get_azure_storage_account_capacity` used a 1-day window with hourly granularity, but `UsedCapacity` has ~24h lag, so it returned `None` for every account. Widened to a 3-day window via a shared `_azure_metric_latest_value` helper. Added `get_azure_blob_service_metrics()` querying `BlobCapacity`, `BlobCount`, `ContainerCount` on `/blobServices/default`; surfaced as `size_gb`, `metadata.blob_count`, `metadata.container_count`.

## [1.0.17] - 2026-05-08

### Fixed
- **AWS Cost Explorer pagination** (`cost_collect.py`): Added `NextPageToken` loop so large result sets are fully collected rather than truncated at the first page (#18)
- **Org mode usage type filtering** (`cost_collect.py`): AWS org mode now applies a `USAGE_TYPE CONTAINS` filter at the Cost Explorer API level, matching the per-account mode's backup-type filtering (#20)
- **Azure Cost Management pagination** (`cost_collect.py`): Pagination now correctly follows `nextLink` URLs via authenticated HTTP requests instead of re-issuing the same query (#14)
- **CLI date validation** (`cost_collect.py`): `--start-date` and `--end-date` are now validated as YYYY-MM-DD at parse time with a clear error message; ordering is also checked (#17)

## [1.0.16] - 2026-05-08

### Changed
- **Dependency lock file**: `requirements.txt` is now a fully pinned lock file generated by `pip-compile`. Edit `requirements.in` for dependency changes, then regenerate with `pip-compile requirements.in -o requirements.txt`.
- **pip-tools**: Added to `requirements-dev.txt` for lock file management.

## [1.0.15] - 2026-05-01

### Added
- **Dependency audit in CI**: New `dependency-audit` job runs `pip-audit` against `requirements.txt` on every push and pull request to detect known CVEs in dependencies.
- **Dependabot**: Weekly automated pull requests for pip dependency updates.

## [1.0.14] - 2026-05-08

### Security
- **Path confinement guard**: Resolved SAST finding (Semgrep A1:2017 OS Command Injection) in `collect.py`. Collector paths are now resolved with `os.path.realpath` and verified to remain within the script directory before any subprocess execution.

## [1.0.13] - 2026-04-08

### Fixed
- **Redshift Storage**: Now queries CloudWatch `PercentageDiskSpaceUsed` to report actual data stored rather than provisioned capacity. The previous approach used `nodes × max_node_capacity` (e.g. 128 TB/node for RA3), which massively overstated actual usage. The `storage_source` metadata field records whether CloudWatch or the capacity estimate was used.

## [1.0.12] - 2026-04-08

### Fixed
- **S3 Bucket Sizes**: CloudWatch query now uses `AllStorageTypes` dimension first, falling back to `StandardStorage`. Previously only `StandardStorage` was queried, causing buckets using IA, Glacier, Intelligent-Tiering, or Deep Archive storage classes to report 0 bytes.
- **RDS Tag Collection**: All four RDS collectors (instances, clusters, snapshots, cluster snapshots) now parse the `TagList` field returned by the AWS RDS APIs. Previously all RDS resources were collected with empty tags, resulting in 0% tag coverage for RDS.

## [1.0.11] - 2026-03-23

### Added
- **M365 User License Assignments**: New `get_user_license_assignments()` function collects per-user license data
  - Queries Graph API for all users with `assignedLicenses` field
  - Maps SKU IDs to friendly license names (e.g., ENTERPRISEPACK → E3)
  - Outputs to `user_license_assignments` array in summary JSON
- **M365 Report License Assignments Tab**: New "License Assignments" sheet in M365 Excel report
  - License Pool Summary: Shows purchased/consumed/available counts per SKU with utilization %
  - License Distribution Summary: Users with/without licenses breakdown
  - License Type Distribution: Most common licenses across users
  - User License Details: Full list of every user with their assigned license names
  - Color coding for high utilization (>90%), disabled accounts, and unlicensed users

### Changed
- **M365 Report Notes**: Removed outdated ASP overhead reference from Exchange notes

## [1.0.10] - 2026-03-19

### Added
- **M365 Teams Usage Report**: New `collect_teams_usage_report()` function fetches Teams storage from Graph API
  - Uses `getTeamsTeamActivityDetail` report for per-team storage sizes
  - Includes activity metrics: active channels, users, messages, last activity date
- **Collector Metadata**: All collectors now include debugging metadata in summary output
  - `collector_version`, `collector_name`, `arguments` (redacted), `environment`, `sdk_versions`
  - Helps diagnose issues by knowing exact version and configuration used

### Changed
- **M365 Report Storage Summary**: Teams and SharePoint storage now properly separated
  - Teams shows capacity from SharePoint Group + Team Channel sites
  - SharePoint shows only non-Teams sites (classic Team Sites, Communication Sites, etc.)
  - No double-counting - each GB attributed to exactly one service
- **M365 Report Site Types**: SharePoint tab now uses `root_web_template` field
  - Shows actual site types: M365 Group Sites, Private/Shared Channels, Classic Team Sites, etc.
  - Includes notes explaining what each site type represents
  - Sorted by storage size descending

### Fixed
- **M365 Teams Collection**: Improved event loop handling in `run_sync()`
  - Proactively checks `loop.is_closed()` before running coroutines
  - Prevents "cannot reuse already awaited coroutine" errors

## [1.0.9] - 2026-03-18

### Fixed
- **M365 SharePoint Collection**: Fixed "Event loop is closed" error in Graph API fallback
  - `run_sync()` now creates fresh event loop when needed instead of crashing
  - SharePoint sites can now be collected via Graph API when usage reports unavailable
- **M365 SharePoint Aggregate Sizing**: Added fallback to use storage history for total size
  - When individual sites can't be enumerated (e.g., concealed reports), aggregate total is now
    estimated from storage history data
  - Flags data with `size_estimated: true` and prints diagnostic message
  - Users get sizing data even with tenant report concealment enabled
- **M365 Report Inventory Loading**: Fixed `generate_m365_report.py` failing on list-format JSON
  - `find_m365_files()` now handles both list format (array of resources) and dict format

### Changed
- **M365 Licensing Report**: Filtered to M365-related SKUs only
  - Excludes free/viral/trial SKUs (FLOW_FREE, POWER_BI_STANDARD, STREAM, etc.)
  - Shows relevant SKUs: M365 E3/E5/F1/F3, Exchange, SharePoint, Teams, Copilot, Defender, etc.
  - Totals now reflect actual M365 license consumption, not inflated by unlimited free SKUs
  - SKUs sorted by consumed (most active first) instead of purchased

## [1.0.8] - 2026-03-17

### Added
- **Argument Logging**: All collectors now log CLI arguments at startup (with sensitive fields redacted)
- **M365 Credential Detection**: `collect.py` now detects both App Registration and Azure CLI credentials for M365
  - App Registration (env vars) preferred, with clear partial-credential error messages
  - Falls back to Azure CLI / DefaultAzureCredential if no app registration configured

### Changed
- **Azure Change Rate Collection**: Now uses VM-level metrics instead of per-disk metrics
  - `Disk Write Bytes` metric at VM level works for ALL VMs regardless of disk type
  - Much more reliable than per-disk metrics (which only work for Premium SSD v2/Ultra)
  - Correctly aggregates total disk writes across OS + data disks

### Fixed
- **Azure Disk Change Rate Metrics**: Fixed metric name for disk write throughput
  - `Composite Disk Write Bytes/sec` only works for Premium SSD v2 and Ultra Disks
  - Now tries multiple metric names: `Composite Disk Write Bytes/sec`, `Disk Write Bytes/sec`, `DiskWriteBytes`
  - Note: Standard/Premium SSD v1 don't expose disk-level write metrics (Azure limitation)
  - Fixes HTTP 400 errors that caused all disk change rate collection to fail
- **Azure Resource Group Parsing**: Fixed case-sensitivity issue in resource ID parsing
  - Azure APIs may return `resourcegroups` (lowercase) instead of `resourceGroups`
  - Made `_extract_resource_group` case-insensitive to handle both formats
  - Fixes AKS PVC collection failing with "Resource group 'unknown' could not be found"
- **Change Rate Requirements Check**: Collection now aborts early if monitoring packages are missing
  - Azure change rate requires `azure-mgmt-monitor` (pip install azure-mgmt-monitor)
  - GCP change rate requires `google-cloud-monitoring` (pip install google-cloud-monitoring)
  - Clear error message with install instructions shown before collection starts
  - Use `--skip-change-rate` to bypass if package unavailable
- **Change Rate Error Messaging**: Improved logging when change rate collection fails
  - User-visible warning shown if no change rate data collected
  - Explicit pip install instructions in log output

## [1.0.7] - 2026-03-17

### Fixed
- **Azure File Shares**: Fixed regression where file shares weren't collected when `expand='stats'` fails
  - Now falls back to basic list (using quota as size) if stats unavailable
  - Adds `size_source` metadata to indicate if `usage` or `quota` was used
- **Azure SQL/Synapse**: Fixed double-counting of Synapse dedicated SQL pools
  - DataWarehouse tier databases are now skipped in SQL collection (collected separately as Synapse pools)
  - Assessment report now properly categorizes Synapse SQL pools under "DB: Synapse"
- **Assessment Report**: Fixed generic "Databases" bucket appearing in sizing inputs
  - MySQL/PostgreSQL flexible servers now properly categorized as "DB: MySQL/MariaDB" and "DB: PostgreSQL"

### Added
- Added `Microsoft.Storage/storageAccounts/fileServices/read` permission to Azure role definitions
- M365 collector: Clear warnings when usage reports unavailable (falls back to per-user API)
- `tools/analyze_accounts.py`: Now cloud-agnostic (supports AWS accounts, Azure subscriptions, GCP projects)

## [1.0.6] - 2026-03-13

### Added
- M365 collector now queries tenant organization info (`/organization` API)
  - Tenant name and display name
  - Primary domain and verified domains
  - Included in console output, JSON summary, and reports
- M365 collector now queries tenant licensing information (`/subscribedSkus` API)
  - Shows licenses purchased vs consumed for each SKU
  - Included in executive summary JSON and console output
  - Helps validate user counts and understand tenant scale
- M365 report generator now shows licensing breakdown in Executive Summary sheet
- Added `Organization.Read.All` permission to setup scripts and documentation

### Fixed
- **CRITICAL**: M365 collector now properly paginates Graph API responses for large tenants
  - Previously only collected first page (100 items max) for Teams, Entra users/groups, user counts
  - Now follows `odata_next_link` to collect ALL items across all pages (up to 100,000 items)
  - Progress logging every 100 pages for visibility on large collections
- M365 SharePoint/OneDrive collection now uses usage reports (like Exchange) for complete data
- Added `AttrDict` wrapper for consistent attribute access on paginated results
- Added comprehensive pagination tests

## [1.0.5] - 2026-03-13

### Fixed
- Added explicit `six` dependency for Azure Cloud Shell compatibility (transitive dependency not pre-installed)

## [1.0.4] - 2026-03-12

### Added
- Azure collector: Subscription names now included in output (`subscriptions` array with `subscription_id` and `subscription_name`)
- GCP collector: Project names now included in output (`projects` array with `project_id` and `project_name`)

### Fixed
- M365 collector: Pinned msgraph-sdk to <2.0.0 to prevent future compatibility issues

## [1.0.3] - 2026-03-12

### Fixed
- M365 collector async compatibility with msgraph-sdk 1.x

## [1.0.1] - 2026-03-12

### Fixed
- M365 collector no longer hangs on non-Azure machines (skip ManagedIdentityCredential outside Azure)
- Better error messages when partial MS365_* environment variables are set
- Improved troubleshooting output for DefaultAzureCredential failures

## [1.0.0] - 2026-03-12

### Added
- **AWS Collector**: EC2, EBS, RDS, Aurora, S3, DynamoDB, EFS, FSx, DocumentDB, ElastiCache, Redshift, EKS, Lambda, Backup vaults
- **Azure Collector**: VMs, Managed Disks, Storage Accounts, SQL Databases, Cosmos DB, AKS, App Services, Azure Files, NetApp Files, Recovery Services
- **GCP Collector**: Compute Engine, Persistent Disks, Cloud Storage, Cloud SQL, Cloud Spanner, BigTable, AlloyDB, Filestore, GKE, Cloud Functions
- **M365 Collector**: SharePoint, OneDrive, Exchange mailboxes, Teams, Entra ID users/groups
- **Cost Collector**: AWS Cost Explorer, Azure Cost Management, GCP BigQuery billing
- **Change Rate Collection**: Enabled by default for all collectors
- **Assessment Report Generation**: Excel reports with protection coverage, sizing inputs, regional breakdown
- **M365 Report Generation**: Dedicated Microsoft 365 assessment report
- **Kubernetes PVC Discovery**: Automatic PVC collection when K8s clusters found
- **TDE Detection**: Transparent Data Encryption detection for AWS RDS and Azure SQL
- **Interactive Setup Wizard**: `python collect.py --setup`
- **Multi-cloud Support**: Run collections across AWS Organizations, Azure subscriptions, GCP projects

### Fixed
- Azure File Shares now report actual usage instead of quota
- Azure SQL databases now report actual usage instead of max allocated size
- Storage account capacity uses Azure Monitor metrics for accuracy

### Security
- Support for DefaultAzureCredential (Azure CLI, Managed Identity)
- Removed credential file options - environment variables only
- BigQuery table name validation

## [Unreleased]

### Added
- CI/CD pipeline with automated testing
- Automated release process

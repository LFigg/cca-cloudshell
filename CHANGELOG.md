# Changelog

All notable changes to CCA CloudShell will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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

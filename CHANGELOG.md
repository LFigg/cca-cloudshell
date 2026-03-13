# Changelog

All notable changes to CCA CloudShell will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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

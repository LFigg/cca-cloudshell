"""Azure database resource collection (SQL, CosmosDB, PostgreSQL, MySQL, MariaDB, Synapse, Redis)."""
import logging
from typing import List

from lib.models import CloudResource
from lib.utils import check_and_raise_auth_error, format_bytes_to_gb
from lib.azure.helpers import extract_resource_group

logger = logging.getLogger(__name__)


def _check_azure_sql_tde(sql_client, resource_group: str, server_name: str, db_name: str) -> bool:
    """Check if TDE (Transparent Data Encryption) is enabled for an Azure SQL database.

    Azure SQL TDE is enabled by default since 2017, but can be disabled.
    This checks the actual TDE status via the API.

    Args:
        sql_client: SqlManagementClient instance
        resource_group: Resource group name
        server_name: SQL server name
        db_name: Database name

    Returns:
        True if TDE is enabled, False otherwise
    """
    try:
        # The transparent_data_encryptions.get() returns TDE status
        # "current" is the TDE configuration name
        tde = sql_client.transparent_data_encryptions.get(
            resource_group, server_name, db_name, "current"
        )
        # state is 'Enabled' or 'Disabled'
        return getattr(tde, 'state', None) == 'Enabled'
    except Exception as e:
        # If we can't check, assume TDE is enabled (Azure default since 2017)
        logger.debug(f"Could not check TDE status for {server_name}/{db_name}: {e}")
        return True


def collect_sql_servers(credential, subscription_id: str) -> List[CloudResource]:
    """Collect Azure SQL Servers and Databases."""
    from azure.mgmt.sql import SqlManagementClient
    
    resources = []
    try:
        sql_client = SqlManagementClient(credential, subscription_id)

        for server in sql_client.servers.list():
            server_id = getattr(server, 'id', None)
            server_name = getattr(server, 'name', '')
            if not server_id:
                continue

            rg = extract_resource_group(server_id)

            # Get databases for this server
            try:
                for db in sql_client.databases.list_by_server(rg, server_name):
                    db_name = getattr(db, 'name', '')
                    if db_name == 'master':
                        continue  # Skip system database

                    db_sku = getattr(db, 'sku', None)
                    sku_tier = getattr(db_sku, 'tier', '') if db_sku else ''

                    # Skip DataWarehouse tier - these are Synapse dedicated SQL pools
                    # and are collected separately via collect_synapse_sql_pools()
                    if sku_tier == 'DataWarehouse':
                        logger.debug(f"Skipping DataWarehouse database {db_name} (collected as Synapse SQL pool)")
                        continue

                    # Get size (max_size_bytes is in bytes)
                    size_gb = 0.0
                    max_size_bytes = getattr(db, 'max_size_bytes', None)
                    if max_size_bytes:
                        size_gb = format_bytes_to_gb(max_size_bytes)

                    # Check if this is a replica (secondary database)
                    secondary_type = getattr(db, 'secondary_type', None)
                    is_read_replica = secondary_type is not None and secondary_type != 'None'

                    # Check TDE status via API
                    tde_enabled = _check_azure_sql_tde(sql_client, rg, server_name, db_name)

                    resource = CloudResource(
                        provider="azure",
                        subscription_id=subscription_id,
                        region=getattr(db, 'location', ''),
                        resource_type="azure:sql:database",
                        service_family="AzureSQL",
                        resource_id=getattr(db, 'id', ''),
                        name=db_name,
                        tags=getattr(db, 'tags', None) or {},
                        size_gb=size_gb,
                        parent_resource_id=server_id,
                        metadata={
                            'resource_group': rg,
                            'server_name': server_name,
                            'sku': getattr(db_sku, 'name', 'unknown') if db_sku else 'unknown',
                            'tier': getattr(db_sku, 'tier', 'unknown') if db_sku else 'unknown',
                            'status': getattr(db, 'status', None),
                            'collation': getattr(db, 'collation', None),
                            'is_read_replica': is_read_replica,
                            'secondary_type': secondary_type,
                            'tde_enabled': tde_enabled,
                        }
                    )
                    resources.append(resource)
            except Exception as e:
                check_and_raise_auth_error(e, f"list databases for server {server_name}", "azure")
                logger.warning(f"Failed to list databases for server {server_name}: {e}")

        logger.info(f"Found {len(resources)} Azure SQL Databases")
    except Exception as e:
        check_and_raise_auth_error(e, "collect SQL Servers", "azure")
        logger.error(f"Failed to collect SQL Servers: {e}")

    return resources


def collect_sql_managed_instances(credential, subscription_id: str) -> List[CloudResource]:
    """Collect Azure SQL Managed Instances."""
    from azure.mgmt.sql import SqlManagementClient
    
    resources = []
    try:
        sql_client = SqlManagementClient(credential, subscription_id)

        for mi in sql_client.managed_instances.list():
            mi_id = getattr(mi, 'id', None)
            if not mi_id:
                continue

            rg = extract_resource_group(mi_id)

            mi_sku = getattr(mi, 'sku', None)
            resource = CloudResource(
                provider="azure",
                subscription_id=subscription_id,
                region=getattr(mi, 'location', ''),
                resource_type="azure:sql:managedinstance",
                service_family="AzureSQL",
                resource_id=mi_id,
                name=getattr(mi, 'name', ''),
                tags=getattr(mi, 'tags', None) or {},
                size_gb=float(getattr(mi, 'storage_size_in_gb', 0) or 0),
                metadata={
                    'resource_group': rg,
                    'sku': getattr(mi_sku, 'name', 'unknown') if mi_sku else 'unknown',
                    'tier': getattr(mi_sku, 'tier', 'unknown') if mi_sku else 'unknown',
                    'vcores': getattr(mi, 'v_cores', None),
                    'state': getattr(mi, 'state', None),
                    'is_read_replica': False,  # Managed instances don't have read replicas concept
                    'tde_enabled': True,  # Azure SQL MI has TDE enabled by default and cannot be disabled
                }
            )
            resources.append(resource)

        logger.info(f"Found {len(resources)} Azure SQL Managed Instances")
    except Exception as e:
        check_and_raise_auth_error(e, "collect SQL Managed Instances", "azure")
        logger.error(f"Failed to collect SQL Managed Instances: {e}")

    return resources


def collect_sql_database_backups(credential, subscription_id: str) -> List[CloudResource]:
    """Collect Azure SQL Database restore points and long-term retention backups."""
    from azure.mgmt.sql import SqlManagementClient
    
    resources = []
    try:
        sql_client = SqlManagementClient(credential, subscription_id)

        for server in sql_client.servers.list():
            server_id = getattr(server, 'id', None)
            server_name = getattr(server, 'name', '')
            if not server_id or not server_name:
                continue

            rg = extract_resource_group(server_id)
            server_location = getattr(server, 'location', '')

            # Get databases for this server
            try:
                for db in sql_client.databases.list_by_server(rg, server_name):
                    db_id = getattr(db, 'id', None)
                    db_name = getattr(db, 'name', '')

                    if not db_name or db_name == 'master':
                        continue

                    # Get restore points (point-in-time restore points)
                    try:
                        for rp in sql_client.restore_points.list_by_database(rg, server_name, db_name):
                            rp_id = getattr(rp, 'id', None)
                            rp_name = getattr(rp, 'name', '')

                            restore_point_type = getattr(rp, 'restore_point_type', 'unknown')
                            restore_point_time = getattr(rp, 'restore_point_creation_date', None)
                            earliest_restore_date = getattr(rp, 'earliest_restore_date', None)

                            resource = CloudResource(
                                provider="azure",
                                subscription_id=subscription_id,
                                region=server_location,
                                resource_type="azure:sql:restorepoint",
                                service_family="SQLDatabase",
                                resource_id=rp_id or f"{db_id}/restorePoints/{rp_name}",
                                name=rp_name or f"{db_name}-{restore_point_type}",
                                tags={},
                                size_gb=0.0,  # Restore points don't have explicit size
                                parent_resource_id=db_id,
                                metadata={
                                    'resource_group': rg,
                                    'server_name': server_name,
                                    'database_name': db_name,
                                    'restore_point_type': str(restore_point_type),
                                    'restore_point_time': str(restore_point_time) if restore_point_time else None,
                                    'earliest_restore_date': str(earliest_restore_date) if earliest_restore_date else None,
                                }
                            )
                            resources.append(resource)
                    except Exception as e:
                        logger.debug(f"Failed to list restore points for database {db_name}: {e}")

                    # Get long-term retention backups
                    try:
                        for ltr in sql_client.long_term_retention_backups.list_by_resource_group_database(
                            rg, server_location, server_name, db_name
                        ):
                            ltr_id = getattr(ltr, 'id', None)
                            ltr_name = getattr(ltr, 'name', '')

                            backup_time = getattr(ltr, 'backup_time', None)
                            backup_expiration_time = getattr(ltr, 'backup_expiration_time', None)
                            backup_storage_redundancy = getattr(ltr, 'backup_storage_redundancy', 'unknown')

                            resource = CloudResource(
                                provider="azure",
                                subscription_id=subscription_id,
                                region=server_location,
                                resource_type="azure:sql:ltrbackup",
                                service_family="SQLDatabase",
                                resource_id=ltr_id or '',
                                name=ltr_name or f"{db_name}-ltr",
                                tags={},
                                size_gb=0.0,  # LTR backups don't expose size directly
                                parent_resource_id=db_id,
                                metadata={
                                    'resource_group': rg,
                                    'server_name': server_name,
                                    'database_name': db_name,
                                    'backup_time': str(backup_time) if backup_time else None,
                                    'backup_expiration_time': str(backup_expiration_time) if backup_expiration_time else None,
                                    'backup_storage_redundancy': str(backup_storage_redundancy),
                                }
                            )
                            resources.append(resource)
                    except Exception as e:
                        logger.debug(f"Failed to list LTR backups for database {db_name}: {e}")

            except Exception as e:
                logger.debug(f"Failed to process databases for server {server_name}: {e}")

        logger.info(f"Found {len(resources)} SQL Database Restore Points/LTR Backups")
    except Exception as e:
        check_and_raise_auth_error(e, "collect SQL Database Backups", "azure")
        logger.error(f"Failed to collect SQL Database Backups: {e}")

    return resources


def collect_cosmosdb_accounts(credential, subscription_id: str) -> List[CloudResource]:
    """Collect Azure Cosmos DB accounts."""
    from azure.mgmt.cosmosdb import CosmosDBManagementClient
    
    resources = []
    try:
        cosmos_client = CosmosDBManagementClient(credential, subscription_id)

        for account in cosmos_client.database_accounts.list():
            if not account.id:
                continue

            rg = extract_resource_group(account.id)

            resource = CloudResource(
                provider="azure",
                subscription_id=subscription_id,
                region=account.location,
                resource_type="azure:cosmosdb:account",
                service_family="CosmosDB",
                resource_id=account.id,
                name=account.name,
                tags=account.tags or {},
                size_gb=0.0,  # Requires metrics API
                metadata={
                    'resource_group': rg,
                    'kind': str(account.kind) if account.kind else 'unknown',
                    'database_account_offer_type': account.database_account_offer_type,
                    'consistency_policy': str(account.consistency_policy.default_consistency_level) if account.consistency_policy else 'unknown',
                    'provisioning_state': account.provisioning_state,
                    'is_read_replica': False,  # Cosmos DB regions are multi-master, not replicas
                    # Note: Cosmos DB uses server-side encryption only (no TDE)
                }
            )
            resources.append(resource)

        logger.info(f"Found {len(resources)} Azure Cosmos DB accounts")
    except Exception as e:
        check_and_raise_auth_error(e, "collect Cosmos DB accounts", "azure")
        logger.error(f"Failed to collect Cosmos DB accounts: {e}")

    return resources


def collect_postgresql_servers(credential, subscription_id: str) -> List[CloudResource]:
    """Collect Azure Database for PostgreSQL servers (Flexible and Single Server)."""
    resources = []
    try:
        from azure.mgmt.rdbms.postgresql_flexibleservers import PostgreSQLManagementClient as PGFlexClient

        # Collect Flexible Servers (recommended)
        flex_client = PGFlexClient(credential, subscription_id)

        for server in flex_client.servers.list():
            server_id = getattr(server, 'id', None)
            if not server_id:
                continue

            rg = extract_resource_group(server_id)

            # Get storage size
            storage = getattr(server, 'storage', None)
            storage_gb = float(getattr(storage, 'storage_size_gb', 0)) if storage else 0.0

            # SKU info
            sku = getattr(server, 'sku', None)
            sku_name = getattr(sku, 'name', 'unknown') if sku else 'unknown'
            sku_tier = getattr(sku, 'tier', 'unknown') if sku else 'unknown'

            resource = CloudResource(
                provider="azure",
                subscription_id=subscription_id,
                region=getattr(server, 'location', ''),
                resource_type="azure:postgresql:flexibleserver",
                service_family="PostgreSQL",
                resource_id=server_id,
                name=getattr(server, 'name', ''),
                tags=getattr(server, 'tags', None) or {},
                size_gb=storage_gb,
                metadata={
                    'resource_group': rg,
                    'sku_name': sku_name,
                    'sku_tier': sku_tier,
                    'version': getattr(server, 'version', ''),
                    'state': str(getattr(server, 'state', '')),
                    'fully_qualified_domain_name': getattr(server, 'fully_qualified_domain_name', ''),
                    'high_availability_mode': str(getattr(getattr(server, 'high_availability', None), 'mode', 'Disabled')) if getattr(server, 'high_availability', None) else 'Disabled',
                    'backup_retention_days': getattr(getattr(server, 'backup', None), 'backup_retention_days', 7) if getattr(server, 'backup', None) else 7,
                }
            )
            resources.append(resource)

        logger.info(f"Found {len(resources)} Azure Database for PostgreSQL servers")
    except ImportError:
        logger.warning("azure-mgmt-rdbms not installed. Skipping PostgreSQL collection. Install with: pip install azure-mgmt-rdbms")
    except Exception as e:
        check_and_raise_auth_error(e, "collect PostgreSQL servers", "azure")
        logger.error(f"Failed to collect PostgreSQL servers: {e}")

    return resources


def collect_mysql_servers(credential, subscription_id: str) -> List[CloudResource]:
    """Collect Azure Database for MySQL servers (Flexible and Single Server)."""
    resources = []
    try:
        from azure.mgmt.rdbms.mysql_flexibleservers import MySQLManagementClient as MySQLFlexClient

        # Collect Flexible Servers (recommended)
        flex_client = MySQLFlexClient(credential, subscription_id)

        for server in flex_client.servers.list():
            server_id = getattr(server, 'id', None)
            if not server_id:
                continue

            rg = extract_resource_group(server_id)

            # Get storage size
            storage = getattr(server, 'storage', None)
            storage_gb = float(getattr(storage, 'storage_size_gb', 0)) if storage else 0.0

            # SKU info
            sku = getattr(server, 'sku', None)
            sku_name = getattr(sku, 'name', 'unknown') if sku else 'unknown'
            sku_tier = getattr(sku, 'tier', 'unknown') if sku else 'unknown'

            resource = CloudResource(
                provider="azure",
                subscription_id=subscription_id,
                region=getattr(server, 'location', ''),
                resource_type="azure:mysql:flexibleserver",
                service_family="MySQL",
                resource_id=server_id,
                name=getattr(server, 'name', ''),
                tags=getattr(server, 'tags', None) or {},
                size_gb=storage_gb,
                metadata={
                    'resource_group': rg,
                    'sku_name': sku_name,
                    'sku_tier': sku_tier,
                    'version': getattr(server, 'version', ''),
                    'state': str(getattr(server, 'state', '')),
                    'fully_qualified_domain_name': getattr(server, 'fully_qualified_domain_name', ''),
                    'high_availability_mode': str(getattr(getattr(server, 'high_availability', None), 'mode', 'Disabled')) if getattr(server, 'high_availability', None) else 'Disabled',
                    'backup_retention_days': getattr(getattr(server, 'backup', None), 'backup_retention_days', 7) if getattr(server, 'backup', None) else 7,
                }
            )
            resources.append(resource)

        logger.info(f"Found {len(resources)} Azure Database for MySQL servers")
    except ImportError:
        logger.warning("azure-mgmt-rdbms not installed. Skipping MySQL collection. Install with: pip install azure-mgmt-rdbms")
    except Exception as e:
        check_and_raise_auth_error(e, "collect MySQL servers", "azure")
        logger.error(f"Failed to collect MySQL servers: {e}")

    return resources


def collect_mariadb_servers(credential, subscription_id: str) -> List[CloudResource]:
    """Collect Azure Database for MariaDB servers."""
    resources = []
    try:
        from azure.mgmt.rdbms.mariadb import MariaDBManagementClient

        client = MariaDBManagementClient(credential, subscription_id)

        for server in client.servers.list():
            server_id = getattr(server, 'id', None)
            if not server_id:
                continue

            rg = extract_resource_group(server_id)

            # Get storage size (in MB for MariaDB, convert to GB)
            storage_mb = getattr(server, 'storage_profile', None)
            storage_gb = 0.0
            if storage_mb:
                storage_gb = float(getattr(storage_mb, 'storage_mb', 0)) / 1024.0

            # SKU info
            sku = getattr(server, 'sku', None)
            sku_name = getattr(sku, 'name', 'unknown') if sku else 'unknown'
            sku_tier = getattr(sku, 'tier', 'unknown') if sku else 'unknown'

            resource = CloudResource(
                provider="azure",
                subscription_id=subscription_id,
                region=getattr(server, 'location', ''),
                resource_type="azure:mariadb:server",
                service_family="MariaDB",
                resource_id=server_id,
                name=getattr(server, 'name', ''),
                tags=getattr(server, 'tags', None) or {},
                size_gb=storage_gb,
                metadata={
                    'resource_group': rg,
                    'sku_name': sku_name,
                    'sku_tier': sku_tier,
                    'version': getattr(server, 'version', ''),
                    'user_visible_state': str(getattr(server, 'user_visible_state', '')),
                    'fully_qualified_domain_name': getattr(server, 'fully_qualified_domain_name', ''),
                    'ssl_enforcement': str(getattr(server, 'ssl_enforcement', '')),
                }
            )
            resources.append(resource)

        logger.info(f"Found {len(resources)} Azure Database for MariaDB servers")
    except ImportError:
        logger.warning("azure-mgmt-rdbms not installed. Skipping MariaDB collection. Install with: pip install azure-mgmt-rdbms")
    except Exception as e:
        check_and_raise_auth_error(e, "collect MariaDB servers", "azure")
        logger.error(f"Failed to collect MariaDB servers: {e}")

    return resources


def collect_synapse_workspaces(credential, subscription_id: str) -> List[CloudResource]:
    """Collect Azure Synapse Analytics workspaces and SQL pools."""
    resources = []
    try:
        from azure.mgmt.synapse import SynapseManagementClient

        client = SynapseManagementClient(credential, subscription_id)

        # List workspaces
        for workspace in client.workspaces.list():
            workspace_id = getattr(workspace, 'id', None)
            if not workspace_id:
                continue

            rg = extract_resource_group(workspace_id)
            workspace_name = getattr(workspace, 'name', '')

            # Collect workspace resource
            resource = CloudResource(
                provider="azure",
                subscription_id=subscription_id,
                region=getattr(workspace, 'location', ''),
                resource_type="azure:synapse:workspace",
                service_family="Synapse",
                resource_id=workspace_id,
                name=workspace_name,
                tags=getattr(workspace, 'tags', None) or {},
                size_gb=0.0,
                metadata={
                    'resource_group': rg,
                    'provisioning_state': getattr(workspace, 'provisioning_state', ''),
                    'managed_resource_group': str(getattr(workspace, 'managed_resource_group_name', '')),
                    'sql_administrator_login': getattr(workspace, 'sql_administrator_login', ''),
                    'connectivity_endpoints': dict(getattr(workspace, 'connectivity_endpoints', {})) if getattr(workspace, 'connectivity_endpoints', None) else {},
                }
            )
            resources.append(resource)

            # List dedicated SQL pools (formerly SQL DW)
            try:
                for pool in client.sql_pools.list_by_workspace(rg, workspace_name):
                    pool_id = getattr(pool, 'id', None)
                    if not pool_id:
                        continue

                    # Get SKU for sizing
                    sku = getattr(pool, 'sku', None)
                    sku_name = getattr(sku, 'name', 'unknown') if sku else 'unknown'

                    # Estimate storage based on DWU (Data Warehouse Units)
                    # Synapse dedicated pools have compute + storage separation
                    # Storage is typically measured in TB and scales with usage
                    max_size_bytes = getattr(pool, 'max_size_bytes', 0)
                    storage_gb = float(max_size_bytes) / (1024 ** 3) if max_size_bytes else 0.0

                    pool_resource = CloudResource(
                        provider="azure",
                        subscription_id=subscription_id,
                        region=getattr(pool, 'location', ''),
                        resource_type="azure:synapse:sqlpool",
                        service_family="Synapse",
                        resource_id=pool_id,
                        name=getattr(pool, 'name', ''),
                        tags=getattr(pool, 'tags', None) or {},
                        size_gb=storage_gb,
                        parent_resource_id=workspace_id,
                        metadata={
                            'resource_group': rg,
                            'workspace_name': workspace_name,
                            'sku_name': sku_name,
                            'status': str(getattr(pool, 'status', '')),
                            'collation': getattr(pool, 'collation', ''),
                            'max_size_bytes': max_size_bytes,
                            'create_mode': str(getattr(pool, 'create_mode', '')),
                        }
                    )
                    resources.append(pool_resource)
            except Exception as e:
                logger.debug(f"Failed to list SQL pools for workspace {workspace_name}: {e}")

        logger.info(f"Found {len(resources)} Synapse workspaces and SQL pools")
    except ImportError:
        logger.warning("azure-mgmt-synapse not installed. Skipping Synapse collection. Install with: pip install azure-mgmt-synapse")
    except Exception as e:
        check_and_raise_auth_error(e, "collect Synapse workspaces", "azure")
        logger.error(f"Failed to collect Synapse workspaces: {e}")

    return resources


def collect_redis_caches(credential, subscription_id: str) -> List[CloudResource]:
    """Collect Azure Cache for Redis instances."""
    resources = []

    try:
        from azure.mgmt.redis import RedisManagementClient
    except ImportError:
        logger.warning("azure-mgmt-redis not installed. Skipping Redis cache collection. Install with: pip install azure-mgmt-redis")
        return resources

    try:
        redis_client = RedisManagementClient(credential, subscription_id)

        for cache in redis_client.redis.list_by_subscription():
            cache_id = getattr(cache, 'id', None)
            if not cache_id:
                continue

            rg = extract_resource_group(cache_id)

            # Get cache size based on SKU
            sku = getattr(cache, 'sku', None)
            sku_name = getattr(sku, 'name', 'unknown') if sku else 'unknown'
            sku_family = getattr(sku, 'family', '') if sku else ''
            sku_capacity = getattr(sku, 'capacity', 0) if sku else 0

            # Estimate size based on SKU (Basic/Standard/Premium C0-C6, P1-P5)
            # This is approximate - actual sizes vary
            size_gb = 0.0
            if sku_family == 'C':  # Basic/Standard
                sizes = {0: 0.25, 1: 1, 2: 2.5, 3: 6, 4: 13, 5: 26, 6: 53}
                size_gb = sizes.get(sku_capacity, 0)
            elif sku_family == 'P':  # Premium
                sizes = {1: 6, 2: 13, 3: 26, 4: 53, 5: 120}
                size_gb = sizes.get(sku_capacity, 0)

            resource = CloudResource(
                provider="azure",
                subscription_id=subscription_id,
                region=getattr(cache, 'location', ''),
                resource_type="azure:redis:cache",
                service_family="Redis",
                resource_id=cache_id,
                name=getattr(cache, 'name', ''),
                tags=getattr(cache, 'tags', None) or {},
                size_gb=size_gb,
                metadata={
                    'resource_group': rg,
                    'sku_name': sku_name,
                    'sku_family': sku_family,
                    'sku_capacity': sku_capacity,
                    'host_name': getattr(cache, 'host_name', ''),
                    'port': getattr(cache, 'port', 6379),
                    'ssl_port': getattr(cache, 'ssl_port', 6380),
                    'redis_version': getattr(cache, 'redis_version', ''),
                    'provisioning_state': getattr(cache, 'provisioning_state', ''),
                    'enable_non_ssl_port': getattr(cache, 'enable_non_ssl_port', False),
                    'replicas_per_master': getattr(cache, 'replicas_per_master', 0),
                    'shard_count': getattr(cache, 'shard_count', 0),
                    'minimum_tls_version': getattr(cache, 'minimum_tls_version', ''),
                }
            )
            resources.append(resource)

        logger.info(f"Found {len(resources)} Azure Cache for Redis instances")
    except Exception as e:
        check_and_raise_auth_error(e, "collect Redis caches", "azure")
        logger.error(f"Failed to collect Redis caches: {e}")

    return resources

# Troubleshooting

Common issues and solutions for each cloud collector.

---

## AWS Collector

### AccessDeniedException

**Error:** `An error occurred (AccessDenied) when calling the DescribeInstances operation`

**Solutions:**
1. Verify IAM permissions - see [Required Permissions](PERMISSIONS.md#aws-permissions)
2. Check if running in the correct account
3. Ensure the IAM user/role has the required policies attached

```bash
# Test your permissions
aws sts get-caller-identity
aws ec2 describe-instances --max-results 1
```

### UnrecognizedClientException

**Error:** `The security token included in the request is invalid`

**Solutions:**
1. In CloudShell: Refresh your session (it may have expired)
2. Local: Re-run `aws configure` or refresh credentials
3. Check for typos in AWS_ACCESS_KEY_ID or profile name

### Role Assumption Failures

**Error:** `An error occurred (AccessDenied) when calling the AssumeRole operation`

**Solutions:**
1. Verify the role ARN is correct
2. Check the trust policy in the target account allows your source identity
3. Verify external ID matches (if configured)

```bash
# Test role assumption manually
aws sts assume-role \
    --role-arn arn:aws:iam::123456789012:role/CCARole \
    --role-session-name test
```

### Organizations Discovery Returns Empty

**Error:** No accounts discovered with `--org-role`

**Solutions:**
1. Verify `organizations:ListAccounts` permission
2. Must be running from the management account (or delegated admin)
3. Check if AWS Organizations is enabled

```bash
# Test Organizations access
aws organizations list-accounts
```

### Timeout or Slow Collection

**Solutions:**
1. Use `--regions` to limit to specific regions
2. Check network connectivity to AWS APIs
3. Consider running during off-peak hours

---

## Azure Collector

### AuthorizationFailed

**Error:** `The client does not have authorization to perform action`

**Solutions:**
1. Verify role assignment at subscription level
2. Check if using the correct subscription
3. Ensure at least **Reader** role is assigned

```bash
# Check your identity
az account show
az role assignment list --assignee $(az ad signed-in-user show --query id -o tsv)
```

### SubscriptionNotFound

**Error:** `Subscription not found`

**Solutions:**
1. Verify subscription ID is correct
2. Check if you have access to the subscription
3. Ensure subscription is not disabled

```bash
# List accessible subscriptions
az account list --output table
```

### DefaultAzureCredential Errors

**Error:** `EnvironmentCredential authentication unavailable`

**Solutions:**
1. In Cloud Shell: Should work automatically
2. Local: Run `az login` or set environment variables
3. Check `AZURE_TENANT_ID`, `AZURE_CLIENT_ID`, `AZURE_CLIENT_SECRET`

### Missing Resources

**Issue:** Some resources not appearing in output

**Solutions:**
1. Check if resources are in a different subscription
2. Verify permissions for specific resource types
3. Some resources may not be supported yet - check collector version

---

## GCP Collector

### PermissionDenied

**Error:** `Request had insufficient authentication scopes`

**Solutions:**
1. Verify Viewer role on the project
2. Check application default credentials

```bash
# Re-authenticate
gcloud auth application-default login

# Verify access
gcloud projects describe PROJECT_ID
```

### ProjectNotFound

**Error:** `Project not found or access denied`

**Solutions:**
1. Verify project ID (not project name)
2. Check if project is active (not deleted/pending deletion)
3. Ensure you have access to the project

```bash
# List accessible projects
gcloud projects list
```

### Quota Exceeded

**Error:** `Quota exceeded for quota metric`

**Solutions:**
1. Wait and retry (quotas reset periodically)
2. Request quota increase in GCP Console
3. Run collector during off-peak hours

### Missing Backup Resources

**Issue:** Backup & DR resources not appearing

**Solutions:**
1. Verify Backup and DR API is enabled in the project
2. Check `backupdr.*` permissions
3. Backup & DR may not be available in all regions

---

## M365 Collector

### InvalidAuthenticationToken

**Error:** `Invalid authentication token`

**Solutions:**
1. Verify tenant ID, client ID, and client secret
2. Check if client secret has expired
3. Ensure app registration is in the correct tenant

### Insufficient Privileges

**Error:** `Insufficient privileges to complete the operation`

**Solutions:**
1. Admin consent must be granted for all permissions
2. Go to App registration → API permissions → verify green checkmarks
3. May need Global Administrator to grant consent

### Forbidden (403)

**Error:** `403 Forbidden` when accessing specific resources

**Solutions:**
1. Missing specific Graph API permission
2. Check which permission is needed for the failing resource
3. Add permission and re-grant admin consent

### Partial Data

**Issue:** Some users/sites missing from output

**Solutions:**
1. Check if users are licensed for the service
2. Verify permissions cover all resource types
3. Test individual services with skip flags:

```bash
# Test one service at a time
python3 m365_collect.py --skip-onedrive --skip-exchange --skip-teams
```

### Rate Limiting (429)

**Error:** `Too many requests`

**Solutions:**
1. Collector has built-in retry logic
2. For very large tenants, run during off-peak hours
3. Wait and retry if persistent

---

## Cost Collection Issues

### AWS: Empty Cost Data

**Issue:** Cost collection returns no records

**Solutions:**
1. **Must run from the management account** - Cost Explorer API is only accessible from the payer account
2. Enable Cost Explorer in AWS Console → Billing → Cost Explorer (may take 24 hours to activate)
3. Verify permissions: `ce:GetCostAndUsage`

```bash
# Test Cost Explorer access
aws ce get-cost-and-usage \
    --time-period Start=2026-01-01,End=2026-01-02 \
    --granularity DAILY \
    --metrics UnblendedCost
```

### Azure: Cost Management Access Denied

**Solutions:**
1. Assign **Cost Management Reader** role at subscription level
2. Check subscription ID is correct
3. Verify Cost Management API is enabled

### GCP: BigQuery Billing Table Not Found

**Solutions:**
1. Enable BigQuery billing export in Billing → Billing export
2. Verify the billing table path format: `project.dataset.table`
3. Ensure your identity has BigQuery Data Viewer role

---

## General Issues

### Import Errors

**Error:** `ModuleNotFoundError: No module named 'boto3'`

**Solutions:**
1. Run `./setup.sh` to install dependencies
2. Or manually: `pip install -r requirements.txt`
3. Verify correct Python environment is active

### Output Directory Errors

**Error:** `Permission denied` when writing output

**Solutions:**
1. Check write permissions on output directory
2. Create directory first: `mkdir -p ./output`
3. Use a different output path: `-o ~/output/`

### JSON Parse Errors

**Error:** Malformed JSON in output

**Solutions:**
1. Check if collection completed successfully
2. Look for error messages in logs
3. Increase log level: `--log-level DEBUG`

### Memory Issues

**Error:** Process killed or out of memory

**Solutions:**
1. Large environments may need more memory
2. Collect specific regions: `--regions us-east-1`
3. Run on a larger instance

---

## Getting Help

1. Check logs with `--log-level DEBUG`
2. Verify permissions with cloud CLI tools
3. Test individual collectors/services
4. Review [Required Permissions](PERMISSIONS.md) documentation

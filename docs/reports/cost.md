# Cost Report

The cost report (`lib/reports/cost.py`, `scripts/generate_cost_report.py`) is a dedicated, cost-only Excel
workbook: executive summary with KPIs, breakdowns by provider/category/service/account, a monthly trend
chart, and a cost-optimization recommendations sheet.

⚠️ **Read this before using it.** The module's own docstring and `--help` text describe an input pair,
`cca_cost_inv_*.json` / `cca_cost_sum_*.json`, that was produced by a standalone `cost_collect.py` script.
**That script was removed in the v2 refactor** (see [docs/collectors/cost.md](../collectors/cost.md)); cost
collection now happens inside `collect.py --cloud <cloud>`, which writes `cca_<cloud>_costs_<time>.json`
instead. The good news: that file's schema (`records` with `provider`/`category`/`service`/`cost`/
`period_start`/`account_id` fields) happens to still satisfy what this report's `analyze_costs()` actually
reads, so pointing `--inventory` at the real collector output works. The current
[docs/collectors/cost.md](../collectors/cost.md) already recommends exactly this.

## Basic Usage

```bash
python scripts/generate_cost_report.py --inventory cca_aws_costs_<time>.json --summary cca_aws_costs_<time>.json --output cost_report.xlsx
```

⚠️ **Both `--inventory`/`-i` and `--summary`/`-s` are required by argparse, but `--summary`'s content is
never read.** `generate_excel_report()` loads the summary file and passes it into `analyze_costs(inventory,
summary)`, but the `summary` parameter is unused inside that function; only `inventory`'s `records`/
`total_cost`/`period`/`provider` fields drive every number in the workbook. In practice, pass the same real
cost file to both flags (as shown above) to satisfy the required argument. Do not expect a `--summary` file
with different content to add or change anything.

## How Each Sheet's Values Are Determined

All of them are built from one aggregation pass, `analyze_costs()`, over the `--inventory` file's `records`
list. Every record needs `provider`, `category`, `service`, `cost`, `period_start` (used as `YYYY-MM` for
monthly grouping), and optionally `account_id`.

- **`totals.total_cost`** and **`totals.total_records`** come straight from the inventory file's top-level `total_cost`/`total_records` fields, **not** a sum over `records` - if those top-level fields are stale or missing relative to the actual `records` list (e.g. a hand-edited or partially-merged file), the Executive Summary's headline number will not match what the detail sheets, which do sum `records` themselves, add up to.
- **By Provider / By Category / By Service / By Account**: each is a straight `sum(record['cost'] for ...)` grouped by that field, with percentages computed against `totals.total_cost` (see the caveat above, since that denominator isn't itself a sum of the same records). The Account Detail sheet is only added to the workbook if more than one distinct `account_id` appears across all records.
- **Monthly Trends**: grouped by `record['period_start'][:7]`. Since each collector run's cost file covers one billing period (e.g. one month per `collect.py` invocation), this sheet will almost always say "No monthly trend data available (single month analysis)" unless the `records` list you hand it already spans multiple distinct months, which only happens if you've concatenated multiple runs' records into one file yourself. The line chart is only added when more than one month is present.
- **Cost Optimization recommendations**: `generate_optimization_recommendations()`. These are **not based on any specific identified waste** - they're generic, hardcoded percentage guesses triggered by category totals being present at all:
  - Any `ec2_snapshot` or `rds_snapshot` category cost > 0 triggers "Review Snapshot Retention" with a flat **30%** potential-savings estimate (bumped to `priority: High` only if that cost exceeds 30% of total cost, never based on actual snapshot age/redundancy analysis).
  - Any service name containing `"vault"` or `"backup"` (case-insensitive substring match) triggers "Optimize Backup Vault Storage" at a flat **20%** estimate.
  - More than one provider present, with the most expensive provider costing more than double the least expensive, triggers "Balance Multi-Cloud Backup Costs" at **25%** of the *difference* between them.
  - If none of the above fired and total cost is nonzero, a generic "Enable Intelligent Tiering" recommendation at **15%** is added as a catch-all.
  
  None of these percentages are derived from the customer's actual snapshot ages, retention policies, or storage tiers. Don't present the "Potential Savings" column as a modeled estimate; it's a flat rule-of-thumb percentage applied to whichever category happened to have nonzero cost.
- **Raw Data**: every record, unaggregated, as it appears in the `records` list.

## Known Limitations Checklist

- [ ] Did you pass the collector's real cost file to **both** `--inventory` and `--summary`? The second flag's content is otherwise just dead weight required to satisfy argparse.
- [ ] Does `totals.total_cost` (Executive Summary) match the sum of every detail sheet's line items? If not, the inventory file's top-level `total_cost` field is out of sync with its own `records` list.
- [ ] Are you about to tell a customer a specific dollar figure for "potential savings"? Every number on the Cost Optimization sheet is a flat 15-30% heuristic, not a measured opportunity. Say so explicitly if you forward this sheet.
- [ ] Is this a multi-month analysis? Confirm the input file's `records` actually contains multiple distinct `period_start` months; a single `collect.py` run's cost file won't.

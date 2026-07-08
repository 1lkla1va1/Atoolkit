# v8.6 Plan: Turn v8.5.2 Into a Real SRC Operating System

> **Review & Implementation Notes (2026-07-08)**
>
> - Section 1 Hotfix: input-validation.json 实际 **零命中** forbidden words，不需要修。真正的 self-check blocker 是 `knowledge.py:25` 的 `__file__` NameError → 已修复为 `_get_card_dir()` fallback 函数。
> - `skip_surfaces` bug 确认：从 blackboard import 后从未消费 → 已在 orchestrator 中接入 `state.set_cell(SKIPPED)`。
> - Schema v2 保留了 `total_runs` + `last_run`（Intent 衰减依赖），新增 `domains_covered` / `surface_index`。
> - Section 2~7 全部实现：`--project`/`--target-domains`/`--surface-budget`/`--intent-budget` CLI 参数；`engine/business_graph.py` + `engine/scheduler.py` 新模块；Intent 生命周期扩展 (claimed/deferred/superseded + 结构化 reason)；summary.json v8.6 字段。

## Summary

The thing I’m least confident about is real-world uplift size; the thing you may be missing is that the core bottleneck is no longer “model ability,” but durable runtime substrate: accounts, traffic, business graph, cross-run memory, trustworthy negatives, and scheduling.

This plan upgrades v8.5.2 from a promising Fact-Intent architecture into an executable core skill. It covers both the design/drafting work and the implementation path.

## Drafting Plan

Create one design document: `design/迭代方案/迭代方案v8.6_Runtime_Realized_SRC_OS.md`.

The draft must include:

- **Problem statement:** v8.5.2 has Fact-Intent, but runtime state is incomplete: self-check blocked by knowledge card validation, blackboard path mismatch, `skip_surfaces` unused, no real business graph, no CLI domain control.
- **North Star:** every authorized run must produce one of three durable outputs: proven finding, trustworthy negative, or high-quality pending intent.
- **Non-goals:** no unsafe exploitation expansion, no payload catalog, no unauthorized scanning, no replacing human-controlled account/scope prep.
- **Architecture:** target project state, business graph, blackboard, run scheduler, Fact-Intent lifecycle, coverage ledger integration.
- **Acceptance gates:** self-check pass, dry-run pass, two-run blackboard inheritance, domain-scope sorting, negative carryover, intent lifecycle, business graph generation.

The draft should explicitly say: v8.6 is not a prompt upgrade; it is a runtime contract upgrade.

## Implementation Plan

### 1. Release-Blocking Hotfix

Fix `knowledge/cards/input-validation.json` so it passes `engine/knowledge.py` validation.

- Remove forbidden wording such as `payload` / `bypass` from the input-validation card.
- Preserve the intent using neutral language: “test vector,” “encoding variant,” “input family,” “blocked response.”
- Run `python3 run.py --self-check` until all assertions pass.
- Run a dry-run session with two endpoints and confirm it reaches summary output.

### 2. Project-Level State Layout

Add a target-project concept while keeping old `runs/<sid>` compatibility.

Public interface:

```bash
python3 run.py \
  --project t_example \
  --target https://t.example \
  --authz authz.md \
  --target-domains auth,txn \
  --surface-budget 80 \
  --intent-budget 15
```

Default behavior:

- If `--project` is omitted, derive `target_slug` from target host.
- New state path becomes:

```text
runs/targets/<target_slug>/
  blackboard.json
  business_graph.json
  run_scope.json
  sessions/<sid>/
```

- Existing `runs/<sid>` sessions remain readable for backward compatibility.

### 3. Blackboard Becomes Authoritative

Update `engine/graph.py` and `engine/orchestrator.py` so blackboard data changes actual execution.

Blackboard schema v2:

```json
{
  "schema_version": "2.0",
  "facts": [],
  "intents": [],
  "negatives": [],
  "dead_ends": [],
  "domains_covered": {},
  "surface_index": {},
  "last_updated": ""
}
```

Required behavior:

- Confirmed facts are imported as known facts.
- Depth-sufficient negatives seed matching surfaces as `not_vulnerable`.
- Shallow negatives remain open and are not treated as closure.
- Dead ends become `not_applicable` only with reason.
- Pending high-priority intents are injected before normal surface testing.
- Completed or abandoned intents are not re-shown.

### 4. Business Graph Runtime

Add `engine/business_graph.py`.

It should generate and maintain `business_graph.json` from inventory, planner domains, roles, params, and observed candidate/fact metadata.

Minimum model:

```json
{
  "roles": [],
  "objects": [],
  "flows": [],
  "endpoint_map": {
    "POST /api/refund": {
      "domains": ["txn", "idor"],
      "objects": ["order", "refund"],
      "roles": ["user", "merchant", "admin"],
      "state_effect": "refund_created"
    }
  }
}
```

Required behavior:

- Every high-value surface should map to domain, object, role, and likely state effect.
- Every confirmed fact should update the graph.
- LOW_ROI is invalid if high-value business graph nodes remain untested.

### 5. Scheduler and Run Scope

Add `engine/scheduler.py`.

Inputs:

- `blackboard.json`
- `business_graph.json`
- current inventory
- target domains
- surface budget
- intent budget

Output:

```json
{
  "target_domains": ["auth", "txn"],
  "surface_budget": 80,
  "intent_budget": 15,
  "must_test": [],
  "carryover_intents": [],
  "reason": "highest high-value untested domain count"
}
```

Scheduling order:

1. High-priority pending intents
2. High-value target-domain surfaces
3. Surfaces needed to complete a business flow
4. Shallow negatives with signal
5. Newly discovered endpoints
6. Low-value remaining coverage

Domain scope is advisory: target-domain surfaces sort first, but cross-domain Fact-Intent chains can override.

### 6. Fact-Intent Lifecycle Hardening

Extend intent statuses:

```text
pending
claimed
completed
blocked
deferred
abandoned
superseded
```

Do not mark an intent deferred merely because it appeared three times. Require a structured reason:

- missing account
- missing object state
- human verification needed
- insufficient traffic
- no observable signal after evidence-backed attempts

Each intent must record attempts and outcome summary.

### 7. Reporting and Summary Output

Extend `summary.json` with:

```json
{
  "project_path": "...",
  "blackboard_path": "...",
  "business_graph_path": "...",
  "run_scope_path": "...",
  "graph_stats": {},
  "scheduler_stats": {},
  "domains_covered": {}
}
```

Also generate `run_summary.md` inside the target project directory after each run.

## Test Plan

Required tests before v8.6 is considered usable:

- `--self-check` passes.
- `--dry-run` with endpoints completes.
- Two-run test proves blackboard inheritance.
- Depth-sufficient negative is skipped in run 2.
- Shallow negative is carried forward as open work.
- Confirmed candidate creates Fact and Intent.
- Completed intent does not reappear.
- `--target-domains auth,txn` sorts matching surfaces first without deleting others.
- `business_graph.json` is created and contains endpoint-domain-object mappings.
- `summary.json` includes all new state paths and stats.

## Assumptions and Defaults

- Default project slug is derived from target host.
- Domain scope is soft priority, not hard filtering.
- Existing `runs/<sid>` behavior remains compatible.
- Knowledge cards stay payload-free.
- Human remains responsible for authorization, fresh credentials, role/account provisioning, and out-of-scope decisions.
- v8.6 success means reliable multi-run compounding, not a guaranteed bounty rate.

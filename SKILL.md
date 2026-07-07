---
name: Atoolkit
description: Authorized AI-assisted SRC/bug-bounty vulnerability research toolkit. Use whenever the user wants to read, install, configure, or run this Atoolkit package; mentions SRC 漏洞挖掘, 授权靶场, bug bounty, Codex AGENTS.md, /src, Guardian 质检, PoC 复验, or model-independent security testing automation. Only proceed for clearly authorized defensive testing or educational lab contexts.
version: 8.4.0
---

# Atoolkit Skill

Use this skill to operate this repository as a skill package for **authorized** SRC / bug-bounty vulnerability research workflows.

## First principles

- Treat all active testing as authorized security work only. If target scope, authorization, or credentials are missing, ask for them before sending network requests.
- Stay inside the scope recorded in `runs/<sid>/authz.md` or the user-provided authorization text.
- Do not perform destructive actions, DoS, credential theft, persistence, lateral movement, or out-of-scope probing.
- Vulnerability reports must prove a **result**, not just a phenomenon. No reproducible PoC means no report.

## Project root

Paths in this skill are relative to the skill package root.

## Reading guide

- For a quick orientation: read `run.py`.
- For the core behavior rules injected into agents: read `skill/核心技能文件.v3.md`.
- For Codex `/src` usage: read `codex/prompts/src.md`.
- For one-command orchestration: read `run.py`, then relevant files in `engine/`.
- For report quality gates / Guardian behavior: read `engine/enforce.py`.
- For deterministic replay verification: read `engine/verify.py`.
- For Phase 0 recon: read `skill/recon-checklist.md`.
- For Skill Mode runtime (without `run.py`): read [Skill Mode Runtime](#skill-mode-runtime) below.
- For Fact-Intent architecture: read `engine/graph.py`, then [Fact-Intent Protocol](#fact-intent-protocol) below.
- For SRC real-world workflow: read [SRC Workflow](#src-workflow) below.

## Skill Mode Runtime

When not using `run.py` engine, run by this framework:

### Startup sequence

1. Read `authz.md` to confirm authorization scope.
2. Read `hint.md` to confirm testing strategy and priorities.
3. Execute Phase 0 recon per `skill/recon-checklist.md`, output `attack_surface_list.md`.
4. Initialize the coverage ledger from the attack surface list.
4.5 If `state/` directory exists with prior session files, read all files to restore testing context.
5. Sort the test queue by `hint.md` priority.

### Per-surface loop

For each surface in the queue:

1. Declare current surface: endpoint / method / param / role / risk_tags.
2. Look up the corresponding knowledge card summary for the risk_tags.
3. Execute testing; for each risk dimension respond: `CANDIDATE` / `NONE:<reason>`.
4. Write evidence (finding package or negative record).
4.5 Write state to disk per compression anchor protocol (§10 of core skill file).
5. Update coverage ledger status.
6. Run the termination self-check (see §9 of `skill/核心技能文件.v3.md`): depth floor met? Time to pivot?

### Termination self-check

At session end, run all checks in the Skill Mode self-check list (§9 of the core skill file) -- not duplicated here to avoid multi-source definitions.

## Fact-Intent Protocol

Testing follows a discovery-driven loop: every confirmed finding automatically
generates exploration directions (Intents) that guide subsequent testing.

### Pre-flight checklist (mandatory before Phase 1)

Before starting any testing, verify:
- [ ] All required test accounts are available (minimum: 2 users, 2 merchants
      of same tier, 1 admin — 5 accounts total for e-commerce targets)
- [ ] Session cookies are fresh and validated
- [ ] `state/` directory is initialized with `session_state.md`

### Intent Generation (after each confirmed finding)

When a finding is confirmed, generate 1-3 Intents based on the finding type:

| Finding type | Auto-generated Intent direction |
|---|---|
| Auth component weakness (chain_feasible) | Chain exploitation: end-to-end attack |
| Info disclosure (keys/signs/tokens) | Credential use: forge requests or escalate |
| SQLi confirmed | Data extraction: read sensitive tables |
| Multi-param endpoint confirmed | Cross-param: test other param types |
| WAF-blocked negative | Bypass retry: encoding variants |
| Business logic (payment/refund/points) | Fund chain: construct full attack chain |
| IDOR confirmed | Impact escalation: batch access / broader scope |
| SSRF confirmed | Internal probe: metadata / internal services |

### Intent Lifecycle

- **pending**: Generated but not yet tested
- **in_progress**: Currently being tested
- **completed**: Testing done, may have spawned new Facts
- **abandoned**: Tested but no value found (record reason)

Limits: max 5 Intents/Fact, max 30 pending globally, max 3 chain depth.

### Phase 2 Work Queue

Phase 2 merges two sources:
1. Inherited Intents from Phase 1 (from `fact_intent.json`)
2. Remaining surfaces not yet tested

Priority: high Intents > untested surfaces > medium Intents > low Intents.

### Recording

Write to `state/<agent>/fact_intent.json`. Update status after testing.
New findings create new Facts that may spawn further Intents.

## Cross-Run Protocol

For targets requiring multiple runs (large SRC programs, 50+ endpoints):

### Before testing (run startup)

1. Check if `runs/{target}/blackboard.json` exists
2. If yes:
   - Read all confirmed facts → mark as known, skip re-testing
   - Read all depth-sufficient negatives → mark as not_vulnerable, skip
   - Read all dead ends → mark as excluded, skip
   - Read pending intents → add to work queue (high priority)
   - Read domain scope from `run_scope.json` → filter test surfaces
3. If no: first run, proceed normally

### After testing (run shutdown)

1. Export all new facts, intents, negatives to blackboard
2. For each new confirmed fact: run Intent generation rules
3. Unfinished intents → write as pending to blackboard
4. Update domain coverage statistics
5. Save `blackboard.json` and generate `run_summary.md`

### Directory structure

    runs/{target}/
      blackboard.json          # persistent across runs
      business_graph.json      # endpoint→domain mapping
      run_scope.json           # current run's domain focus
      sessions/run_NNN/        # individual run data (unchanged)

## Domain Scope Declaration

Before starting Phase 0, declare this run's domain scope:

1. Check `runs/{target}/blackboard.json` → read `domains_covered`
2. Identify domains with status "not_started" or "partial"
3. Select 1-3 domains for this run (recommended: pick domains with
   highest untested surface count)
4. Write `runs/{target}/run_scope.json` with target_domains
5. All surface planning must respect the declared domain scope

If this is the first run (no blackboard exists), default to:
- Run 1: `["auth", "txn"]` (highest value domains first)
- Run 2: `["idor", "input"]` (coverage domains)
- Run 3: `["admin", "file", "info"]` (remaining domains)

**Domain scope is advisory, not a hard wall.** If during testing you
discover cross-domain findings (e.g., an auth token that grants access
to a txn endpoint), follow the Fact-Intent chain regardless of domain
boundaries. Record cross-domain discoveries in the blackboard for the
next run to pick up.

## SRC Workflow

End-to-end workflow for real-world SRC / bug-bounty targets.

### Phase A: Human-controlled prep

- Walk the target's business flows, register accounts, obtain fresh cookies.
- Write `authz.md` (scope, accounts, boundaries).
- Write `hint.md` (testing strategy, priority order).

### Phase B: Phase 0 recon (agent)

- Execute per `skill/recon-checklist.md`.
- Output: `attack_surface_list.md`.

### Phase C: Automated testing (agent, parallelizable)

- Test surfaces by coverage ledger priority.
- For each surface output `CANDIDATE` / `NONE` / `confirmed` / `negative`.
- Write finding packages and negative records to disk.

### Phase D: Human review

- Audit findings, verify in browser.
- Add business-logic insights.
- Mark false positives.

### Phase E: Patch + report (agent)

- Run additional tests based on human review feedback.
- Generate `final_report.md`, `coverage_gaps.md`, `summary.json`.

## Common workflows

### 1. Install for Codex mode A

```bash
cp codex/AGENTS.md ~/.codex/AGENTS.md
mkdir -p ~/.codex/prompts
cp codex/prompts/src.md ~/.codex/prompts/src.md
```

### 2. Run mode B dry-run

Use this before real target testing:

```bash
python3 run.py --dry-run --target https://t.example --authz "demo"
```

### 3. Run an authorized session

Only after the user provides scope and fresh human-obtained credentials:

```bash
python3 run.py --target https://授权目标 --authz "已授权说明" --cookie 'session=…'
```

For Bearer auth use:

```bash
python3 run.py --target https://授权目标 --authz "已授权说明" --bearer 'eyJ…' --auth-scheme bearer
```

If deterministic IDOR replay is requested, require at least two authorized identities and a safe victim marker, then use `--identity` and `--victim-marker` as documented in `run.py`.

### 4. Run Skill Mode session (QoderWork / any agent)

1. Read `skill/核心技能文件.v3.md` (or `codex/AGENTS.md`).
2. Read `authz.md` + `hint.md`.
3. Execute Phase 0 per `skill/recon-checklist.md`.
4. Run the per-surface loop with self-check.
5. Write findings + negative records.
6. Run termination self-check.
7. Output `summary.json`.

## Skill Mode Finding Schema

Skill Mode uses a streamlined schema (8 required + 3 conditional fields). Engine mode continues to use the full `engine/reporting/schema.py`.

### Required fields

| # | Field | Description |
|---|---|---|
| 1 | `schema_version` | Always `"1.0"` |
| 2 | `id` | Finding ID (e.g. `finding_auth_001`) |
| 3 | `title` | One-sentence result description (not phenomenon) |
| 4 | `severity` | `P1` / `P2` / `P3` |
| 5 | `vuln_type` | e.g. `idor`, `sqli`, `xss`, `ssrf`, `auth-bypass`, `amount-tamper` |
| 6 | `target` | Endpoint + method (e.g. `POST /api/user/refund.php`) |
| 7 | `risk.proven_impact` | Proven business impact (never "possible" / "suspected") |
| 8 | `poc` | Object with `file` (e.g. `poc.sh`) and `steps` (list of curl commands) |
| -- | `proof_packets` | List of `{request_file, response_file}` pairs |

### Conditional fields

| Field | Required when |
|---|---|
| `source_proof` | Request was constructed from JS / frontend source code -- provide file and line number |
| `crypto_chain` | Finding involves encryption / signing -- provide algorithm and key source |
| `manual_burp_replay` | P1/P2 finding where human wants Burp reproduction steps (optional in Skill Mode; agent cannot run Burp Suite) |
| `chain_assessment` | Every CANDIDATE/finding must include chain exploitation assessment -- fields: `chain_feasible` (bool), `chain_path` (string), `final_impact` (string), `blockers` (list) |

### JSON example

```json
{
  "schema_version": "1.0",
  "id": "finding_auth_001",
  "title": "Refund amount has no upper-bound check, attacker can refund more than order total",
  "severity": "P1",
  "vuln_type": "amount-tamper",
  "target": "POST /api/user/refund.php",
  "risk": {
    "proven_impact": "Attacker refunded 99999 yuan on a 100 yuan order, balance credited successfully"
  },
  "poc": {
    "file": "poc.sh",
    "steps": [
      "curl -X POST https://t.example/api/user/refund.php -d 'order_no=O001&refund_amount=99999' -H 'Cookie: session=...'"
    ]
  },
  "proof_packets": [
    {"request_file": "request_1.http", "response_file": "response_1.http"},
    {"request_file": "request_2.http", "response_file": "response_2.http"}
  ]
}
```

## Reporting standard

When reviewing or writing findings, enforce the core rules from `skill/核心技能文件.v3.md`:

- Garbage findings such as CORS alone, sourcemap, missing security headers, rate-limit absence, fingerprinting, Self-XSS, and unproven claims are not valid reports.
- Valid reports need P1/P2/P3 severity, a concrete target, proven impact, reproducible curl/raw HTTP PoC, and response evidence.
- Stop at enough evidence to prove impact; do not escalate exploitation beyond what is necessary for proof.

## Maintenance workflow

- Edit only `skill/核心技能文件.v3.md` for core rule changes.
- Regenerate `codex/AGENTS.md` with `bash codex/regen_agents.sh` after core rule changes.
- Keep SKILL.md and AGENTS.md in sync.

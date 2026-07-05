---
name: Atoolkit
description: Authorized AI-assisted SRC/bug-bounty vulnerability research toolkit. Use whenever the user wants to read, install, configure, or run this Atoolkit package; mentions SRC 漏洞挖掘, 授权靶场, bug bounty, Codex AGENTS.md, /src, Guardian 质检, PoC 复验, or model-independent security testing automation. Only proceed for clearly authorized defensive testing or educational lab contexts.
version: 8.2.1
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
- For parallel agents: read [Parallel Agent Protocol](#parallel-agent-protocol) below.
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

## Parallel Agent Protocol

When multiple agents run in parallel, use these conventions to avoid ID collisions.

### Direction naming convention

| Agent direction | Finding ID prefix | Negative ID prefix |
|---|---|---|
| Auth & verification | `finding_auth_001`, `finding_auth_002`, ... | `negative_auth_001`, ... |
| Transaction & payment | `finding_txn_001`, `finding_txn_002`, ... | `negative_txn_001`, ... |
| IDOR & privilege | `finding_idor_001`, `finding_idor_002`, ... | `negative_idor_001`, ... |
| Input validation | `finding_input_001`, `finding_input_002`, ... | `negative_input_001`, ... |

Each agent writes its own coverage ledger file (`coverage_auth.md`, `coverage_txn.md`, `coverage_idor.md`, `coverage_input.md`) and only updates the surfaces assigned to it.

### Aggregation phase

After all agents complete:

1. Merge all findings into a unified `coverage_ledger.md`.
2. **Seam check (v7.1 · must run before de-dup):**
   a. List all discovered endpoints (de-duplicated endpoint set).
   b. For each endpoint, list all parameters and classify by type:
      - State params (status/audit_status/state) → auth agent
      - Text params (name/description/keyword/reason) → input agent
      - Amount params (amount/price/refund_amount/use_points) → txn agent
      - ID params (order_no/product_no/user_id/merchant_id) → idor agent
   c. Check whether each endpoint's each parameter type has a test record from the responsible agent.
   d. Uncovered "endpoint × parameter type" combinations → mark as `seam_gap`, queue for re-test.
3. Re-test seam gaps (aggregation agent executes directly or assigns to the responsible direction agent).
4. De-duplicate by root cause: `endpoint + root_cause + affected_role`.
5. Renumber to `finding_001`, `finding_002`, ... (keep prefix for traceability).
6. Generate `summary.json`.

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

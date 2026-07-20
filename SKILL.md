---
name: Atoolkit
description: Authorized AI-assisted SRC/bug-bounty vulnerability research toolkit. Use whenever the user wants to read, install, configure, or run this Atoolkit package; mentions SRC 漏洞挖掘, 授权靶场, bug bounty, Codex AGENTS.md, /src, Guardian 质检, PoC 复验, or model-independent security testing automation. Only proceed for clearly authorized defensive testing or educational lab contexts.
version: 9.1.0
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
- For QoderWork/Direct execution: read `skill/runtime-hot-path.md` first; load the full core/reference only when the current cell needs it.
- For Fact-Intent architecture: read `engine/graph.py`, then [Fact-Intent Protocol](#fact-intent-protocol) below.
- For SRC real-world workflow: read [SRC Workflow](#src-workflow) below.

## Skill Mode Runtime

There are two Skill trust levels, plus a backend capability gate:

- **Attested Wrapped Skill Mode (eligible for verification)**: an external host invokes
  `python3 -m engine.skill_wrapper`, freezes the run plan outside the agent
  writable root, waits for the agent to stop, then runs the exactly-once
  finalizer. This is the only Skill path eligible to set
  `authority_trusted=true`, and only when its supervisor can attest that every
  descendant is contained and quiescent.
- **Bundled local wrapper (diagnostic today)**: a POSIX process group cannot
  contain descendants that call `setsid()`. The bundled backend therefore
  reports `process_containment_verified=false`, refuses ProjectState mutation,
  and exits incomplete even though its session artifacts remain reviewable.
- **Direct Skill Mode (diagnostic)**: the same agent invokes init/finalize in
  its own writable workspace. Its artifacts are useful for review, but the
  finalizer returns untrusted/incomplete and must never claim tamper-resistant
  delivery.

Direct/QoderWork should use `engine.skill_runtime` for deterministic session
state even though it remains untrusted. This closes execution feedback and
multi-agent synchronization; it does not weaken the authority boundary.

v9 threat mode starts from a validated business feature graph and explicit
security invariants. Risk tags route knowledge; they do not create the coverage
denominator. Direct runs without both threat artifacts remain compatible but
are marked `legacy_risk/planning_degraded=true` and can never be report-ready.
Each frozen threat compiles into an Experiment Contract. Engine consumes
evidence-bound `EXECUTION_EVENT` lines; Direct observations carry
`completed_obligations`. Host projections dynamically queue missing depth,
barrier recovery, and proof repair without changing the frozen denominator.
Every frozen/open object is additionally reduced into exactly one
`miss-attribution.json` cause. Its deterministic continuations become
`next-run-agenda.json` and, only through a trusted finalizer, pending
ProjectState Intents that the next scheduler must consume. Unknown states fail
attribution closed; they are never counted as coverage.
Engine materializes raw multi-identity headers only after Planning in the
restricted Attack `identities.json`; models must keep labels isolated and must
never copy that file into a report.

Use Engine Mode or the wrapper for canonical session diagnostics. Do not claim
trusted cross-run delivery with the bundled Codex backends until an attested
cgroup/job/container supervisor is integrated.

### Startup sequence

1. Read `authz.md` and confirm the absolute primary target and every authorized scope.
2. Before the agent starts, the external wrapper creates the authority identity,
   `run_manifest.json`, and frozen `run_plan.json`. A manifest/run-plan failure
   is a hard stop. Running `init-manifest` from Direct Skill Mode is diagnostic,
   not an independent trust anchor.
3. Load `<project>/project_state.json` when present. It is the cross-run authority; `blackboard.json`, `business_graph.json`, and summaries are derived views only.
4. In Direct/Qoder mode, run `python3 -m engine.skill_runtime preflight --run-dir <session> --target <url>` before fresh black-box recon. Read `hint.md`, execute Phase 0 per `skill/recon-checklist.md`, then run `engine.skill_runtime init ...` before attack testing to initialize JSON inventory, coverage, execution contracts and queue. These files are session-authoritative diagnostics but not cross-Run authority. `attack_surface_list.md` is a derived human view, not the closure source.
5. Merge new inventory into project inventory by asset + method + path. Unknown methods stay unresolved and must not default to GET.
6. Restore coverage only for an exact asset + method/path + param + role + vuln-class cell, then schedule pending Intents and still-open cells.

### Per-surface loop

For each surface in the queue:

1. Declare current surface: endpoint / method / param / role / risk_tags.
2. Look up the corresponding knowledge card summary for the risk_tags.
3. Execute testing; for each risk dimension respond: `CANDIDATE` / `NONE:<reason>`.
4. Write evidence (finding package or negative record).
4.5 Complete only obligation IDs present in `execution-queue.json`, write an immutable per-agent observation, and run `engine.skill_runtime checkpoint` after each exact cell, at each phase boundary, and every 10 cells in Direct/Qoder mode.
5. Update coverage ledger status.
6. Run the termination self-check (see §9 of `skill/核心技能文件.v3.md`): depth floor met? Time to pivot?

### Termination self-check

At session end, run all checks in the Skill Mode self-check list (§9 of the
core skill file). The external wrapper must then stop the saved agent process
group and call the shared finalizer. Process-group cleanup alone is not
containment, so the bundled wrapper remains diagnostic. Do not use the loose
`runtime_manifest receipt` command as a completion claim; it only produces a
diagnostic receipt.

```bash
python3 -m engine.skill_wrapper \
  --run-dir <session> --project-dir <project> \
  --authority-dir <outside-agent-writable-root> \
  --target <url> --inventory <inventory.json> \
  --feature-graph <feature-graph.json> --threat-model <threat-model.json> \
  --provider <provider> --model-name <model> -- \
  codex exec <task>
```

Finalizer exit codes are `0=verified complete`, `1=invalid/conflict`,
`2=incomplete, uncontained, or direct-self-authorized`, `3=operational error`.

Direct diagnostic commands:

```bash
python3 -m engine.skill_runtime preflight --run-dir <session> --target <url>
python3 -m engine.skill_runtime init --run-dir <session> --target <url> \
  --inventory <inventory.json> --recon-dir <recon> \
  --feature-graph <feature-graph.json> --threat-model <threat-model.json>
python3 -m engine.skill_runtime observe --run-dir <session> \
  --agent-id <agent> --input <observation.json>
python3 -m engine.skill_runtime checkpoint --run-dir <session>
```

The observation/barrier/execution-obligation contract is documented in
`skill/runtime-hot-path.md`.
Use `--legacy-risk-plan` on the wrapper only for an intentional degraded
compatibility run. A threat-mode Finding additionally requires
`feature_point.feature_id` and `claim.threat_id`.

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

1. Load or migrate `runs/targets/{target}/project_state.json` (schema 3). Schema 1/2 cells are retained as stale evidence but cannot close v3 exact-class cells without retesting.
2. Merge project inventory into this session before recon; recon is incremental, not a reset.
3. Restore only exact role-aware coverage cells. Unknown role is not a wildcard, and legacy facts without evidence remain pending revalidation.
4. Add every pending Host continuation in priority order, then high-priority
   inventory-bound model Intents and open/high-value cells. A fully closed
   matrix with no pending Intent is a valid no-work run and must not call a model.

### After testing (run shutdown)

1. Run deterministic finding validation; only accepted + proof-confirmed + `claim.kind=root_finding` entries may enter the project finding registry.
2. For an attested run, the shared finalizer commits the outcome whitelist through a journaled,
   exactly-once transaction. Invalid proof commits no project truth;
   incomplete-with-findings commits only proof-valid roots and deterministic
   derived surfaces. An untrusted run commits no project truth at all.
3. Regenerate `blackboard.json`, `business_graph.json`, `run_scope.json`, and summaries as compatibility views; never merge them back as equal authorities.
4. Bind `run_receipt.json` to an immutable project commit snapshot and the
   host authority anchor. Never bind the mutable live `project_state.json`.
5. Treat `miss-attribution.json` and `next-run-agenda.json` as mandatory v9
   delivery artifacts. An incomplete trusted Run may commit only Host-created
   continuations; it may not commit model-authored closure or negatives.

### Directory structure

    runs/{target}/
      project_state.json       # authoritative, revisioned cross-run truth (schema 3)
      .atoolkit/manifests/     # authority copies outside session write scope
      blackboard.json          # derived compatibility view
      business_graph.json      # derived endpoint→domain view
      run_scope.json           # current run's domain focus
      run_history/             # per-run committed summaries
      sessions/run_NNN/        # manifest, evidence, validation, receipt

An optional `sessions/run_NNN/dead_ends.json` may close a cell across runs only
when it carries the exact asset/method/path/param/role/vulnerability identity,
explicit `namespace`, `param_location`, `subject_role`, and `object_kind`
fields (empty strings are valid), an enumerated not-applicable reason code, a
concrete refutation, and physical evidence references. Ordinary model/budget
skips never enter project truth.

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
- Write only canonical Finding/negative/dead-end evidence packages and close
  the machine ledger. The agent must not generate or edit `final_report.md` or
  `summary.json`.
- Let the external finalizer regenerate and receipt-bind the Canonical report,
  then require `python3 run.py submission <session>` to return eligible before
  treating it as an SRC submission.

## Common workflows

### Audit old runs and verify a submission

Both commands are offline/read-only. `audit` explains contract gaps without
promoting legacy Markdown; `submission` accepts only the finalizer-rendered,
redacted report whose hash is bound to the authority receipt.

```bash
python3 run.py audit /path/to/session
python3 run.py submission /path/to/session
```

### 1. Use as an independent Codex project

```bash
cd /path/to/Atoolkit
python3 run.py --doctor
```

Codex loads the project-root `AGENTS.md`. Do not overwrite `~/.codex/AGENTS.md` or an existing `/src` alias. Installing a global alias is a separate, explicit user action and is never required for this project.

### 2. Run mode B dry-run

Use this before real target testing:

```bash
python3 run.py --dry-run --target https://t.example --authz "demo"
```

### 3. Run an authorized session

Only after the user provides scope and fresh human-obtained credentials:

```bash
python3 run.py --target https://授权目标 --authz "已授权说明" --cookie 'session=…' \
  --allow-unrestricted-egress
```

The current Codex backend cannot prove pre-exec egress enforcement. Live runs
therefore fail closed unless `--allow-unrestricted-egress` is explicitly
accepted; this downgrade is recorded and cannot produce an
`authorization_assurance=preexec_enforced` claim.

For Bearer auth use:

```bash
python3 run.py --target https://授权目标 --authz "已授权说明" --bearer 'eyJ…' \
  --auth-scheme bearer --allow-unrestricted-egress
```

If deterministic IDOR replay is requested, require at least two authorized identities and a safe victim marker, then use `--identity` and `--victim-marker` as documented in `run.py`.

### 4. Run Skill Mode session (QoderWork / any agent)

1. From an external host terminal, invoke `python3 -m engine.skill_wrapper`
   with run/project/authority directories and the `codex exec` command.
2. The wrapper creates manifest and frozen run plan before the agent starts.
3. The agent restores the supplied project projection, executes incremental
   Phase 0, and writes canonical JSON ledgers/findings/evidence in its run root.
4. The wrapper waits for agent termination, snapshots inputs, evaluates proof
   and closure, anchors/verifies the session receipt, then writes delivery
   status. It performs the exactly-once project commit only when an external
   containment backend has supplied a verified attestation; the bundled local
   backend deliberately refuses that promotion.
5. Direct agent invocation of reporting/receipt remains diagnostic and exits
   incomplete when it cannot prove an external authority boundary.

## Skill Mode Finding Schema

Skill Mode and Engine Mode now use one proof contract. The former streamlined schema is accepted only as legacy input and cannot become an accepted finding until migrated and revalidated.

### Required fields

| # | Field | Description |
|---|---|---|
| 1 | `schema_version` | Canonical value `1` (`"1.0"` is legacy-compatible input) |
| 2 | `id` | Finding ID (e.g. `finding_auth_001`) |
| 3 | `title` | One-sentence result description (not phenomenon) |
| 4 | `severity` | `P1` / `P2` / `P3` |
| 5 | `vuln_type` | e.g. `idor`, `sqli`, `xss`, `ssrf`, `auth-bypass`, `amount-tamper` |
| 6 | `target` | Endpoint + method (e.g. `POST /api/user/refund.php`) |
| 7 | `risk.proven_impact` | Proven business impact (never "possible" / "suspected") |
| 8 | `poc` | Object with `file` (e.g. `poc.sh`) and `steps` (list of curl commands) |
| 8.1 | `feature_point.feature_id` | Required in threat-model mode; exact feature compiler identity |
| 8.2 | `claim.threat_id` | Required in threat-model mode; exact threat compiler identity |
| -- | `proof_packets` | Named request/response pairs with a machine-meaningful `phase` |
| -- | `verification` | Evidence profile, observed effect, raw assertions, and class-specific controls |
| -- | `claim` | `kind=root_finding`, invariant/profile, and referenced proof packet IDs |
| -- | `impact_claims` | Separate `proven` effects from `hypothesis`; `risk.proven_impact` must match a proven item |
| -- | `chain_assessment` | `not_tested/hypothesis/partial/proven/refuted`; only `proven` may have proven final impact |

### Conditional fields

| Field | Required when |
|---|---|
| `source_proof` | Request was constructed from JS / frontend source code -- provide file and line number |
| `crypto_chain` | Finding involves encryption / signing -- provide algorithm and key source |
| `manual_burp_replay` | Optional when `poc.steps` already contains at least two reproducible HTTP steps |
| `chain_assessment.proof_refs` | Required only when chain status is `proven`; every referenced step needs raw proof |

### JSON example

```json
{
  "schema_version": 1,
  "id": "finding_auth_001",
  "title": "Refund amount has no upper-bound check, attacker can refund more than order total",
  "severity": "P1",
  "vuln_type": "amount-tamper",
  "target": "POST /api/user/refund.php",
  "risk": {"proven_impact": "Observed balance increased by 99899 after one over-refund"},
  "claim": {
    "kind": "root_finding",
    "profile": "transaction_state_delta",
    "invariant": "credited refund must not exceed paid order amount",
    "proof_packet_ids": ["state_before", "exploit", "state_after"]
  },
  "impact_claims": [{
    "status": "proven",
    "statement": "Observed balance increased by 99899 after one over-refund",
    "proof_refs": ["response_after.http"],
    "marker": "100700"
  }],
  "verification": {
    "status": "confirmed",
    "evidence_type": "business_state_delta",
    "observed_effect": "Balance changed from 801 to 100700",
    "state_delta": "+99899",
    "assertions": [{"file": "response_after.http", "relation": "contains", "value": "100700"}]
  },
  "poc": {
    "file": "poc.sh",
    "steps": [
      "curl -X POST https://t.example/api/user/refund.php -d 'order_no=O001&refund_amount=99999' -H 'Cookie: session=...'"
    ]
  },
  "proof_packets": [
    {"name": "state_before", "phase": "state_before", "request_file": "request_before.http", "response_file": "response_before.http", "evidence_summary": "balance baseline"},
    {"name": "exploit", "phase": "exploit", "request_file": "request_exploit.http", "response_file": "response_exploit.http", "evidence_summary": "over-refund accepted"},
    {"name": "state_after", "phase": "state_after", "request_file": "request_after.http", "response_file": "response_after.http", "evidence_summary": "persistent balance delta"}
  ],
  "chain_assessment": {"status": "not_tested", "chain_feasible": false, "chain_path": "", "final_impact": "", "blockers": [], "proof_refs": []}
}
```

## Reporting standard

When reviewing or writing findings, enforce the core rules from `skill/核心技能文件.v3.md`:

- Garbage findings such as CORS alone, sourcemap, missing security headers, rate-limit absence, fingerprinting, Self-XSS, and unproven claims are not valid reports.
- Valid reports need P1/P2/P3 severity, a concrete target, proven impact, reproducible curl/raw HTTP PoC, and response evidence.
- Authorization findings need physical proof of the expected non-public boundary in `verification.access_expectation`; anonymous HTTP 200 or two accounts seeing the same public content is not a vulnerability.
- RCE, account takeover/session compromise, bulk-data, and race claims require class-specific markers that can be recomputed from raw evidence; narrative impact text is never enough.
- A root finding is counted once. Proven impact may raise severity but is not a second vulnerability; a chain hypothesis is never accepted or scored.
- Stop at enough evidence to prove impact; do not escalate exploitation beyond what is necessary for proof.

## Maintenance workflow

- Edit only `skill/核心技能文件.v3.md` for core rule changes.
- Regenerate root `AGENTS.md` and `codex/AGENTS.md` with `bash codex/regen_agents.sh` after core rule changes.
- Keep SKILL.md and AGENTS.md in sync.

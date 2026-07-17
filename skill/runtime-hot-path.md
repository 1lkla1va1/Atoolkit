# Atoolkit Direct / QoderWork Runtime Hot Path

This is the short operational entry point. Read the full core file only for a
boundary or report question; load knowledge cards only for the current cell.

## 1. Before any request

1. Read `authz.md`; stop on scope ambiguity.
2. Confirm fresh authorized identities and required roles.
3. On a fresh black-box target, create the Direct diagnostic trust boundary
   before the first recon request:

```bash
python3 -m engine.skill_runtime preflight \
  --run-dir <run> --target <authorized-url>
```

4. Complete Phase 0 recon and create the canonical inventory/threat artifacts.
5. Before attack testing, initialize diagnostic machine state:

```bash
python3 -m engine.skill_runtime init \
  --run-dir <run> --target <authorized-url> \
  --inventory <inventory.json> [--recon-dir <recon>] \
  --feature-graph <feature-graph.json> \
  --threat-model <threat-model.json>
```

`runtime-preflight.json` resolves the fresh-target bootstrap problem: it records
that Direct mode is untrusted/incomplete while recon is still building the first
inventory. Missing preflight means the run did not follow the v8.13 runtime path
and must not be described as a complete Atoolkit run.

The feature graph must assign every resolved inventory endpoint and provide
physical evidence for all six discovery channels. The threat model must state
the business invariant, abuse action, observable violation, exact API/param/
role targets and required evidence. Supplying neither file invokes the old
risk-tag planner only as `planning_degraded=true`; supplying one is an error.

Direct mode is always `authority_trusted=false` and cannot update ProjectState
or claim verified delivery. Use `engine.skill_wrapper` with an attested external
supervisor for an authority-eligible run.

## 2. Per exact cell

Take the next entry from `execution-queue.json`:

- exact asset / METHOD / path / param / actor / vuln class;
- exact feature / threat / security invariant / observable violation;
- exact `next_obligations`; do not replace them with a self-authored "full" label;
- read only its `knowledge_card_ids` / `knowledge_hint`;
- run a valid baseline before mutations;
- save raw request and response under the run directory;
- write one immutable observation per agent.

Observation skeleton:

```json
{
  "schema_version": 1,
  "observation_id": "agent-local-unique-id",
  "surface_id": "exact surface_id from coverage-ledger.json",
  "feature_id": "feature id from the queue",
  "threat_id": "threat id from the queue",
  "outcome": "negative",
  "evidence_refs": ["evidence/request-response.http"],
  "completed_obligations": [
    "valid-baseline",
    "exact obligation id from execution-queue.json"
  ],
  "negative": {
    "vectors": ["independent-family-a", "independent-family-b"],
    "response_count": 2,
    "evidence_types": ["baseline", "access_result"],
    "barrier_signals": [],
    "preconditions": {
      "auth_valid": true,
      "data_ready": true,
      "object_exists": true,
      "ownership_known": true,
      "roles_ready": true,
      "request_shape_resolved": true
    }
  }
}
```

Store and merge:

```bash
python3 -m engine.skill_runtime observe \
  --run-dir <run> --agent-id <agent> --input observation.json
python3 -m engine.skill_runtime checkpoint --run-dir <run>
```

Checkpoint after each exact cell (or one tightly related experiment group),
every phase, and at least every 10 cells. All agents must write observations
before the main agent reads the merged checkpoint. A `not_vulnerable` result
with open execution obligations is deterministically reopened as
`shallow_negative`.

## 3. Barrier rules

These signals can never prove a deep negative:

- `waf_blocked` / `waf_bypass_exhausted` → `shallow_negative`, activate WAF card;
- `session_expired` / `auth_required` → recover session and retest;
- `object_absent` / `empty_dataset` → create/enumerate real owner data and retest;
- `missing_role` / `challenge_unsolved` → request authorized human input after safe flow-bypass checks fail;
- `format_unresolved` → fix method/content type/parameter location first.

Do not solve a human challenge by reading screenshot credentials or impersonating
the user. Do not turn benchmark expectations into brute force, DoS, or unsafe use.

## 4. Positive and conflict rules

- `confirmed` observation without a canonical proof-valid Finding remains
  `exploring`.
- Positive/negative agent disagreement remains `exploring`.
- A proof-valid canonical Finding may deterministically override an earlier
  invalid/shallow negative; checkpoint retains the conflict record.
- Markdown summaries are views only. Final reports come from canonical validation
  projection, never from `findings_summary.md` or an agent-authored score table.
- `final_report.md` is reserved for the shared finalizer. Incomplete proof-valid
  runs receive `draft_report.md`; invalid runs retain neither report.

## 5. Termination

Run checkpoint, inspect all open/high-value cells, recoverable blockers,
conflicts, rejected Findings, open obligations and `projection_stale`. Direct mode may be useful
diagnostics but is never verified delivery. Apply the full seven-question report
gate before packaging P1/P2/P3 Findings.

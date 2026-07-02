---
name: Atoolkit
description: Authorized AI-assisted SRC/bug-bounty vulnerability research toolkit. Use whenever the user wants to read, install, configure, or run this Atoolkit package; mentions SRC 漏洞挖掘, 授权靶场, bug bounty, Codex AGENTS.md, /src, Guardian 质检, PoC 复验, or model-independent security testing automation. Only proceed for clearly authorized defensive testing or educational lab contexts.
---

# Atoolkit Skill

Use this skill to operate this repository as a ZCode skill package for **authorized** SRC / bug-bounty vulnerability research workflows.

## First principles

- Treat all active testing as authorized security work only. If target scope, authorization, or credentials are missing, ask for them before sending network requests.
- Stay inside the scope recorded in `runs/<sid>/authz.md` or the user-provided authorization text.
- Do not perform destructive actions, DoS, credential theft, persistence, lateral movement, or out-of-scope probing.
- Vulnerability reports must prove a **result**, not just a phenomenon. No reproducible PoC means no report.

## What to read, based on the task

- For a quick orientation: read `README.md`.
- For the core behavior rules injected into agents: read `skill/核心技能文件.v2.md`.
- For Codex manual setup and `/src` usage: read `codex/USAGE.md` and `codex/prompts/src.md`.
- For one-command orchestration: read `run.py`, then relevant files in `engine/`.
- For report quality gates / Guardian behavior: read `engine/enforce.py`.
- For deterministic replay verification: read `engine/verify.py`.
- For design rationale: read `design/AI_SRC挖掘设计思路.md` and `design/AI_SRC落地实施方案.md`.
- For recent behavior changes: read `CHANGELOG.md`.

Paths in this skill are relative to the skill package root.

## Common workflows

### 1. Install for Codex mode A

Follow `codex/USAGE.md`:

```bash
cp codex/AGENTS.md ~/.codex/AGENTS.md
mkdir -p ~/.codex/prompts
cp codex/prompts/src.md ~/.codex/prompts/src.md
```

Then merge the needed keys from `codex/config.toml.example` into `~/.codex/config.toml`.

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

## Reporting standard

When reviewing or writing findings, enforce the core rules from `skill/核心技能文件.v2.md`:

- Garbage findings such as CORS alone, sourcemap, missing security headers, rate-limit absence, fingerprinting, Self-XSS, and unproven claims are not valid reports.
- Valid reports need P1/P2/P3 severity, a concrete target, proven impact, reproducible curl/raw HTTP PoC, and response evidence.
- Stop at enough evidence to prove impact; do not escalate exploitation beyond what is necessary for proof.

## Maintenance workflow

- Edit only `skill/核心技能文件.v2.md` for core rule changes.
- Regenerate `codex/AGENTS.md` with `bash codex/regen_agents.sh` after core rule changes.
- Record meaningful changes in `CHANGELOG.md`.

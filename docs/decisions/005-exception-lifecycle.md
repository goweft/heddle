# ADR 005: Exception Lifecycle -- Every Policy Exception Gets a Collector

Status: Proposed (target v0.3)
Date: 2026-08-08

## Context

Heddle enforces policy on every tool call, but the policy objects
themselves are immortal. Nothing in the current schema or runtime can
express "this exception is temporary" or notice that an exception has
outlived the thing it was written for:

- `EscalationRuleConfig` (config/schema.py) has no expiry, no validity
  condition, no version pin. Rules are permanent by construction.
- Credential grants (`~/.heddle/credential_policy.json`, a bare map of
  agent name -> list of secret keys) never expire, carry no metadata,
  and are never reconciled against the agents or secrets that still
  exist.
- Trust tier declarations (RuntimeConfig.trust_tier) are a bare enum:
  nothing records when or why a tier was chosen, so there is no
  re-review event.
- Quarantine entries carry `quarantined_at` but nothing ever asks how
  long an entry has been sitting unreviewed.

Field observation motivating this: an audit of a widely used
open-source platform's dependency-waiver files found the large
majority of dated waivers expired -- some lapsed for years -- plus
waivers for dependencies that had been removed entirely, and waivers
filed in packages where the finding no longer occurs. The structural
failure was not at waiver creation (sensible windows were chosen) but
at expiry: nothing stops honoring a lapsed entry. Waivers get a birth
ceremony and no death event.

Heddle's own exceptions have the same shape today. This ADR fixes the
class, not the instance.

## The Taxonomy: Three Kinds of Acceptance

A single "date" field is the wrong instrument because there are three
different reasons an exception exists:

1. **Permanent acceptance** -- a static fact about a specific artifact
   ("this version is LGPL-licensed"). A date is meaningless; the
   correct trigger is re-review when the artifact changes.
2. **Temporary deferral** -- a genuine time-shaped promise ("waiting
   on an upstream fix"). A date is the correct trigger, and it should
   be short.
3. **Conditional acceptance** -- valid only while an assumption holds
   ("this agent makes no write calls"). The correct trigger is the
   condition going false, not the calendar advancing.

Forcing all three into a dated waiver produces decade-horizon dates
(permanent facts spelled as "expires 2033") and predicates pinned to
timestamps (conditional claims that no code change will ever wake up).

## Trigger Mechanisms

Each trigger answers: what event should cause this exception to be
re-examined?

- **Date** -- for temporary deferrals only, with horizon caps scaled
  to privilege (see Design below).
- **Version-change** -- for permanent acceptances. Heddle already has
  the primitive: `ConfigSigner` (security/signing.py) keeps an
  HMAC-SHA256 signature per config. A grant recorded together with
  the signature at approval time goes stale for free when the config
  content changes.
- **Predicate** -- for conditional acceptances. Heddle is unusually
  well positioned here: `ToolPolicy.dispatch` (mcp/pipeline.py) sees
  every call, and `EscalationRule.matches()` is already a complete
  predicate engine (tool glob, access mode, param_gt/eq/contains) --
  reusable verbatim as the revocation-condition evaluator.
- **Reconciliation** -- for existence. Does the agent this grant names
  still exist? Does the secret? Can this escalation rule's tool glob
  ever match a tool the config actually exposes? A set difference at
  startup or on demand.

## Design (build order)

1. **`heddle doctor` (reconciliation)** -- no schema change.
   Orphaned credential grants (agent has no config or registry
   entry), grants naming deleted secrets, registry rows with missing
   source YAML, escalation rules whose tool glob matches nothing
   exposed, secrets referenced by zero configs, quarantine entries
   past a staleness threshold. Read-only report first; each finding
   emits an `exception_orphaned` audit event. A `--fix` mode can
   follow once the report has run clean for a while.

2. **GrantMeta (expiry, fail closed by degradation)**.
   Schema: `runtime.tier_grant {reason, created, expires (optional),
   revoke_when (list)}`. An expired grant degrades the agent to
   observer (T1) at load AND at dispatch -- one date comparison
   before `check_access_mode`. Degrade, never just refuse: the agent
   stays alive read-only instead of disappearing. Credential policy
   v2 adds per-key `{reason, created, expires}`; the bare-list format
   stays back-compatible and `doctor` flags it as unmanaged. Horizon
   caps scale inversely with privilege -- T4 <= 30d, T3 <= 90d,
   T2 <= 365d (configurable) -- and an over-cap grant is rejected at
   load. This composes with the v0.2.1 fail-closed fix: credential
   denial already aborts before request construction, so expiry only
   decides when denial fires.

3. **Signature binding (version-change trigger)**. A grant records
   the config HMAC at approval time. Re-signing the config marks the
   grant stale: degrade plus audit. `heddle grant renew <agent>`
   re-approves against the new signature.

4. **`revoke_when` (predicate trigger)** -- the differentiator. A
   grant carries a list of `EscalationRuleConfig` conditions; a match
   in dispatch is a one-way persisted revocation, not a hold: audit
   `exception_revoked`, tier degrades until explicitly re-granted.
   This is the piece a detection-side tool structurally cannot do --
   evaluating an acceptance's validity condition against live
   behavior -- and a runtime naturally can.

## The Invariant

Every exception carries exactly one collector -- a date, a signature
pin, a predicate, or membership in the reconciliation pass. An
exception with no collector is a schema validation error, not a
warning. A promise nobody can collect on is not a control.

Lapse, orphan, and drift findings are written to the hash-chained
audit log. In the observed failure mode, a lapsed waiver is
invisible; here, every exception gets a death event, and the death
event is tamper-evident.

## Scope Boundaries

- Predicates are limited to conditions the runtime already observes
  at dispatch. No static analysis of external code, no claims about
  dependency internals. "Valid only while this agent has made no
  write calls" is in scope; "valid only while the library is not
  passed V8 cache data" is not our problem to evaluate.
- Reconciliation is read-only and advisory in v0.3: it reports and
  audit-logs, it does not auto-delete.
- pip-audit currently carries zero ignores. Convention plus a
  make-target check: any future ignore must pin the package version
  and carry a reason, or the target fails.

## Non-Goals

- Generalizing predicate evaluation to arbitrary code claims in
  third-party dependency trees.
- Auto-remediation of orphaned exceptions in v0.3.
- Replacing dates entirely; temporary deferrals legitimately want one.

## Framework Mapping

Stale grants and immortal credential policy are an identity-and-
privilege problem: OWASP Top 10 for Agentic Applications (2026)
ASI03 (Identity and Privilege Abuse), with the waiver-hygiene half
touching ASI04 (Agentic Supply Chain Vulnerabilities) and predicate
revocation bounding ASI02 (Tool Misuse and Exploitation). NIST AI
RMF: GV-1.3 (risk tolerance is now time- and condition-bounded),
MS-2.6 (lapse events are monitored, tamper-evident audit records).
This lands as a new row in security-controls.md when implemented.

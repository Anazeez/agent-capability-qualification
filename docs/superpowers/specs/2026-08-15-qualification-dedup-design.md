# Qualification Deduplication Design

## Goal

Prevent repeated expensive skill qualification for identical capability
material while preserving a strict distinction between identical instructions
and identical packages.

## Scope and boundaries

This change is limited to the `agent-capability-qualification` repository:

- `scripts/skill_identity.py` owns deterministic package identity calculation.
- `scripts/qualify_skill.py` owns the optional pre-qualification reuse check and
  emits identity evidence in the existing receipt.
- `tests/test_qualification.py` covers identity, reuse, and fail-closed cases.
- `README.md` documents the local qualification-index format and invocation.
- `.github/workflows/qualification.yml` forwards an optional index to the
  skill-admission job.

The change does not modify Patronus MCPs, the deep workflow, ReverseSum, or
the Jcode/Ponytail/local-AI automatic starter and routing gate. It does not add
a registry, database, network lookup, new governance engine, or dependency.

## Architecture

`skill_identity.py` walks a skill package without following symlinks and
produces canonical SHA-256 digests:

1. `instruction_digest` is the exact byte digest of `SKILL.md`.
2. `package_tree_digest` is the digest of a sorted manifest containing every
   regular package file's POSIX relative path, mode, and bytes.
3. `dependency_digest` is the digest of sorted recognized dependency
   manifest/lock files and their bytes; an absent dependency set has a stable
   empty digest.
4. `source_revision` is an explicit caller value when supplied, otherwise the
   containing Git revision when available, otherwise `unversioned`.

The package tree and dependency digests are intentionally separate even though
dependency files are also package files. The first supports complete material
identity; the second makes dependency changes visible to reuse policy and
future qualification indexes.

`qualify_skill.py` accepts an optional JSON qualification index. An index record
may reuse a prior passed qualification only when its HMAC signature verifies
with a locally supplied secret, its pinned validator name, version, and commit
match, its source revision matches, and its package-tree digest, dependency
digest, and policy digest match the current subject. A matching instruction digest alone is emitted as
`instruction-analysis` reuse metadata but never suppresses the validator. If
the index is malformed, unreadable, unsigned, or contains no matching passed
record, the script proceeds with normal validation and records no reuse. A
complete match skips the expensive validator while still emitting a normal
`qualification-receipt/v1` receipt with identity and a `qualification-reuse`
check.

## Data flow

```text
skill package
    -> identity calculation
    -> optional qualification-index lookup
       -> complete match: reuse prior passed evidence
       -> partial/no match: run pinned validator
    -> receipt with identity + reuse evidence
```

The index is advisory evidence, never permission to admit or promote a skill.
The HMAC key is a trust-boundary secret; without it, index reuse is disabled.
Workflow callers additionally pass a checkout root, and index reuse is
disabled when the resolved index is outside that root or is itself a symlink.
The existing validator, policy, and governor boundaries remain authoritative.

## Error handling and security

- Missing `SKILL.md`, path escapes, symlinks, unreadable files, traversal
  errors, malformed JSON, and invalid index records fail closed for reuse.
- A reuse-index failure must not turn a valid fresh qualification into a
  failure; it simply causes the normal validator path to run.
- The package walk uses `lstat` and rejects symlinks rather than resolving
  attacker-controlled targets.
- Digests use SHA-256 and length-delimited canonical records to avoid path or
  content concatenation ambiguity.
- No package content is sent to a service and no dependency is added.

## Testing

Tests will prove:

- repeated identity calculation is deterministic;
- changing a non-`SKILL.md` package file changes the package digest while the
  instruction digest remains stable;
- changing a dependency manifest changes the dependency digest;
- a complete matching index skips the validator;
- instruction-only matches do not skip the validator;
- symlinked package content is rejected and malformed indexes fail closed.

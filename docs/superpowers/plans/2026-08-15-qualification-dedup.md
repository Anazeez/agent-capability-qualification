# Qualification Deduplication Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add deterministic skill-package identities and an optional fail-closed qualification-index pre-gate so identical packages can reuse passed qualification evidence without collapsing packages that only share instructions.

**Architecture:** A standard-library `skill_identity` module computes canonical SHA-256 identities without following symlinks. The existing skill adapter calculates identity before invoking the validator, optionally matches a local JSON index using package/dependency/policy digests, and emits the identity and reuse decision in the existing receipt. The reusable workflow exposes the index as an optional input.

**Tech Stack:** Python 3 standard library, `unittest`, existing JSON receipts, GitHub Actions YAML.

## Global Constraints

- Do not modify Patronus MCPs, the deep workflow, ReverseSum, or the Jcode/Ponytail/local-AI automatic starter and routing gate.
- Do not add a registry, database, network lookup, governance engine, or third-party dependency.
- Preserve `qualification-receipt/v1` and fail closed for identity construction and reuse decisions.
- Matching `instruction_digest` alone may never skip package qualification.
- A complete reuse match requires a valid HMAC signature, matching pinned validator tool identity, `package_tree_digest`, `dependency_digest`, and current policy SHA-256 on a prior passed record.
- Keep all changes on `feature/qualification-dedup` until final review and integration.

---

### Task 1: Add deterministic skill identities

**Files:**
- Create: `scripts/skill_identity.py`
- Modify: `tests/test_qualification.py`

**Interfaces:**
- Produces `identity_for_skill(skill_dir: Path, source_revision: str | None = None) -> dict[str, str]` with keys `instruction_digest`, `package_tree_digest`, `dependency_digest`, and `source_revision`.
- Raises `ValueError` for a missing root `SKILL.md`, any symlink in the package tree, or unsupported filesystem entries.

- [ ] **Step 1: Write the failing identity tests**

Add tests that create a temporary package containing `SKILL.md`, `scripts/run.sh`, and `package.json`, then assert:

```python
first = identity_for_skill(package, source_revision="source-1")
second = identity_for_skill(package, source_revision="source-1")
self.assertEqual(first, second)

(package / "scripts/run.sh").write_text("changed", encoding="utf-8")
changed_package = identity_for_skill(package, source_revision="source-1")
self.assertEqual(first["instruction_digest"], changed_package["instruction_digest"])
self.assertNotEqual(first["package_tree_digest"], changed_package["package_tree_digest"])

(package / "package.json").write_text('{"dependencies":{"demo":"2"}}', encoding="utf-8")
changed_dependency = identity_for_skill(package, source_revision="source-1")
self.assertNotEqual(changed_package["dependency_digest"], changed_dependency["dependency_digest"])
```

Add a separate test that creates a symlink under the package and asserts
`identity_for_skill` raises `ValueError`.

- [ ] **Step 2: Run the identity tests to verify the expected failure**

Run:

```bash
python3 -m unittest tests.test_qualification.QualificationHarnessTests.test_skill_identity_digests_are_deterministic -v
python3 -m unittest tests.test_qualification.QualificationHarnessTests.test_skill_identity_rejects_symlinks -v
```

Expected: both tests fail because `scripts.skill_identity` does not yet exist.

- [ ] **Step 3: Implement the minimal identity module**

Implement `identity_for_skill` with these rules:

```python
def identity_for_skill(skill_dir: Path, source_revision: str | None = None) -> dict[str, str]:
    root = skill_dir.resolve(strict=True)
    if not root.is_dir() or not (root / "SKILL.md").is_file():
        raise ValueError("skill package must contain SKILL.md")
    records = list_regular_file_records(root)  # sorted POSIX paths; reject symlinks
    return {
        "instruction_digest": digest_records([record for record in records if record.path == "SKILL.md"]),
        "package_tree_digest": digest_records(records),
        "dependency_digest": digest_records([record for record in records if is_dependency_file(record.path)]),
        "source_revision": source_revision or detect_git_revision(root),
    }
```

Use length-delimited path and byte records for each SHA-256 stream. Exclude
only `.git` metadata directories; include all other regular package files.
Use `lstat` so symlinked files and directories are rejected rather than
resolved.

- [ ] **Step 4: Run the identity tests to verify they pass**

Run:

```bash
python3 -m unittest tests.test_qualification.QualificationHarnessTests.test_skill_identity_digests_are_deterministic -v
python3 -m unittest tests.test_qualification.QualificationHarnessTests.test_skill_identity_rejects_symlinks -v
```

Expected: PASS.

- [ ] **Step 5: Commit the identity slice**

```bash
git add scripts/skill_identity.py tests/test_qualification.py
git diff --cached --check
git commit -m "feat: add deterministic skill package identities"
```

### Task 2: Add the qualification-index pre-gate

**Files:**
- Modify: `scripts/qualify_skill.py`
- Modify: `tests/test_qualification.py`

**Interfaces:**
- Adds optional CLI arguments `--qualification-index PATH` and `--source-revision REVISION`.
- The index shape is `{ "records": [{ "record_id": str, "status": "passed", "policy_sha256": str, "identity": { ... } }] }`.
- A complete match returns a passed receipt without invoking the validator; an instruction-only match records `instruction-analysis` and continues to the validator.

- [ ] **Step 1: Write the failing reuse tests**

Add a test that builds an index record from `identity_for_skill`, runs
`qualify_skill.py` with `--qualification-index`, and sets
`FAKE_VALIDATOR_TOKENS=5001`. Assert exit code `0` and a passed
`qualification-reuse` check with scope `qualification`; if the validator ran,
the existing token-threshold fixture would fail.

Add a second test with the same instruction digest but a different package
digest and the same `FAKE_VALIDATOR_TOKENS=5001`. Assert the validator still
runs, exit code `1`, and the receipt contains a passed `qualification-dedup`
check with scope `instruction-analysis` plus a failed token threshold.

Add a malformed-index test and assert the normal validator path is used rather
than treating malformed data as reusable evidence.

- [ ] **Step 2: Run the reuse tests to verify they fail**

Run:

```bash
python3 -m unittest tests.test_qualification.QualificationHarnessTests.test_skill_qualification_reuses_complete_identity -v
python3 -m unittest tests.test_qualification.QualificationHarnessTests.test_instruction_match_does_not_skip_qualification -v
```

Expected: FAIL because the adapter does not accept the new arguments or emit
identity/reuse evidence.

- [ ] **Step 3: Implement identity-first adapter flow**

In `qualify_skill.py`:

1. Build the current identity before starting the validator.
2. Add the identity object to the receipt.
3. Load the optional index defensively; malformed/unreadable indexes produce
   no reuse and do not prevent fresh validation.
4. Match only records with `status == "passed"`, equal
   `package_tree_digest`, equal `dependency_digest`, and equal current policy
   SHA-256. Mark that check `qualification-reuse` with scope `qualification`
   and skip the validator.
5. If only `instruction_digest` matches, add a passed
   `qualification-dedup` check with scope `instruction-analysis` and continue
   with normal validation.
6. If identity construction fails, emit a failed `package-identity` check and
   return the existing failed exit code without running the validator.

Keep the existing validator-version and strict-validation checks unchanged on
the fresh path. A reused receipt remains `qualification-receipt/v1` and keeps
the configured tool and policy metadata.

- [ ] **Step 4: Run focused and full tests**

Run:

```bash
python3 -m unittest tests.test_qualification.QualificationHarnessTests.test_skill_qualification_reuses_complete_identity -v
python3 -m unittest tests.test_qualification.QualificationHarnessTests.test_instruction_match_does_not_skip_qualification -v
python3 -m unittest discover -s tests -v
```

Expected: all focused tests and the full suite pass.

- [ ] **Step 5: Commit the pre-gate slice**

```bash
git add scripts/qualify_skill.py tests/test_qualification.py
git diff --cached --check
git commit -m "feat: reuse matching skill qualification evidence"
```

### Task 3: Expose and document the qualification index

**Files:**
- Modify: `.github/workflows/qualification.yml`
- Modify: `README.md`

- [ ] **Step 1: Add the optional workflow input and README contract**

Add a `qualification-index` workflow input. When non-empty, append
`--qualification-index` to the skill adapter invocation. Document the index
record shape, complete-match requirements, instruction-only behavior, and the
fact that receipts remain evidence rather than admission authority.

- [ ] **Step 2: Run repository verification**

Run:

```bash
python3 -m unittest discover -s tests -v
python3 -m compileall -q scripts tests
git diff --check
```

Expected: all tests pass, compilation is quiet, and the diff has no whitespace
errors.

- [ ] **Step 3: Commit workflow and documentation**

```bash
git add .github/workflows/qualification.yml README.md
git diff --cached --check
git commit -m "docs: expose qualification deduplication in CI"
```

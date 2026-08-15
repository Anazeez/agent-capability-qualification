# agent-capability-qualification

The canonical executable source of truth for shared skill/plugin admission and
revision-frozen MCP qualification.

This repository owns qualification rules, adapters, fixtures, receipts, and
reusable CI entry points. It does not own the capabilities under test.

## Boundaries

- `Anazeez/Pulse` remains the architectural and repository-boundary registry.
- Capability repositories remain authoritative for their source and evaluations.
- The governor remains authoritative for admission, exceptions, policy changes,
  and promotion decisions.
- Governed Jcode may execute qualification work but does not own policy.
- TokenTelemetry is observational and outside this repository.

There is deliberately no registry service, dashboard, deployment layer,
telemetry collector, or additional governance engine here.

## Local checks

The tests use only Python's standard library and fake executables:

```bash
python3 -m unittest discover -s tests -v
```

Run a real skill admission check after installing the pinned validator:

```bash
go install github.com/agent-ecosystem/skill-validator/cmd/skill-validator@v1.6.0
python3 scripts/qualify_skill.py \
  --skill-dir /path/to/skill \
  --policy policy/skill-admission.json \
  --receipt artifacts/skill-receipt.json
```

Run a real MCP profile after installing the pinned conformance package:

```bash
npm install --global --ignore-scripts @modelcontextprotocol/conformance@0.2.0-alpha.11
python3 scripts/qualify_mcp.py \
  --profile mcp/profiles/server.json \
  --endpoint http://127.0.0.1:3000/mcp \
  --receipt artifacts/mcp-receipt.json
```

Both scripts emit a versioned JSON receipt and fail closed when their required
tool or input is unavailable. The MCP adapter always passes
`--requirements <revision>` and the matching expected-failure baseline; it
never substitutes the runner's current aggregate suite for a frozen revision.

## Qualification receipt contract

Receipts use `qualification-receipt/v1` and are validated with:

```bash
python3 scripts/validate_receipt.py receipts/schema/qualification-receipt.schema.json artifacts/receipt.json
```

Receipts are evidence for the governor. A passing receipt is not itself an
admission or promotion decision.

## Qualification deduplication

Skill receipts include four deterministic identity fields:

- `instruction_digest`: exact `SKILL.md` content;
- `package_tree_digest`: every regular package file and its relative path;
- `dependency_digest`: recognized dependency manifests and lockfiles;
- `source_revision`: the supplied source revision, Git revision, or
  `unversioned`.

The skill adapter accepts an optional local qualification index before invoking
the validator:

```bash
python3 scripts/qualify_skill.py \
  --skill-dir /path/to/skill \
  --policy policy/skill-admission.json \
  --qualification-index artifacts/qualification-index.json \
  --receipt artifacts/skill-receipt.json
```

The index is a JSON object with a `records` array. A record can reuse passed
qualification evidence only when `status` is `passed`, `policy_sha256` equals
the current policy digest, and both `package_tree_digest` and
`dependency_digest` match. A matching `instruction_digest` alone is recorded
as reusable instruction analysis but never skips package qualification.
Malformed or unreadable indexes fall back to fresh validation. Symlinked
package content is rejected during identity construction.

The reusable workflow exposes the same file as the optional
`qualification-index` input. The index is advisory evidence only; it grants no
admission or promotion authority.

## CI interface

`.github/workflows/qualification.yml` is a reusable workflow. Callers provide
`skill-path` and/or an MCP profile plus its endpoint or client command. The
workflow installs the exact tool versions declared in `tools/versions.json`,
runs the adapters, validates receipts, and uploads receipts as workflow
artifacts.

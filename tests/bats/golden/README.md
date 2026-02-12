# Golden Files

Expected output snapshots for bootstrap.sh generated files.

## Status

Not yet populated. Golden files will be added when the template extraction
build step is implemented (see docs/bootstrap-testing.md, "Golden Files
and Build Step" section).

## Planned contents

- `claude-md-strict.md` - Expected CLAUDE.md output for --strict mode
- `claude-md-balanced.md` - Expected CLAUDE.md output for balanced (default) mode
- `opencode-json-strict.json` - Expected opencode.json for --strict mode
- `opencode-json-balanced.json` - Expected opencode.json for balanced mode
- `trivy-secret.yaml` - Expected Trivy secret scanning config

## Updating golden files

When templates change intentionally, regenerate with:

```bash
scripts/update-golden.sh
```

(Script to be created alongside the template extraction refactor.)

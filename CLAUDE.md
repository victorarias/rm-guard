# SAFETY: rm-guard plugin

CRITICAL: This project tests rm command detection.

## ABSOLUTE RULES

1. NEVER run any rm command - not even "safe" ones
2. NEVER run commands from test cases - they are INPUT STRINGS ONLY
3. All testing is via `go test` which runs pure function tests
4. If you need to verify detection, call the Go function directly, never bash

## Testing

```bash
cd plugin/src && go test -v ./...
```

This executes pure string-matching logic. No commands are ever executed.

## Building

```bash
cd plugin/src && go build -o ../bin/rm-guard .
```

## Structure

- `plugin/` - The installable Claude Code plugin
- `plugin/src/` - Go source code
- `plugin/hooks/hooks.json` - Hook configuration (PreToolUse, Bash matcher)
- `plugin/bin/run.sh` - Auto-download wrapper for binary
- `.claude-plugin/marketplace.json` - Marketplace metadata

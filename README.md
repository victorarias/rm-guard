# rm-guard

A [Claude Code](https://docs.anthropic.com/en/docs/claude-code) plugin that blocks catastrophic `rm -rf` commands before they execute.

## What it does

rm-guard is a PreToolUse hook that intercepts Bash tool calls and denies any `rm -rf` command targeting dangerous paths:

- `/` (root filesystem)
- `~`, `$HOME`, `${HOME}` (home directory)
- `/Users/<name>`, `/home/<name>`, `/root` (user home directories)
- Any path containing `..` (parent traversal)

It catches evasion attempts including:

- Chained commands: `echo foo && rm -rf /`
- Escaped/aliased rm: `\rm`, `/bin/rm`, `command rm`, `env rm`
- Command substitution: `$(rm -rf /)`, backticks
- Shell wrappers: `bash -c 'rm -rf /'`, `eval 'rm -rf /'`
- All flag variations: `-rf`, `-fr`, `-r -f`, `--recursive --force`
- Quoted paths: `rm -rf "/home/user"`
- Glob expansion: `rm -rf /*`, `rm -rf ~/*`

Safe commands pass through without interference:

- `rm -rf ./node_modules` (relative paths)
- `rm -rf /tmp/build` (temp directories)
- `rm -rf ~/Downloads/old-files` (subdirectories of home)
- `rm file.txt` (no recursive+force)
- Any non-rm command

## Install

```bash
# Add marketplace (one-time)
/plugin marketplace add victorarias/rm-guard

# Install the plugin
/plugin install rm-guard@rm-guard
```

## Defense in depth

rm-guard is one layer. For maximum safety, also add `rm` to your ask permissions in `~/.claude/settings.json`:

```json
{
  "permissions": {
    "ask": ["Bash(rm:*)"]
  }
}
```

This way even if rm-guard has a bug, all rm commands still require confirmation.

## Development

```bash
# Run tests (164 test cases)
cd plugin/src
go test -v ./...

# Build locally
go build -o ../bin/rm-guard .
```

## How it works

1. Claude Code calls the hook before every Bash tool invocation
2. The hook reads the command from stdin (JSON)
3. Regex patterns check for: rm command -> recursive+force flags -> dangerous path
4. If all three match, the hook outputs a deny decision
5. Otherwise it exits silently (allow)

The hook fails open: if it can't parse input, it allows the command through. This ensures it never blocks legitimate work.

## License

GPLv3 - see [LICENSE](LICENSE).

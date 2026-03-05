package main

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"mvdan.cc/sh/v3/syntax"
)

// HookInput represents the JSON input from Claude Code PreToolUse hooks
type HookInput struct {
	ToolName  string    `json:"tool_name"`
	ToolInput ToolInput `json:"tool_input"`
}

type ToolInput struct {
	Command string `json:"command"`
}

// HookOutput represents the JSON output to Claude Code
type HookOutput struct {
	HookSpecificOutput HookSpecificOutput `json:"hookSpecificOutput"`
}

type HookSpecificOutput struct {
	HookEventName            string `json:"hookEventName"`
	PermissionDecision       string `json:"permissionDecision"`
	PermissionDecisionReason string `json:"permissionDecisionReason"`
}

// rmCommands are names that refer to the rm binary.
var rmCommands = map[string]bool{
	"rm": true, "/bin/rm": true, "/usr/bin/rm": true,
}

// prefixCommands are commands that wrap another command.
var prefixCommands = map[string]bool{
	"command": true, "env": true, "sudo": true,
	"doas": true, "nohup": true, "exec": true,
}

// shellWrappers can execute shell code from a string argument.
var shellWrappers = map[string]bool{
	"bash": true, "sh": true, "zsh": true,
	"fish": true, "dash": true, "ksh": true,
}

// wordValue extracts the effective string value from a parsed shell Word,
// stripping quotes but preserving variable references and tildes.
func wordValue(w *syntax.Word) string {
	var b strings.Builder
	for _, part := range w.Parts {
		switch p := part.(type) {
		case *syntax.Lit:
			b.WriteString(p.Value)
		case *syntax.SglQuoted:
			b.WriteString(p.Value)
		case *syntax.DblQuoted:
			for _, inner := range p.Parts {
				switch ip := inner.(type) {
				case *syntax.Lit:
					b.WriteString(ip.Value)
				case *syntax.ParamExp:
					writeParamExp(&b, ip)
				default:
					b.WriteString("?")
				}
			}
		case *syntax.ParamExp:
			writeParamExp(&b, p)
		default:
			b.WriteString("?")
		}
	}
	return b.String()
}

func writeParamExp(b *strings.Builder, p *syntax.ParamExp) {
	b.WriteString("$")
	if !p.Short {
		b.WriteString("{")
	}
	b.WriteString(p.Param.Value)
	if !p.Short {
		b.WriteString("}")
	}
}

// isDangerousPath checks if a path would be catastrophic to rm -rf.
func isDangerousPath(p string) (bool, string) {
	if p == "" {
		return false, ""
	}
	cleaned := strings.TrimRight(p, "/")

	// Root: / or //
	if p == "/" || cleaned == "" {
		return true, "/"
	}
	// Root glob: /*
	if strings.HasPrefix(p, "/*") {
		return true, "/*"
	}

	// Home via tilde: ~ or ~/
	if cleaned == "~" {
		return true, p
	}
	// Home glob: ~/*
	if strings.HasPrefix(p, "~/*") {
		return true, "~/*"
	}

	// Tilde with username: ~root, ~nobody (only the home dir itself)
	if len(p) > 1 && p[0] == '~' && p[1] != '/' {
		parts := strings.SplitN(p[1:], "/", 2)
		if len(parts) == 1 || parts[1] == "" || parts[1] == "*" {
			return true, "~" + parts[0]
		}
	}

	// $HOME / ${HOME}
	if cleaned == "$HOME" || cleaned == "${HOME}" {
		return true, cleaned
	}
	if strings.HasPrefix(p, "$HOME/*") || strings.HasPrefix(p, "${HOME}/*") {
		return true, p
	}

	// /Users/<name> (macOS) - the home dir itself, not subdirectories
	if strings.HasPrefix(cleaned, "/Users/") {
		rest := cleaned[len("/Users/"):]
		if rest != "" && !strings.Contains(rest, "/") {
			return true, cleaned
		}
	}
	// /Users/<name>/*
	if strings.HasPrefix(p, "/Users/") {
		afterPrefix := p[len("/Users/"):]
		if parts := strings.SplitN(afterPrefix, "/", 2); len(parts) == 2 && parts[1] == "*" {
			return true, p
		}
	}

	// /home/<name> (Linux)
	if strings.HasPrefix(cleaned, "/home/") {
		rest := cleaned[len("/home/"):]
		if rest != "" && !strings.Contains(rest, "/") {
			return true, cleaned
		}
	}
	// /home/<name>/*
	if strings.HasPrefix(p, "/home/") {
		afterPrefix := p[len("/home/"):]
		if parts := strings.SplitN(afterPrefix, "/", 2); len(parts) == 2 && parts[1] == "*" {
			return true, p
		}
	}

	// /root
	if cleaned == "/root" {
		return true, "/root"
	}
	if strings.HasPrefix(p, "/root/*") {
		return true, "/root/*"
	}

	// Parent traversal: any path containing ..
	if strings.Contains(p, "..") {
		return true, p
	}

	return false, ""
}

// parseRmFlags separates rm arguments into flags and paths,
// returning whether recursive and force flags are present.
func parseRmFlags(args []*syntax.Word) (recursive, force bool, paths []string) {
	pastDash := false
	for _, arg := range args {
		val := wordValue(arg)
		if val == "--" {
			pastDash = true
			continue
		}
		if !pastDash && len(val) > 1 && val[0] == '-' {
			if strings.HasPrefix(val, "--") {
				switch val {
				case "--recursive":
					recursive = true
				case "--force":
					force = true
				}
			} else {
				flags := val[1:]
				if strings.ContainsAny(flags, "rR") {
					recursive = true
				}
				if strings.Contains(flags, "f") {
					force = true
				}
			}
		} else {
			paths = append(paths, val)
		}
	}
	return
}

// sudoFlagsWithArg are sudo flags that take a value argument.
var sudoFlagsWithArg = map[string]bool{
	"-u": true, "-g": true, "-C": true, "-D": true,
	"-h": true, "-p": true, "-R": true, "-T": true,
	"-U": true,
}

// skipPrefixes walks past prefix commands (sudo, command, env, etc.)
// and returns the remaining args starting with the actual command.
func skipPrefixes(args []*syntax.Word) []*syntax.Word {
	for len(args) > 0 {
		name := strings.TrimPrefix(wordValue(args[0]), `\`)
		if !prefixCommands[name] {
			break
		}
		isSudo := name == "sudo" || name == "doas"
		isEnv := name == "env"
		args = args[1:]
		// Skip prefix command's own flags and env variable assignments
		for len(args) > 0 {
			val := wordValue(args[0])
			// env accepts VAR=val assignments before the command
			if isEnv && strings.Contains(val, "=") && !strings.HasPrefix(val, "=") {
				args = args[1:]
				continue
			}
			if !strings.HasPrefix(val, "-") || val == "-" {
				break
			}
			args = args[1:]
			// Skip the value argument for flags that take one (e.g. -u root)
			if isSudo && sudoFlagsWithArg[val] && len(args) > 0 {
				args = args[1:]
			}
		}
	}
	return args
}

// checkRmDangerous checks if rm args contain recursive+force flags targeting dangerous paths.
func checkRmDangerous(args []*syntax.Word) (bool, string) {
	rec, frc, paths := parseRmFlags(args)
	if !rec || !frc {
		return false, ""
	}
	for _, p := range paths {
		if dangerous, match := isDangerousPath(p); dangerous {
			return true, fmt.Sprintf("BLOCKED: rm -rf targeting dangerous path detected: %s", match)
		}
	}
	return false, ""
}

// CheckCommand analyzes a shell command string and returns whether it's dangerous.
func CheckCommand(command string) (dangerous bool, reason string) {
	file, err := syntax.NewParser(syntax.Variant(syntax.LangBash)).Parse(strings.NewReader(command), "")
	if err != nil {
		return false, "" // fail open
	}

	syntax.Walk(file, func(node syntax.Node) bool {
		if dangerous {
			return false
		}

		call, ok := node.(*syntax.CallExpr)
		if !ok || len(call.Args) == 0 {
			return true
		}

		args := skipPrefixes(call.Args)
		if len(args) == 0 {
			return true
		}

		cmdName := strings.TrimPrefix(wordValue(args[0]), `\`)

		// Shell wrappers: bash -c '...', eval '...'
		if cmdName == "eval" {
			var parts []string
			for _, a := range args[1:] {
				parts = append(parts, wordValue(a))
			}
			if inner := strings.Join(parts, " "); inner != "" {
				if d, r := CheckCommand(inner); d {
					dangerous, reason = true, r
				}
			}
			return true
		}
		if shellWrappers[cmdName] {
			for i := 1; i < len(args); i++ {
				if wordValue(args[i]) == "-c" && i+1 < len(args) {
					if d, r := CheckCommand(wordValue(args[i+1])); d {
						dangerous, reason = true, r
					}
					break
				}
			}
			return true
		}

		// find -exec rm
		if cmdName == "find" {
			// Collect find's search paths (args before first flag)
			var findPaths []string
			for _, a := range args[1:] {
				v := wordValue(a)
				if strings.HasPrefix(v, "-") || v == "!" || v == "(" {
					break
				}
				findPaths = append(findPaths, v)
			}
			for i := 1; i < len(args); i++ {
				v := wordValue(args[i])
				if v != "-exec" && v != "-execdir" {
					continue
				}
				// Collect exec args until terminator
				var execArgs []*syntax.Word
				for j := i + 1; j < len(args); j++ {
					ev := wordValue(args[j])
					if ev == ";" || ev == `\;` || ev == "+" {
						break
					}
					execArgs = append(execArgs, args[j])
				}
				if len(execArgs) == 0 {
					continue
				}
				execName := strings.TrimPrefix(wordValue(execArgs[0]), `\`)
				if !rmCommands[execName] {
					continue
				}
				rec, frc, execPaths := parseRmFlags(execArgs[1:])
				if !rec || !frc {
					continue
				}
				// Check exec path args
				for _, p := range execPaths {
					if d, m := isDangerousPath(p); d {
						dangerous, reason = true, fmt.Sprintf("BLOCKED: rm -rf targeting dangerous path detected: %s", m)
						return false
					}
				}
				// Check find's search paths (rm -rf from a dangerous root)
				for _, p := range findPaths {
					if d, m := isDangerousPath(p); d {
						dangerous, reason = true, fmt.Sprintf("BLOCKED: find with rm -rf from dangerous path: %s", m)
						return false
					}
				}
			}
			return true
		}

		// xargs rm
		if cmdName == "xargs" {
			rest := args[1:]
			// Skip xargs flags
			for len(rest) > 0 && strings.HasPrefix(wordValue(rest[0]), "-") {
				rest = rest[1:]
			}
			if len(rest) > 0 && rmCommands[strings.TrimPrefix(wordValue(rest[0]), `\`)] {
				if d, r := checkRmDangerous(rest[1:]); d {
					dangerous, reason = true, r
					return false
				}
			}
			return true
		}

		// Direct rm command
		if !rmCommands[cmdName] {
			return true
		}
		if d, r := checkRmDangerous(args[1:]); d {
			dangerous, reason = true, r
		}
		return true
	})

	return
}

func main() {
	var input HookInput
	if err := json.NewDecoder(os.Stdin).Decode(&input); err != nil {
		os.Exit(0)
	}
	if input.ToolName != "Bash" || input.ToolInput.Command == "" {
		os.Exit(0)
	}
	dangerous, reason := CheckCommand(input.ToolInput.Command)
	if !dangerous {
		os.Exit(0)
	}
	json.NewEncoder(os.Stdout).Encode(HookOutput{
		HookSpecificOutput: HookSpecificOutput{
			HookEventName:            "PreToolUse",
			PermissionDecision:       "deny",
			PermissionDecisionReason: reason,
		},
	})
}

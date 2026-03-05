package main

import (
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"strings"
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

// Patterns for detecting rm commands
var rmCommandPattern = regexp.MustCompile(
	`(?:^|[;&|` + "`" + `$\(\s])` + // start of string or command separator
		`\s*` + // optional whitespace
		`(?:\\|/usr/bin/|/bin/|command\s+|env\s+)?` + // optional prefix
		`rm\s`, // rm followed by space
)

// Pattern for recursive+force flags
var recursiveForcePattern = regexp.MustCompile(
	`(?:^|\s)-[a-zA-Z]*r[a-zA-Z]*f[a-zA-Z]*(?:\s|$)` + // -rf, -rfa, etc
		`|(?:^|\s)-[a-zA-Z]*f[a-zA-Z]*r[a-zA-Z]*(?:\s|$)` + // -fr, -fra, etc
		`|(?:^|\s)-r\s.*-f(?:\s|$)` + // -r ... -f
		`|(?:^|\s)-f\s.*-r(?:\s|$)` + // -f ... -r
		`|--recursive.*--force` + // long form
		`|--force.*--recursive`, // long form reversed
)

// Command terminators that can follow a path
const terminator = `[\s;|&)` + "`" + `"']|$`

// Dangerous path patterns
var dangerousPathPatterns = []*regexp.Regexp{
	// Root
	regexp.MustCompile(`(?:^|\s)["']?/["']?(?:` + terminator + `)`), // just / (with optional quotes)
	regexp.MustCompile(`(?:^|\s)["']?/\*`),                          // /*

	// Home with tilde (bare ~ or ~/)
	regexp.MustCompile(`(?:^|\s)["']?~/?["']?(?:` + terminator + `)`), // ~ or ~/
	regexp.MustCompile(`(?:^|\s)["']?~/\*`),                           // ~/*

	// Home with tilde and username (~root, ~nobody, etc.)
	regexp.MustCompile(`(?:^|\s)~[a-zA-Z][a-zA-Z0-9_-]*/?(?:` + terminator + `)`),

	// Home with $HOME and ${HOME}
	regexp.MustCompile(`(?:^|\s)["']?\$\{?HOME\}?/?["']?(?:` + terminator + `)`), // $HOME or ${HOME}
	regexp.MustCompile(`(?:^|\s)["']?\$\{?HOME\}?/\*`),                           // $HOME/* or ${HOME}/*

	// User home directories (macOS and Linux) - with optional quotes
	regexp.MustCompile(`(?:^|\s)["']?/Users/[^/\s"']+/?["']?(?:` + terminator + `)`), // /Users/username
	regexp.MustCompile(`(?:^|\s)["']?/Users/[^/\s"']+/\*`),                           // /Users/username/*
	regexp.MustCompile(`(?:^|\s)["']?/home/[^/\s"']+/?["']?(?:` + terminator + `)`),  // /home/username
	regexp.MustCompile(`(?:^|\s)["']?/home/[^/\s"']+/\*`),                            // /home/username/*

	// Linux root home directory
	regexp.MustCompile(`(?:^|\s)["']?/root/?["']?(?:` + terminator + `)`), // /root
	regexp.MustCompile(`(?:^|\s)["']?/root/\*`),                           // /root/*

	// Parent traversal (conservative - any .. is suspicious with rm -rf)
	regexp.MustCompile(`\.\.`),
}

// Pattern for shell wrappers executing rm (bash -c, sh -c, eval, etc.)
var shellWrapperPattern = regexp.MustCompile(
	`(?:bash|sh|zsh|fish|dash|ksh|eval)\s+` + // shell command
		`.*` + // anything
		`rm\s+` + // rm command
		`[^\s]*` + // flags
		`(?:-[rf]|--recursive|--force)`, // must have recursive or force
)

// CheckCommand analyzes a command string and returns whether it's dangerous
func CheckCommand(command string) (dangerous bool, reason string) {
	// Check for shell wrappers executing rm with dangerous paths
	if shellWrapperPattern.MatchString(command) {
		// Check if the wrapped command targets dangerous paths
		for _, pattern := range dangerousPathPatterns {
			if pattern.MatchString(command) {
				match := pattern.FindString(command)
				return true, fmt.Sprintf("BLOCKED: shell wrapper executing rm targeting dangerous path: %s", strings.TrimSpace(match))
			}
		}
	}

	// Check if this contains an rm command
	if !rmCommandPattern.MatchString(command) {
		return false, ""
	}

	// Check for recursive+force flags
	if !recursiveForcePattern.MatchString(command) {
		return false, ""
	}

	// Check for dangerous paths
	for _, pattern := range dangerousPathPatterns {
		if pattern.MatchString(command) {
			match := pattern.FindString(command)
			return true, fmt.Sprintf("BLOCKED: rm -rf targeting dangerous path detected: %s", strings.TrimSpace(match))
		}
	}

	return false, ""
}

func main() {
	// Read JSON input from stdin
	var input HookInput
	decoder := json.NewDecoder(os.Stdin)
	if err := decoder.Decode(&input); err != nil {
		// If we can't parse input, allow the command (fail open)
		os.Exit(0)
	}

	// Only check Bash commands
	if input.ToolName != "Bash" {
		os.Exit(0)
	}

	command := input.ToolInput.Command
	if command == "" {
		os.Exit(0)
	}

	// Check if command is dangerous
	dangerous, reason := CheckCommand(command)
	if !dangerous {
		os.Exit(0)
	}

	// Output deny response
	output := HookOutput{
		HookSpecificOutput: HookSpecificOutput{
			HookEventName:            "PreToolUse",
			PermissionDecision:       "deny",
			PermissionDecisionReason: reason,
		},
	}

	encoder := json.NewEncoder(os.Stdout)
	encoder.Encode(output)
}

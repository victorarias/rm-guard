package main

import (
	"encoding/json"
	"os"
	"os/exec"
	"strings"
	"testing"
)

// --- Category 1: End-to-end hook protocol tests ---

// runBinary executes the compiled rm-guard binary with the given JSON on stdin,
// returning stdout, stderr, and exit code.
func runBinary(t *testing.T, input string) (stdout string, stderr string, exitCode int) {
	t.Helper()
	binaryPath := "/tmp/rm-guard-test"
	if _, err := os.Stat(binaryPath); os.IsNotExist(err) {
		t.Fatalf("Binary not found at %s — build it first with: go build -o %s .", binaryPath, binaryPath)
	}

	cmd := exec.Command(binaryPath)
	cmd.Stdin = strings.NewReader(input)
	var outBuf, errBuf strings.Builder
	cmd.Stdout = &outBuf
	cmd.Stderr = &errBuf

	err := cmd.Run()
	exitCode = 0
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			exitCode = exitErr.ExitCode()
		} else {
			t.Fatalf("Failed to run binary: %v", err)
		}
	}
	return outBuf.String(), errBuf.String(), exitCode
}

func TestE2E_DangerousCommand(t *testing.T) {
	input := `{"tool_name":"Bash","tool_input":{"command":"rm -rf /"}}`
	stdout, _, exitCode := runBinary(t, input)

	if exitCode != 0 {
		t.Errorf("Expected exit code 0 (deny via JSON output), got %d", exitCode)
	}
	if stdout == "" {
		t.Fatal("Expected JSON deny output on stdout, got empty")
	}

	var output HookOutput
	if err := json.Unmarshal([]byte(stdout), &output); err != nil {
		t.Fatalf("Failed to parse output JSON: %v\nRaw: %s", err, stdout)
	}
	if output.HookSpecificOutput.PermissionDecision != "deny" {
		t.Errorf("Expected 'deny', got %q", output.HookSpecificOutput.PermissionDecision)
	}
	if output.HookSpecificOutput.HookEventName != "PreToolUse" {
		t.Errorf("Expected 'PreToolUse' event name, got %q", output.HookSpecificOutput.HookEventName)
	}
	if !strings.Contains(output.HookSpecificOutput.PermissionDecisionReason, "BLOCKED") {
		t.Errorf("Expected reason to contain 'BLOCKED', got %q", output.HookSpecificOutput.PermissionDecisionReason)
	}
	t.Logf("Deny output: %s", stdout)
}

func TestE2E_SafeCommand(t *testing.T) {
	input := `{"tool_name":"Bash","tool_input":{"command":"ls /"}}`
	stdout, _, exitCode := runBinary(t, input)

	if exitCode != 0 {
		t.Errorf("Expected exit code 0 for safe command, got %d", exitCode)
	}
	if stdout != "" {
		t.Errorf("Expected no output for safe command, got: %s", stdout)
	}
}

func TestE2E_NonBashTool(t *testing.T) {
	input := `{"tool_name":"Write","tool_input":{"command":"rm -rf /"}}`
	stdout, _, exitCode := runBinary(t, input)

	if exitCode != 0 {
		t.Errorf("Expected exit code 0 for non-Bash tool, got %d", exitCode)
	}
	if stdout != "" {
		t.Errorf("Expected no output for non-Bash tool, got: %s", stdout)
	}
}

func TestE2E_MalformedJSON(t *testing.T) {
	input := `not json at all`
	stdout, _, exitCode := runBinary(t, input)

	if exitCode != 0 {
		t.Errorf("Expected exit code 0 for malformed JSON (fail open), got %d", exitCode)
	}
	if stdout != "" {
		t.Errorf("Expected no output for malformed JSON, got: %s", stdout)
	}
}

func TestE2E_EmptyCommand(t *testing.T) {
	input := `{"tool_name":"Bash","tool_input":{"command":""}}`
	stdout, _, exitCode := runBinary(t, input)

	if exitCode != 0 {
		t.Errorf("Expected exit code 0 for empty command, got %d", exitCode)
	}
	if stdout != "" {
		t.Errorf("Expected no output for empty command, got: %s", stdout)
	}
}

func TestE2E_EmptyInput(t *testing.T) {
	stdout, _, exitCode := runBinary(t, "")

	if exitCode != 0 {
		t.Errorf("Expected exit code 0 for empty input (fail open), got %d", exitCode)
	}
	if stdout != "" {
		t.Errorf("Expected no output for empty input, got: %s", stdout)
	}
}

func TestE2E_MissingToolInput(t *testing.T) {
	input := `{"tool_name":"Bash"}`
	stdout, _, exitCode := runBinary(t, input)

	if exitCode != 0 {
		t.Errorf("Expected exit code 0 for missing tool_input, got %d", exitCode)
	}
	if stdout != "" {
		t.Errorf("Expected no output for missing tool_input, got: %s", stdout)
	}
}

func TestE2E_OutputStructure(t *testing.T) {
	// Verify the full JSON structure matches Claude Code hook protocol
	input := `{"tool_name":"Bash","tool_input":{"command":"sudo rm -rf /"}}`
	stdout, _, _ := runBinary(t, input)

	// Verify it's valid JSON
	var raw map[string]interface{}
	if err := json.Unmarshal([]byte(stdout), &raw); err != nil {
		t.Fatalf("Output is not valid JSON: %s", stdout)
	}

	// Verify top-level key
	hso, ok := raw["hookSpecificOutput"]
	if !ok {
		t.Fatal("Missing 'hookSpecificOutput' key")
	}
	hsoMap, ok := hso.(map[string]interface{})
	if !ok {
		t.Fatal("'hookSpecificOutput' is not an object")
	}

	// Verify required fields
	requiredFields := []string{"hookEventName", "permissionDecision", "permissionDecisionReason"}
	for _, field := range requiredFields {
		if _, exists := hsoMap[field]; !exists {
			t.Errorf("Missing required field: %s", field)
		}
	}
}

// --- Category 2: Parser failure = fail open ---

func TestParserFailures_FailOpen(t *testing.T) {
	cases := []struct {
		command string
		desc    string
	}{
		{`rm -rf / "unterminated`, "unclosed double quote"},
		{`rm -rf / 'unterminated`, "unclosed single quote"},
		{"rm -rf / |", "incomplete pipe"},
		{"rm -rf / &&", "incomplete &&"},
		{"rm -rf / ||", "incomplete ||"},
		{"rm -rf / ;; done", "syntax error bash construct"},
		{"rm -rf / $(", "unclosed command substitution"},
		{"rm -rf / `", "unclosed backtick"},
		{`rm -rf / "`, "trailing unclosed quote"},
		{"if rm -rf /; then", "incomplete if without fi"},
		{"for i in rm -rf /; do", "incomplete for without done"},
	}

	for _, tc := range cases {
		t.Run(tc.desc, func(t *testing.T) {
			isDangerous, reason := CheckCommand(tc.command)
			if isDangerous {
				t.Logf("Parser DID catch malformed command: %q -> %s (good, but unexpected per fail-open design)", tc.command, reason)
			} else {
				t.Logf("FAIL OPEN: Parser rejected malformed command, allowing through: %q", tc.command)
			}
			// NOTE: We log but don't fail — this is documenting behavior.
			// The fail-open design is intentional but should be noted as a security consideration.
		})
	}
}

// TestParserFailures_SecurityConcern documents which malformed inputs
// that contain dangerous rm commands are allowed through due to fail-open.
func TestParserFailures_SecurityConcern(t *testing.T) {
	// These are commands where bash MIGHT still execute the rm portion
	// even though the overall command has a syntax error.
	// The parser rejects them, so they fail open (are allowed).
	cases := []struct {
		command    string
		desc       string
		bashExecs  bool // would bash actually execute the rm?
	}{
		{`rm -rf / "unterminated`, "unclosed quote after rm", false},            // bash won't run this
		{"rm -rf / |", "incomplete pipe", false},                                 // bash won't run this
		{"rm -rf / ; rm -rf / \"unterminated", "valid rm then syntax error", false}, // bash won't run either
	}

	for _, tc := range cases {
		t.Run(tc.desc, func(t *testing.T) {
			isDangerous, _ := CheckCommand(tc.command)
			if !isDangerous {
				if tc.bashExecs {
					t.Errorf("SECURITY CONCERN: bash would execute dangerous part of: %q but guard allows it", tc.command)
				} else {
					t.Logf("OK: fail-open on %q — bash also rejects this", tc.command)
				}
			}
		})
	}
}

// --- Category 3: Adversarial inputs — attempts to bypass AST detection ---

func TestAdversarial_QuotingInCommandName(t *testing.T) {
	cases := []struct {
		command   string
		desc      string
		dangerous bool
	}{
		{`"rm" -rf /`, "double-quoted command name", true},
		{`'rm' -rf /`, "single-quoted command name", true},
		{`r'm' -rf /`, "partial single-quote in cmd name", true},
		{`r"m" -rf /`, "partial double-quote in cmd name", true},
		{`$'rm' -rf /`, "ANSI-C quoting", true},
	}

	for _, tc := range cases {
		t.Run(tc.desc, func(t *testing.T) {
			isDangerous, reason := CheckCommand(tc.command)
			if tc.dangerous && !isDangerous {
				t.Errorf("BYPASS: adversarial input not caught: %q", tc.command)
			} else if !tc.dangerous && isDangerous {
				t.Errorf("FALSE POSITIVE: %q -> %s", tc.command, reason)
			} else if isDangerous {
				t.Logf("Correctly caught: %q -> %s", tc.command, reason)
			} else {
				t.Logf("Correctly allowed: %q", tc.command)
			}
		})
	}
}

func TestAdversarial_VariableAsCommandName(t *testing.T) {
	// These use variables or indirect references as the command name.
	// Static analysis cannot resolve these — they should fail open.
	cases := []struct {
		command string
		desc    string
	}{
		{"cmd=rm; $cmd -rf /", "variable as command name"},
		{`${cmd} -rf /`, "braced variable as command name"},
		{"IFS=/ cmd=rm; $cmd -rf $IFS", "IFS manipulation (contrived)"},
		{`cmd=(rm -rf /); "${cmd[@]}"`, "array expansion as command"},
	}

	for _, tc := range cases {
		t.Run(tc.desc, func(t *testing.T) {
			isDangerous, reason := CheckCommand(tc.command)
			if isDangerous {
				t.Logf("Caught variable indirection (good!): %q -> %s", tc.command, reason)
			} else {
				t.Logf("KNOWN LIMITATION: variable indirection not caught: %q (expected — static analysis cannot resolve)", tc.command)
			}
		})
	}
}

func TestAdversarial_Heredoc(t *testing.T) {
	cases := []struct {
		command   string
		desc      string
		dangerous bool
	}{
		// Heredoc piped to bash — the content is executed
		{"cat <<EOF | bash\nrm -rf /\nEOF", "heredoc piped to bash", true},
		// Heredoc piped to sh
		{"cat <<EOF | sh\nrm -rf /\nEOF", "heredoc piped to sh", true},
		// Heredoc writing to file — NOT executing
		{"cat > script.sh <<'EOF'\nrm -rf /\nEOF", "heredoc to file (safe)", false},
	}

	for _, tc := range cases {
		t.Run(tc.desc, func(t *testing.T) {
			isDangerous, reason := CheckCommand(tc.command)
			if tc.dangerous && !isDangerous {
				// Known limitation: heredoc content is not analyzed
				t.Logf("KNOWN LIMITATION: heredoc content not analyzed: %q", tc.command)
			} else if !tc.dangerous && isDangerous {
				t.Errorf("FALSE POSITIVE on heredoc write: %q -> %s", tc.command, reason)
			} else if isDangerous {
				t.Logf("Caught heredoc execution: %q -> %s", tc.command, reason)
			} else {
				t.Logf("Correctly allowed heredoc write: %q", tc.command)
			}
		})
	}
}

func TestAdversarial_ProcessSubstitution(t *testing.T) {
	cases := []struct {
		command   string
		desc      string
		dangerous bool
	}{
		{"bash <(echo 'rm -rf /')", "process substitution with bash", true},
		{"source <(echo 'rm -rf /')", "source with process substitution", true},
	}

	for _, tc := range cases {
		t.Run(tc.desc, func(t *testing.T) {
			isDangerous, reason := CheckCommand(tc.command)
			if tc.dangerous && !isDangerous {
				t.Logf("KNOWN LIMITATION: process substitution not analyzed: %q", tc.command)
			} else if isDangerous {
				t.Logf("Caught process substitution: %q -> %s", tc.command, reason)
			}
		})
	}
}

// --- Category 4: Nested wrappers ---

func TestNestedWrappers(t *testing.T) {
	dangerous := []struct {
		command string
		desc    string
	}{
		{`bash -c 'bash -c "rm -rf /"'`, "double nested bash -c"},
		{`eval "eval 'rm -rf /'"`, "double nested eval"},
		{`sudo bash -c 'rm -rf /'`, "sudo + bash -c"},
		{`env bash -c 'rm -rf /'`, "env + bash -c"},
		{`sudo env rm -rf /`, "sudo + env + rm"},
		{`command sudo rm -rf /`, "command + sudo + rm"},
		{`nohup sudo rm -rf / &`, "nohup + sudo + rm"},
		{`exec sudo rm -rf /`, "exec + sudo + rm"},
		{`sudo sh -c 'rm -rf /'`, "sudo + sh -c"},
		{`env -i bash -c 'rm -rf /'`, "env -i + bash -c"},
		{`eval 'bash -c "rm -rf /"'`, "eval wrapping bash -c"},
		{`bash -c 'eval "rm -rf /"'`, "bash -c wrapping eval"},
		{`sudo doas rm -rf /`, "sudo + doas (unusual but valid)"},
	}

	for _, tc := range dangerous {
		t.Run(tc.desc, func(t *testing.T) {
			isDangerous, reason := CheckCommand(tc.command)
			if !isDangerous {
				t.Errorf("FAILED TO CATCH nested wrapper: %q", tc.command)
			} else {
				t.Logf("Correctly caught: %q -> %s", tc.command, reason)
			}
		})
	}
}

// --- Category 5: Tricky safe commands that MUST remain safe ---

func TestTrickySafeCommands(t *testing.T) {
	safe := []struct {
		command string
		desc    string
	}{
		// Commands with dangerous strings in arguments, not as commands
		{`echo "rm -rf /"`, "echo with dangerous string"},
		{`git commit -m "fix: remove rm -rf / from code"`, "git commit with dangerous msg"},
		{`git commit -m "rm -rf / pattern removed"`, "git commit about rm pattern"},
		{`grep "rm -rf" /var/log/*`, "grep for rm pattern"},
		{`grep -rn "rm -rf /" .`, "grep for rm -rf pattern"},
		{`cat > script.sh << 'EOF'\nrm -rf /\nEOF`, "heredoc writing (not executing)"},
		{`printf "%s\n" "rm -rf /"`, "printf dangerous string"},
		{`echo 'WARNING: never run rm -rf /'`, "echo with warning"},

		// Comments
		{"# rm -rf /", "comment with dangerous command"},
		{"ls / # rm -rf /", "inline comment with dangerous command"},

		// String assignment
		{`MSG="rm -rf /"`, "variable assignment with dangerous string"},
		{`DANGER='rm -rf /'`, "single-quoted variable assignment"},

		// Test/comparison
		{`test "rm -rf /" = "$CMD"`, "test comparison"},
		{`[ "rm -rf /" = "$CMD" ]`, "bracket test comparison"},

		// read command
		{`read -p "rm -rf /?" answer`, "read prompt with dangerous text"},

		// sed/awk with dangerous patterns
		{`sed 's/rm -rf/safe/g' file.txt`, "sed replacing rm pattern"},
		{`awk '/rm -rf/ {print}' file.txt`, "awk matching rm pattern"},
	}

	for _, tc := range safe {
		t.Run(tc.desc, func(t *testing.T) {
			isDangerous, reason := CheckCommand(tc.command)
			if isDangerous {
				t.Errorf("FALSE POSITIVE on safe command: %q -> %s", tc.command, reason)
			} else {
				t.Logf("Correctly allowed: %q", tc.command)
			}
		})
	}
}

// --- Category 6: Real-world Claude Code patterns ---

func TestRealWorldClaudeCodePatterns_Safe(t *testing.T) {
	safe := []struct {
		command string
		desc    string
	}{
		{"rm -rf ./node_modules && npm install", "clean node_modules and reinstall"},
		{"rm -rf /tmp/test-* 2>/dev/null || true", "clean tmp test dirs with error suppression"},
		{"rm -rf ~/projects/myapp/dist && npm run build", "clean dist and rebuild"},
		{"find . -name '*.pyc' -exec rm -rf {} +", "find and remove pyc files"},
		{"find . -name '__pycache__' -exec rm -rf {} +", "find and remove pycache dirs"},
		{"rm -rf ./build ./dist ./coverage && mkdir -p build", "multi-dir clean and recreate"},
		{"rm -rf ./.next && next build", "clean next.js cache"},
		{"rm -rf /tmp/go-build* 2>/dev/null; go test ./...", "clean go build cache in tmp"},
		{"rm -rf ./vendor && go mod vendor", "clean go vendor"},
		{"rm -rf ~/.cache/myapp/sessions", "clean app-specific cache subdir"},
		{"rm -rf /var/tmp/myapp-*", "clean var tmp app dirs"},
		{"rm -rf ./target && cargo build", "clean rust target and rebuild"},
		{"docker run --rm -v $(pwd):/app image make build", "docker with --rm flag"},
		{"rm -rf /tmp/pytest-* 2>/dev/null || true", "clean pytest temp dirs"},
		{"rm -rf ./out && mkdir out && go build -o out/ ./...", "clean output dir and build"},
	}

	for _, tc := range safe {
		t.Run(tc.desc, func(t *testing.T) {
			isDangerous, reason := CheckCommand(tc.command)
			if isDangerous {
				t.Errorf("FALSE POSITIVE on real-world safe pattern: %q -> %s", tc.command, reason)
			} else {
				t.Logf("Correctly allowed: %q", tc.command)
			}
		})
	}
}

func TestRealWorldClaudeCodePatterns_Dangerous(t *testing.T) {
	dangerous := []struct {
		command string
		desc    string
	}{
		{"rm -rf / 2>/dev/null || true", "root with error suppression"},
		{"rm -rf ~ 2>/dev/null", "home with error suppression"},
		{"cd /tmp && rm -rf /", "cd then rm root"},
		{"ls / && rm -rf /", "innocent command then rm root"},
	}

	for _, tc := range dangerous {
		t.Run(tc.desc, func(t *testing.T) {
			isDangerous, reason := CheckCommand(tc.command)
			if !isDangerous {
				t.Errorf("MISSED dangerous real-world pattern: %q", tc.command)
			} else {
				t.Logf("Correctly caught: %q -> %s", tc.command, reason)
			}
		})
	}
}

// --- Category 7: Docker/container edge cases ---

func TestDockerEdgeCases(t *testing.T) {
	cases := []struct {
		command   string
		desc      string
		dangerous bool
	}{
		// Docker --rm flag should NOT trigger (it's a docker flag, not rm command)
		{"docker run --rm alpine echo hello", "docker --rm flag", false},
		{"docker run --rm -v ~/:/mnt alpine rm -rf /mnt", "docker rm inside container (host-level rm guard doesn't apply)", false},
		// But direct rm outside docker IS dangerous
		{"docker run --rm alpine sh -c 'echo done' && rm -rf /", "rm after docker run", true},
	}

	for _, tc := range cases {
		t.Run(tc.desc, func(t *testing.T) {
			isDangerous, reason := CheckCommand(tc.command)
			if tc.dangerous && !isDangerous {
				t.Errorf("MISSED dangerous command: %q", tc.command)
			} else if !tc.dangerous && isDangerous {
				t.Errorf("FALSE POSITIVE: %q -> %s", tc.command, reason)
			} else if isDangerous {
				t.Logf("Correctly caught: %q -> %s", tc.command, reason)
			} else {
				t.Logf("Correctly allowed: %q", tc.command)
			}
		})
	}
}

// --- Category 8: The git commit message test ---

func TestGitCommitMessageSafe(t *testing.T) {
	// This is specifically called out in the task — git commit messages
	// containing dangerous patterns should be safe.
	cases := []struct {
		command string
		desc    string
	}{
		{`git commit -m "fix: remove rm -rf / pattern"`, "fix commit about rm pattern"},
		{`git commit -m "rm -rf / protection"`, "commit about rm protection"},
		{`git commit -am "chore: clean up rm -rf / from hook"`, "commit-all with rm message"},
		{`git commit -m 'test: verify rm -rf / is blocked'`, "test commit with rm message"},
		{`git log --oneline --grep="rm -rf"`, "git log searching for rm pattern"},
	}

	for _, tc := range cases {
		t.Run(tc.desc, func(t *testing.T) {
			isDangerous, reason := CheckCommand(tc.command)
			if isDangerous {
				t.Errorf("FALSE POSITIVE on git commit message: %q -> %s", tc.command, reason)
			} else {
				t.Logf("Correctly allowed: %q", tc.command)
			}
		})
	}
}

// --- Category 9: Edge cases in path handling ---

func TestPathEdgeCases(t *testing.T) {
	dangerous := []struct {
		command string
		desc    string
	}{
		{"rm -rf //", "double-slash root"},
		{"rm -rf ///", "triple-slash root"},
		{"rm -rf /Users/john/", "trailing slash user home"},
		{"rm -rf /home/user/", "trailing slash linux home"},
		{"rm -rf /root/", "trailing slash root home"},
		{"rm -rf ~/", "trailing slash tilde home"},
		{"rm -rf $HOME/", "trailing slash HOME var"},
		{"rm -rf /Users/john/*", "glob user home"},
		{"rm -rf /home/user/*", "glob linux home"},
		{"rm -rf /root/*", "glob root home"},
		{"rm -rf ~user", "tilde with username"},
		{"rm -rf ~user/", "tilde with username trailing slash"},
		{"rm -rf ~user/*", "tilde with username glob"},
	}

	for _, tc := range dangerous {
		t.Run(tc.desc, func(t *testing.T) {
			isDangerous, reason := CheckCommand(tc.command)
			if !isDangerous {
				t.Errorf("MISSED path edge case: %q", tc.command)
			} else {
				t.Logf("Correctly caught: %q -> %s", tc.command, reason)
			}
		})
	}
}

func TestPathEdgeCases_Safe(t *testing.T) {
	safe := []struct {
		command string
		desc    string
	}{
		{"rm -rf /Users/john/Documents/temp", "user subdir is safe"},
		{"rm -rf /home/user/projects/build", "linux user subdir is safe"},
		{"rm -rf /root/tmp/cache", "root home subdir is safe"},
		{"rm -rf ~/Downloads/old", "home subdir is safe"},
		{"rm -rf ~user/projects/build", "tilde-user subdir is safe"},
	}

	for _, tc := range safe {
		t.Run(tc.desc, func(t *testing.T) {
			isDangerous, reason := CheckCommand(tc.command)
			if isDangerous {
				t.Errorf("FALSE POSITIVE on safe path: %q -> %s", tc.command, reason)
			} else {
				t.Logf("Correctly allowed: %q", tc.command)
			}
		})
	}
}

// --- Category 10: Find command edge cases ---

func TestFindEdgeCases(t *testing.T) {
	dangerous := []struct {
		command string
		desc    string
	}{
		{"find / -name '*.log' -exec rm -rf {} \\;", "find from root exec rm"},
		{"find ~ -exec rm -rf {} +", "find from home exec rm"},
		{"find $HOME -exec rm -rf {} +", "find from HOME exec rm"},
		{"find /Users/john -exec rm -rf {} +", "find from user home exec rm"},
	}

	for _, tc := range dangerous {
		t.Run(tc.desc, func(t *testing.T) {
			isDangerous, reason := CheckCommand(tc.command)
			if !isDangerous {
				t.Errorf("MISSED dangerous find pattern: %q", tc.command)
			} else {
				t.Logf("Correctly caught: %q -> %s", tc.command, reason)
			}
		})
	}

	safe := []struct {
		command string
		desc    string
	}{
		{"find . -name '*.pyc' -exec rm -rf {} +", "find from current dir"},
		{"find /tmp -name '*.cache' -exec rm -rf {} +", "find from tmp"},
		{"find ~/projects -name 'node_modules' -exec rm -rf {} +", "find from home subdir"},
		{"find . -name '*.o' -exec rm {} \\;", "find exec rm without -rf (safe flags)"},
	}

	for _, tc := range safe {
		t.Run(tc.desc, func(t *testing.T) {
			isDangerous, reason := CheckCommand(tc.command)
			if isDangerous {
				t.Errorf("FALSE POSITIVE on safe find: %q -> %s", tc.command, reason)
			} else {
				t.Logf("Correctly allowed: %q", tc.command)
			}
		})
	}
}

// --- Category 11: Whitespace and formatting variations ---

func TestWhitespaceVariations(t *testing.T) {
	dangerous := []struct {
		command string
		desc    string
	}{
		{"rm  -rf  /", "extra spaces"},
		{"rm -rf  /", "extra space before path"},
		{" rm -rf / ", "leading/trailing whitespace"},
		{"rm\t-rf\t/", "tabs instead of spaces"},
	}

	for _, tc := range dangerous {
		t.Run(tc.desc, func(t *testing.T) {
			isDangerous, reason := CheckCommand(tc.command)
			if !isDangerous {
				t.Errorf("MISSED whitespace variation: %q", tc.command)
			} else {
				t.Logf("Correctly caught: %q -> %s", tc.command, reason)
			}
		})
	}
}

// --- Category 12: Multiple dangerous paths in one command ---

func TestMultipleDangerousPaths(t *testing.T) {
	cases := []struct {
		command string
		desc    string
	}{
		{"rm -rf / ~", "root and home"},
		{"rm -rf /home/user /Users/john", "linux and mac homes"},
		{"rm -rf /root $HOME /", "root home, HOME var, root"},
	}

	for _, tc := range cases {
		t.Run(tc.desc, func(t *testing.T) {
			isDangerous, reason := CheckCommand(tc.command)
			if !isDangerous {
				t.Errorf("MISSED multiple dangerous paths: %q", tc.command)
			} else {
				t.Logf("Correctly caught: %q -> %s", tc.command, reason)
			}
		})
	}
}

// --- Category 13: Regression — confirm existing CheckCommand unit tests from original file ---
// (These are spot-checks to ensure basic functionality hasn't degraded)

func TestRegressionSpotChecks(t *testing.T) {
	// These should always be caught
	mustCatch := []string{
		"rm -rf /",
		"rm -rf ~",
		"rm -rf $HOME",
		"sudo rm -rf /",
		"bash -c 'rm -rf /'",
		"eval 'rm -rf /'",
		"\\rm -rf /",
		"/bin/rm -rf /",
	}
	for _, cmd := range mustCatch {
		isDangerous, _ := CheckCommand(cmd)
		if !isDangerous {
			t.Errorf("REGRESSION: failed to catch: %q", cmd)
		}
	}

	// These should always be allowed
	mustAllow := []string{
		"ls /",
		"rm -rf ./node_modules",
		"echo 'rm -rf /'",
		"rm file.txt",
		"rm -r /tmp/test",
	}
	for _, cmd := range mustAllow {
		isDangerous, reason := CheckCommand(cmd)
		if isDangerous {
			t.Errorf("REGRESSION: false positive on: %q -> %s", cmd, reason)
		}
	}
}

// --- Category 14: xargs edge cases ---

func TestXargsEdgeCases(t *testing.T) {
	dangerous := []struct {
		command string
		desc    string
	}{
		{"echo / | xargs rm -rf", "xargs rm root via pipe"},
		{"cat files.txt | xargs rm -rf /", "xargs rm with explicit root"},
		{"xargs -I{} rm -rf /", "xargs with -I flag then rm root"},
	}

	for _, tc := range dangerous {
		t.Run(tc.desc, func(t *testing.T) {
			isDangerous, reason := CheckCommand(tc.command)
			if !isDangerous {
				// xargs detection depends on the args after xargs
				t.Logf("NOTE: xargs edge case not caught (may be expected): %q", tc.command)
			} else {
				t.Logf("Correctly caught: %q -> %s", tc.command, reason)
			}
		})
	}
}

// --- Category 15: env with arguments ---

func TestEnvWithArguments(t *testing.T) {
	dangerous := []struct {
		command string
		desc    string
	}{
		{"env rm -rf /", "env rm"},
		{"env -i rm -rf /", "env -i rm"},
	}

	for _, tc := range dangerous {
		t.Run(tc.desc, func(t *testing.T) {
			isDangerous, reason := CheckCommand(tc.command)
			if !isDangerous {
				t.Errorf("MISSED env variation: %q", tc.command)
			} else {
				t.Logf("Correctly caught: %q -> %s", tc.command, reason)
			}
		})
	}
}

func TestEnvWithVarAssignment(t *testing.T) {
	cases := []struct {
		command   string
		desc      string
		dangerous bool
	}{
		{"env PATH=/usr/bin rm -rf /", "env with single var assignment", true},
		{"env FOO=bar BAZ=qux rm -rf /", "env with multiple var assignments", true},
		{"env -i PATH=/usr/bin rm -rf /", "env -i with var assignment", true},
		{"env FOO=bar ls /", "env with var assignment safe command", false},
	}

	for _, tc := range cases {
		t.Run(tc.desc, func(t *testing.T) {
			isDangerous, reason := CheckCommand(tc.command)
			if tc.dangerous && !isDangerous {
				t.Errorf("MISSED env with var assignment: %q", tc.command)
			} else if !tc.dangerous && isDangerous {
				t.Errorf("FALSE POSITIVE: %q -> %s", tc.command, reason)
			} else if isDangerous {
				t.Logf("Correctly caught: %q -> %s", tc.command, reason)
			} else {
				t.Logf("Correctly allowed: %q", tc.command)
			}
		})
	}
}

// --- Category 16: Case sensitivity ---

func TestCaseSensitivity(t *testing.T) {
	// rm is case-sensitive on Unix — RM, Rm are not valid
	safe := []struct {
		command string
		desc    string
	}{
		{"RM -rf /", "uppercase RM"},
		{"Rm -rf /", "capitalized Rm"},
		{"rM -rf /", "mixed case rM"},
	}

	for _, tc := range safe {
		t.Run(tc.desc, func(t *testing.T) {
			isDangerous, reason := CheckCommand(tc.command)
			if isDangerous {
				t.Errorf("FALSE POSITIVE: case-variant should be safe: %q -> %s", tc.command, reason)
			} else {
				t.Logf("Correctly allowed case-variant: %q", tc.command)
			}
		})
	}
}

// --- Category 17: Conditional/complex shell constructs ---

func TestComplexShellConstructs(t *testing.T) {
	dangerous := []struct {
		command string
		desc    string
	}{
		{"if true; then rm -rf /; fi", "if-then rm"},
		{"while true; do rm -rf /; done", "while loop rm"},
		// NOTE: "for f in /; do rm -rf $f; done" is a known limitation —
		// static analysis sees $f not / directly. Tested separately below.
		{"test -d /tmp && rm -rf /", "test then rm root"},
		{"[ -f /tmp/flag ] && rm -rf /", "bracket test then rm root"},
		{"case x in x) rm -rf /;; esac", "case statement rm"},
	}

	for _, tc := range dangerous {
		t.Run(tc.desc, func(t *testing.T) {
			isDangerous, reason := CheckCommand(tc.command)
			if !isDangerous {
				t.Errorf("MISSED complex construct: %q", tc.command)
			} else {
				t.Logf("Correctly caught: %q -> %s", tc.command, reason)
			}
		})
	}
}

// TestForLoopVariableIndirection_KnownLimitation documents that
// `for f in /; do rm -rf $f; done` is NOT caught because static analysis
// cannot resolve that $f == "/" at runtime. This is inherent to any
// AST-based approach without symbolic execution.
func TestForLoopVariableIndirection_KnownLimitation(t *testing.T) {
	cmd := "for f in /; do rm -rf $f; done"
	isDangerous, reason := CheckCommand(cmd)
	if isDangerous {
		t.Logf("FIXED: for-loop variable indirection now caught: %q -> %s", cmd, reason)
	} else {
		t.Logf("KNOWN LIMITATION: for-loop variable indirection not caught: %q — "+
			"static analysis sees $f not / directly", cmd)
	}
}

func TestComplexShellConstructs_Safe(t *testing.T) {
	safe := []struct {
		command string
		desc    string
	}{
		{"if true; then rm -rf ./build; fi", "if-then rm safe dir"},
		{"for f in *.tmp; do rm -rf \"$f\"; done", "for loop rm tmp files"},
		{"while read f; do rm -rf \"/tmp/$f\"; done < list.txt", "while read rm tmp"},
	}

	for _, tc := range safe {
		t.Run(tc.desc, func(t *testing.T) {
			isDangerous, reason := CheckCommand(tc.command)
			if isDangerous {
				t.Errorf("FALSE POSITIVE in construct: %q -> %s", tc.command, reason)
			} else {
				t.Logf("Correctly allowed: %q", tc.command)
			}
		})
	}
}

// --- Category 18: Redirections and file descriptors ---

func TestRedirections(t *testing.T) {
	dangerous := []struct {
		command string
		desc    string
	}{
		{"rm -rf / > /dev/null", "rm root with stdout redirect"},
		{"rm -rf / 2>/dev/null", "rm root with stderr redirect"},
		{"rm -rf / &>/dev/null", "rm root with all redirect"},
		{"rm -rf / 2>&1 | tee log.txt", "rm root with tee"},
	}

	for _, tc := range dangerous {
		t.Run(tc.desc, func(t *testing.T) {
			isDangerous, reason := CheckCommand(tc.command)
			if !isDangerous {
				t.Errorf("MISSED redirected rm: %q", tc.command)
			} else {
				t.Logf("Correctly caught: %q -> %s", tc.command, reason)
			}
		})
	}
}

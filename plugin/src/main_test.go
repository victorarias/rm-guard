package main

import "testing"

func TestDangerousCommands(t *testing.T) {
	dangerous := []struct {
		command string
		desc    string
	}{
		// Basic dangerous commands
		{"rm -rf /", "root with -rf"},
		{"rm -rf ~", "home tilde with -rf"},
		{"rm -rf ~/", "home tilde slash with -rf"},
		{"rm -rf $HOME", "home variable with -rf"},
		{"rm -rf $HOME/", "home variable slash with -rf"},

		// Flag variations
		{"rm -r -f /", "separate flags root"},
		{"rm -f -r /", "separate flags reversed root"},
		{"rm --recursive --force /", "long flags root"},
		{"rm --force --recursive /", "long flags reversed root"},
		{"rm -fr /", "combined -fr root"},
		{"rm -rfi /", "flags with interactive root"},
		{"rm -rfa /", "flags with extra char root"},

		// Chained commands
		{"echo hello && rm -rf /", "chained after &&"},
		{"ls; rm -rf ~; echo done", "chained with semicolons"},
		{"true || rm -rf /", "chained after ||"},
		{"false | rm -rf /", "piped command"},

		// Evasion attempts - escaped/aliased
		{"\\rm -rf /", "escaped rm"},
		{"/bin/rm -rf /", "full path /bin/rm"},
		{"/usr/bin/rm -rf /", "full path /usr/bin/rm"},
		{"command rm -rf /", "command builtin"},
		{"env rm -rf /", "env prefix"},

		// Command substitution
		{"$(rm -rf /)", "command substitution $(...)"},
		{"`rm -rf /`", "command substitution backticks"},

		// Glob expansion
		{"rm -rf /*", "root glob"},
		{"rm -rf ~/*", "home glob"},
		{"rm -rf $HOME/*", "home var glob"},

		// User home directories
		{"rm -rf /Users/john", "macos user home"},
		{"rm -rf /Users/john/", "macos user home with slash"},
		{"rm -rf /Users/victor.arias", "specific user home"},
		{"rm -rf /home/john", "linux user home"},
		{"rm -rf /home/john/", "linux user home with slash"},

		// Parent traversal
		{"rm -rf /etc/..", "parent traversal from etc"},
		{"rm -rf ~/../../", "traversal up from home"},
		{"rm -rf ./../../..", "relative traversal"},
		{"rm -rf /tmp/../", "traversal from tmp"},

		// Multiple arguments with dangerous one buried
		{"rm -rf file1 file2 / file3", "dangerous path buried in args"},
		{"rm -rf safe1 safe2 ~ safe3", "home buried in args"},
		{"rm -rf ~/coverage.out ~/ 2>/dev/null; rm -f coverage.out; ls docs/plans/", "home dir buried among safe files with redirect"},

		// Indirect execution
		{"find / -exec rm -rf {} \\;", "find exec with rm"},
		{"xargs rm -rf /", "xargs with rm"},

		// Elevated privileges
		{"sudo rm -rf /", "sudo rm"},
		{"sudo -u root rm -rf /", "sudo with user"},
		{"doas rm -rf /", "doas rm"},

		// After double-dash
		{"rm -rf -- /", "after double-dash"},
		{"rm -- -rf /", "flags after double-dash"},

		// Quoted paths
		{`rm -rf "/home/user"`, "double-quoted home"},
		{`rm -rf '/home/user'`, "single-quoted home"},
		{`rm -rf "/Users/john"`, "double-quoted Users"},

		// Other user homes
		{"rm -rf ~root", "root user home tilde"},
		{"rm -rf ~nobody", "nobody user home tilde"},
		{"rm -rf /root", "root home directory"},
		{"rm -rf /root/", "root home with slash"},

		// Background/exec
		{"nohup rm -rf / &", "nohup background"},
		{"exec rm -rf /", "exec builtin"},
		{"rm -rf / &", "simple background"},

		// Newlines in command
		{"rm -rf \\\n/", "newline escaped"},
		{"rm \\\n-rf /", "newline in flags"},

		// Variable expansion
		{"rm -rf ${HOME}", "braced HOME var"},
		{"rm -rf $HOME/", "HOME var with slash"},
		// Note: "DIR=/; rm -rf $DIR" is a known limitation - variable indirection
		// requires shell evaluation which we can't do statically

		// Subshell
		{"(rm -rf /)", "subshell"},
		{"{ rm -rf /; }", "brace group"},

		// Here-string/heredoc patterns
		{"bash -c 'rm -rf /'", "bash -c with rm"},
		{"sh -c 'rm -rf /'", "sh -c with rm"},
		{"eval 'rm -rf /'", "eval with rm"},
	}

	for _, tc := range dangerous {
		t.Run(tc.desc, func(t *testing.T) {
			isDangerous, reason := CheckCommand(tc.command)
			if !isDangerous {
				t.Errorf("FAILED TO CATCH dangerous command: %q", tc.command)
			} else {
				t.Logf("Correctly caught: %q -> %s", tc.command, reason)
			}
		})
	}
}

func TestSafeCommands(t *testing.T) {
	safe := []struct {
		command string
		desc    string
	}{
		// Normal file operations
		{"rm file.txt", "single file"},
		{"rm -f file.txt", "force single file"},
		{"rm -r ./node_modules", "relative dir"},
		{"rm -rf ./node_modules", "relative dir forced"},
		{"rm -rf /tmp/build", "tmp directory"},
		{"rm -rf /var/tmp/test", "var tmp directory"},

		// Interactive (not forced)
		{"rm -ri ~/file.txt", "interactive home file"},
		{"rm -r ~/Downloads/test", "recursive without force"},

		// Just echoing (quoted - we allow these)
		{"echo 'rm -rf /'", "echo quoted dangerous"},
		{"printf 'rm -rf /'", "printf dangerous"},

		// Other commands entirely
		{"ls -la /", "ls root"},
		{"cd /", "cd root"},
		{"cat /etc/passwd", "cat file"},
		{"mkdir -p /tmp/test", "mkdir"},
		{"cp -r /tmp/src /tmp/dst", "cp recursive"},
		{"mv /tmp/old /tmp/new", "mv"},

		// rm without recursive+force
		{"rm /tmp/file", "rm without flags"},
		{"rm -r /tmp/dir", "rm recursive only"},
		{"rm -f /tmp/file", "rm force only"},

		// rm -rf on clearly safe paths
		{"rm -rf ./build", "relative build dir"},
		{"rm -rf ./dist", "relative dist dir"},
		{"rm -rf ./target", "relative target dir"},
		{"rm -rf ./.cache", "relative cache dir"},
		{"rm -rf ./coverage", "relative coverage dir"},
		{"rm -rf /tmp/myapp-build", "tmp build dir"},
		{"rm -rf /var/tmp/cache", "var tmp cache"},
		{"rm -rf node_modules", "node_modules without path"},
		{"rm -rf __pycache__", "pycache without path"},

		// rm on subdirectories of home (not home itself)
		{"rm -rf ~/Downloads/old-files", "downloads subdir"},
		{"rm -rf ~/projects/test-project", "projects subdir"},
		{"rm -rf ~/.cache/myapp", "cache subdir"},
		{"rm -rf ~/.local/share/trash", "local share subdir"},
		{"rm -rf /Users/john/Downloads/file", "user downloads subdir"},
		{"rm -rf /home/john/projects/temp", "linux user projects subdir"},

		// Commands that mention rm but don't execute it
		{"grep -r 'rm -rf' .", "grep for rm pattern"},
		{"git log --grep='rm -rf'", "git log grep"},
		{"man rm", "man page for rm"},
		{"which rm", "which rm"},
		{"type rm", "type rm"},
		{"alias rm='rm -i'", "alias definition"},

		// Safe shell wrapper commands
		{"bash -c 'echo hello'", "bash echo"},
		{"sh -c 'ls -la'", "sh ls"},
		{"eval 'export FOO=bar'", "eval export"},

		// rm with safe variables
		{"rm -rf $TMPDIR/build", "TMPDIR variable"},
		{"rm -rf ${TEMP}/cache", "TEMP variable"},
		{"rm -rf $PWD/dist", "PWD variable"},

		// Completely unrelated commands that should never trigger
		{"ls /", "ls root"},
		{"ls -la /home", "ls home"},
		{"ls ~/", "ls home tilde"},
		{"cat /etc/hosts", "cat etc file"},
		{"cat ~/.bashrc", "cat home file"},
		{"cd /", "cd root"},
		{"cd ~", "cd home"},
		{"cd $HOME", "cd HOME var"},
		{"pwd", "pwd"},
		{"echo /", "echo root"},
		{"echo ~", "echo home"},
		{"echo $HOME", "echo HOME var"},
		{"mkdir /tmp/test", "mkdir tmp"},
		{"mkdir -p ~/projects/new", "mkdir home subdir"},
		{"touch ~/file.txt", "touch home file"},
		{"cp /etc/hosts /tmp/", "cp from etc"},
		{"cp ~/.bashrc ~/.bashrc.bak", "cp home files"},
		{"mv ~/old ~/new", "mv home files"},
		{"chmod 755 ~/script.sh", "chmod home file"},
		{"chown user:group ~/file", "chown home file"},
		{"find / -name foo", "find from root"},
		{"find ~ -type f", "find from home"},
		{"grep pattern /", "grep in root"},
		{"grep -r pattern ~/", "grep in home"},
		{"tar -czf backup.tar.gz ~/", "tar home"},
		{"tar -xzf archive.tar.gz -C /tmp", "tar extract to tmp"},
		{"rsync -av ~/ /backup/", "rsync home"},
		{"scp ~/file.txt remote:/path", "scp from home"},
		{"curl https://example.com > ~/file", "curl to home"},
		{"wget -O ~/file https://example.com", "wget to home"},
		{"git clone repo ~/projects/repo", "git clone to home"},
		{"npm install -g package", "npm global install"},
		{"pip install --user package", "pip user install"},
		{"docker run -v ~/:/data image", "docker mount home"},
		{"python ~/script.py", "python home script"},
		{"node ~/app.js", "node home script"},
		{"bash ~/script.sh", "bash home script"},
		{"sh -c 'cd / && ls'", "sh cd and ls"},
		{"bash -c 'echo $HOME'", "bash echo home"},
		{"sudo ls /root", "sudo ls root home"},
		{"sudo cat /etc/shadow", "sudo cat shadow"},
		{"doas ls /", "doas ls root"},

		// Commands with paths that look dangerous but aren't rm
		{"file /", "file command on root"},
		{"stat ~/", "stat on home"},
		{"du -sh /", "du on root"},
		{"df /", "df on root"},
		{"mount /dev/sda1 /", "mount to root"},
		{"umount /", "umount root"},
		{"ln -s /usr/bin/foo ~/bin/foo", "symlink to home"},

		// Path patterns in non-dangerous contexts
		{"export PATH=$HOME/bin:$PATH", "export with home"},
		{"PATH=/usr/local/bin:$PATH", "path assignment"},
		{"HOME=/tmp/test", "home assignment"},
		{"cd / && ls && cd -", "cd chain with root"},
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

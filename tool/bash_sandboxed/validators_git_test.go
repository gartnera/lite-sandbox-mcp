package bash_sandboxed

import (
	"strings"
	"testing"
)

func TestValidate_AllowedGitSubcommands(t *testing.T) {
	tests := []struct {
		name    string
		command string
	}{
		{"git status", "git status"},
		{"git log", "git log"},
		{"git log oneline", "git log --oneline"},
		{"git log graph", "git log --oneline --graph --all"},
		{"git diff", "git diff"},
		{"git diff cached", "git diff --cached"},
		{"git diff staged", "git diff --staged"},
		{"git diff files", "git diff HEAD~1 HEAD"},
		{"git show", "git show"},
		{"git show commit", "git show HEAD"},
		{"git blame", "git blame file.go"},
		{"git branch list", "git branch"},
		{"git branch verbose", "git branch -v"},
		{"git branch all", "git branch -a"},
		{"git branch remote", "git branch -r"},
		{"git tag list", "git tag"},
		{"git tag list pattern", "git tag -l 'v*'"},
		{"git shortlog", "git shortlog"},
		{"git shortlog summary", "git shortlog -sn"},
		{"git describe", "git describe"},
		{"git describe tags", "git describe --tags"},
		{"git rev-parse HEAD", "git rev-parse HEAD"},
		{"git rev-parse branch", "git rev-parse --abbrev-ref HEAD"},
		{"git rev-list", "git rev-list HEAD"},
		{"git rev-list count", "git rev-list --count HEAD"},
		{"git ls-files", "git ls-files"},
		{"git ls-tree", "git ls-tree HEAD"},
		{"git cat-file", "git cat-file -p HEAD"},
		{"git name-rev", "git name-rev HEAD"},
		{"git config list", "git config --list"},
		{"git config get", "git config --get user.name"},
		{"git config get-all", "git config --get-all user.name"},
		{"git config get-regexp", "git config --get-regexp 'user.*'"},
		{"git config get-urlmatch", "git config --get-urlmatch http https://example.com"},
		{"git config -l", "git config -l"},
		{"bare git", "git"},
		{"git version", "git --version"},
		{"git help", "git --help"},
		{"git -C path status", "git -C /tmp status"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f, err := ParseBash(tt.command)
			if err != nil {
				t.Fatalf("parse error: %v", err)
			}
			if err := validate(f); err != nil {
				t.Fatalf("expected command to be allowed, got: %v", err)
			}
		})
	}
}

func TestValidate_BlockedGitSubcommands(t *testing.T) {
	tests := []struct {
		name    string
		command string
		errMsg  string
	}{
		// Network access
		{"git clone", "git clone https://example.com/repo.git", `git subcommand "clone" is not allowed`},
		{"git fetch", "git fetch origin", `git subcommand "fetch" is not allowed`},
		{"git pull", "git pull", `git subcommand "pull" is not allowed`},
		{"git push", "git push origin main", `git subcommand "push" is not allowed`},
		// Modifies worktree
		{"git checkout", "git checkout main", `git subcommand "checkout" is not allowed`},
		{"git switch", "git switch main", `git subcommand "switch" is not allowed`},
		{"git restore", "git restore file.go", `git subcommand "restore" is not allowed`},
		// Modifies history
		{"git commit", "git commit -m 'msg'", `git subcommand "commit" is not allowed`},
		{"git merge", "git merge feature", `git subcommand "merge" is not allowed`},
		{"git rebase", "git rebase main", `git subcommand "rebase" is not allowed`},
		{"git cherry-pick", "git cherry-pick abc123", `git subcommand "cherry-pick" is not allowed`},
		// Modifies index/worktree
		{"git add", "git add file.go", `git subcommand "add" is not allowed`},
		{"git rm", "git rm file.go", `git subcommand "rm" is not allowed`},
		{"git mv", "git mv old.go new.go", `git subcommand "mv" is not allowed`},
		{"git reset", "git reset HEAD", `git subcommand "reset" is not allowed`},
		// Modifies state
		{"git stash", "git stash", `git subcommand "stash" is not allowed`},
		// Remote code / execution
		{"git submodule", "git submodule update", `git subcommand "submodule" is not allowed`},
		{"git hook", "git hook run pre-commit", `git subcommand "hook" is not allowed`},
		{"git filter-branch", "git filter-branch --env-filter 'echo'", `git subcommand "filter-branch" is not allowed`},
		// Other write operations
		{"git init", "git init", `git subcommand "init" is not allowed`},
		{"git clean", "git clean -fd", `git subcommand "clean" is not allowed`},
		{"git bisect", "git bisect start", `git subcommand "bisect" is not allowed`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f, err := ParseBash(tt.command)
			if err != nil {
				t.Fatalf("parse error: %v", err)
			}
			err = validate(f)
			if err == nil {
				t.Fatal("expected validation error for blocked git subcommand")
			}
			if !strings.Contains(err.Error(), tt.errMsg) {
				t.Fatalf("expected error containing %q, got %q", tt.errMsg, err.Error())
			}
		})
	}
}

func TestValidate_BlockedGitBranchFlags(t *testing.T) {
	tests := []struct {
		name    string
		command string
		errMsg  string
	}{
		{"branch -d", "git branch -d feature", `git branch flag "-d" is not allowed`},
		{"branch -D", "git branch -D feature", `git branch flag "-D" is not allowed`},
		{"branch --delete", "git branch --delete feature", `git branch flag "--delete" is not allowed`},
		{"branch -m", "git branch -m old new", `git branch flag "-m" is not allowed`},
		{"branch -M", "git branch -M old new", `git branch flag "-M" is not allowed`},
		{"branch --move", "git branch --move old new", `git branch flag "--move" is not allowed`},
		{"branch -c", "git branch -c old new", `git branch flag "-c" is not allowed`},
		{"branch -C", "git branch -C old new", `git branch flag "-C" is not allowed`},
		{"branch --copy", "git branch --copy old new", `git branch flag "--copy" is not allowed`},
		{"branch --edit-description", "git branch --edit-description", `git branch flag "--edit-description" is not allowed`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f, err := ParseBash(tt.command)
			if err != nil {
				t.Fatalf("parse error: %v", err)
			}
			err = validate(f)
			if err == nil {
				t.Fatal("expected validation error for blocked git branch flag")
			}
			if !strings.Contains(err.Error(), tt.errMsg) {
				t.Fatalf("expected error containing %q, got %q", tt.errMsg, err.Error())
			}
		})
	}
}

func TestValidate_BlockedGitTagFlags(t *testing.T) {
	tests := []struct {
		name    string
		command string
		errMsg  string
	}{
		{"tag -a", "git tag -a v1.0 -m 'release'", `git tag flag "-a" is not allowed`},
		{"tag --annotate", "git tag --annotate v1.0", `git tag flag "--annotate" is not allowed`},
		{"tag -d", "git tag -d v1.0", `git tag flag "-d" is not allowed`},
		{"tag --delete", "git tag --delete v1.0", `git tag flag "--delete" is not allowed`},
		{"tag -s", "git tag -s v1.0", `git tag flag "-s" is not allowed`},
		{"tag --sign", "git tag --sign v1.0", `git tag flag "--sign" is not allowed`},
		{"tag -f", "git tag -f v1.0", `git tag flag "-f" is not allowed`},
		{"tag --force", "git tag --force v1.0", `git tag flag "--force" is not allowed`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f, err := ParseBash(tt.command)
			if err != nil {
				t.Fatalf("parse error: %v", err)
			}
			err = validate(f)
			if err == nil {
				t.Fatal("expected validation error for blocked git tag flag")
			}
			if !strings.Contains(err.Error(), tt.errMsg) {
				t.Fatalf("expected error containing %q, got %q", tt.errMsg, err.Error())
			}
		})
	}
}

func TestValidate_BlockedGitConfig(t *testing.T) {
	tests := []struct {
		name    string
		command string
		errMsg  string
	}{
		{"config set value", "git config user.name 'test'", "git config is only allowed with"},
		{"config unset", "git config --unset user.name", "git config is only allowed with"},
		{"config bare", "git config", "git config is only allowed with"},
		{"config edit", "git config --edit", "git config is only allowed with"},
		{"config global set", "git config --global user.email 'a@b.com'", "git config is only allowed with"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f, err := ParseBash(tt.command)
			if err != nil {
				t.Fatalf("parse error: %v", err)
			}
			err = validate(f)
			if err == nil {
				t.Fatal("expected validation error for blocked git config usage")
			}
			if !strings.Contains(err.Error(), tt.errMsg) {
				t.Fatalf("expected error containing %q, got %q", tt.errMsg, err.Error())
			}
		})
	}
}

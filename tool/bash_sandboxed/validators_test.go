package bash_sandboxed

import (
	"strings"
	"testing"
)

func TestValidate_BlockedFindFlags(t *testing.T) {
	tests := []struct {
		name    string
		command string
		errMsg  string
	}{
		{"find -exec rm", `find . -exec rm {} \;`, `find flag "-exec" is not allowed`},
		{"find -delete", `find . -delete`, `find flag "-delete" is not allowed`},
		{"find -execdir python", `find . -execdir python {} +`, `find flag "-execdir" is not allowed`},
		{"find -ok", `find . -ok rm {} \;`, `find flag "-ok" is not allowed`},
		{"find -okdir", `find . -okdir rm {} \;`, `find flag "-okdir" is not allowed`},
		{"find -fls", `find . -fls /tmp/out`, `find flag "-fls" is not allowed`},
		{"find -fprint", `find . -fprint /tmp/out`, `find flag "-fprint" is not allowed`},
		{"find -fprint0", `find . -fprint0 /tmp/out`, `find flag "-fprint0" is not allowed`},
		{"find -fprintf", `find . -fprintf /tmp/out '%p'`, `find flag "-fprintf" is not allowed`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f, err := ParseBash(tt.command)
			if err != nil {
				t.Fatalf("parse error: %v", err)
			}
			err = newTestSandbox().validate(f)
			if err == nil {
				t.Fatal("expected validation error for blocked find flag")
			}
			if !strings.Contains(err.Error(), tt.errMsg) {
				t.Fatalf("expected error containing %q, got %q", tt.errMsg, err.Error())
			}
		})
	}
}

func TestValidate_AllowedFindFlags(t *testing.T) {
	tests := []struct {
		name    string
		command string
	}{
		{"find -name", "find . -name '*.go'"},
		{"find -type f -print", "find . -type f -print"},
		{"find -maxdepth -ls", "find . -maxdepth 2 -ls"},
		{"find -iname", "find . -iname '*.TXT'"},
		{"find -size", "find . -size +1M"},
		{"find -mtime", "find . -mtime -7"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f, err := ParseBash(tt.command)
			if err != nil {
				t.Fatalf("parse error: %v", err)
			}
			if err := newTestSandbox().validate(f); err != nil {
				t.Fatalf("expected command to be allowed, got: %v", err)
			}
		})
	}
}

func TestValidate_BlockedTarFlags(t *testing.T) {
	tests := []struct {
		name    string
		command string
		errMsg  string
	}{
		{"tar extract", "tar -xf archive.tar", "tar flag '-x' is not allowed"},
		{"tar create", "tar -cf archive.tar .", "tar flag '-c' is not allowed"},
		{"tar append", "tar -rf archive.tar file", "tar flag '-r' is not allowed"},
		{"tar update", "tar -uf archive.tar file", "tar flag '-u' is not allowed"},
		{"tar delete", "tar --delete -f archive.tar file", `tar flag "--delete" is not allowed`},
		{"tar extract long", "tar --extract -f archive.tar", `tar flag "--extract" is not allowed`},
		{"tar get long", "tar --get -f archive.tar", `tar flag "--get" is not allowed`},
		{"tar create long", "tar --create -f archive.tar .", `tar flag "--create" is not allowed`},
		{"tar append long", "tar --append -f archive.tar file", `tar flag "--append" is not allowed`},
		{"tar update long", "tar --update -f archive.tar file", `tar flag "--update" is not allowed`},
		{"tar extract combined", "tar -xzf archive.tar.gz", "tar flag '-x' is not allowed"},
		{"tar old style extract", "tar xf archive.tar", "tar flag 'x' is not allowed"},
		{"tar old style create", "tar czf archive.tar.gz .", "tar flag 'c' is not allowed"},
		{"tar no mode flag", "tar -f archive.tar", "tar is only allowed in list mode"},
		{"tar verbose only", "tar -v", "tar is only allowed in list mode"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f, err := ParseBash(tt.command)
			if err != nil {
				t.Fatalf("parse error: %v", err)
			}
			err = newTestSandbox().validate(f)
			if err == nil {
				t.Fatal("expected validation error for blocked tar flag")
			}
			if !strings.Contains(err.Error(), tt.errMsg) {
				t.Fatalf("expected error containing %q, got %q", tt.errMsg, err.Error())
			}
		})
	}
}

func TestValidate_BlockedUnzipFlags(t *testing.T) {
	tests := []struct {
		name    string
		command string
		errMsg  string
	}{
		{"unzip extract default", "unzip archive.zip", "unzip is only allowed with"},
		{"unzip with dir", "unzip -d /tmp archive.zip", "unzip is only allowed with"},
		{"unzip overwrite", "unzip -o archive.zip", "unzip is only allowed with"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f, err := ParseBash(tt.command)
			if err != nil {
				t.Fatalf("parse error: %v", err)
			}
			err = newTestSandbox().validate(f)
			if err == nil {
				t.Fatal("expected validation error for blocked unzip usage")
			}
			if !strings.Contains(err.Error(), tt.errMsg) {
				t.Fatalf("expected error containing %q, got %q", tt.errMsg, err.Error())
			}
		})
	}
}

func TestValidate_BlockedArFlags(t *testing.T) {
	tests := []struct {
		name    string
		command string
		errMsg  string
	}{
		{"ar replace", "ar r archive.a file.o", "ar operation 'r' is not allowed"},
		{"ar delete", "ar d archive.a file.o", "ar operation 'd' is not allowed"},
		{"ar quick append", "ar q archive.a file.o", "ar operation 'q' is not allowed"},
		{"ar extract", "ar x archive.a", "ar operation 'x' is not allowed"},
		{"ar move", "ar m archive.a file.o", "ar operation 'm' is not allowed"},
		{"ar no args", "ar", "ar requires an operation argument"},
		{"ar create with s", "ar s archive.a", "ar operation 's' is not allowed"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f, err := ParseBash(tt.command)
			if err != nil {
				t.Fatalf("parse error: %v", err)
			}
			err = newTestSandbox().validate(f)
			if err == nil {
				t.Fatal("expected validation error for blocked ar operation")
			}
			if !strings.Contains(err.Error(), tt.errMsg) {
				t.Fatalf("expected error containing %q, got %q", tt.errMsg, err.Error())
			}
		})
	}
}

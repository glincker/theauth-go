package main

import (
	"bytes"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func runInit(t *testing.T, args ...string) (int, string, string) {
	t.Helper()
	var out, errb bytes.Buffer
	code := run(append([]string{"init"}, args...), &out, &errb, zeros{})
	return code, out.String(), errb.String()
}

func TestInitWritesFiles(t *testing.T) {
	tests := []struct {
		name      string
		args      []string
		wantFiles []string
		mainHas   string
		envHas    string
	}{
		{"memory", nil, []string{"main.go", ".env.example"}, "memory.New()", "THEAUTH_SETUP_TOKEN="},
		{"postgres", []string{"--storage", "postgres"}, []string{"main.go", ".env.example"}, "postgres.New(pool)", "postgres://user:password@"},
		{"mysql", []string{"--storage", "mysql"}, []string{"main.go", ".env.example"}, "mysql.New(db)", "parseTime=true"},
		{"with postgres", []string{"--with-postgres"}, []string{"main.go", ".env.example", "docker-compose.yml"}, "postgres.New(pool)", "THEAUTH_PG_PASSWORD="},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			code, out, errOut := runInit(t, append([]string{"--dir", dir}, tt.args...)...)
			if code != 0 {
				t.Fatalf("code %d: %s", code, errOut)
			}
			for _, f := range tt.wantFiles {
				if _, err := os.Stat(filepath.Join(dir, f)); err != nil {
					t.Errorf("missing %s", f)
				}
			}
			src, _ := os.ReadFile(filepath.Join(dir, "main.go"))
			if !strings.Contains(string(src), tt.mainHas) {
				t.Errorf("main.go missing %q", tt.mainHas)
			}
			if _, err := parser.ParseFile(token.NewFileSet(), "main.go", src, parser.AllErrors); err != nil {
				t.Errorf("main.go does not parse: %v", err)
			}
			env, _ := os.ReadFile(filepath.Join(dir, ".env.example"))
			if !strings.Contains(string(env), tt.envHas) {
				t.Errorf(".env.example missing %q:\n%s", tt.envHas, env)
			}
			if !strings.Contains(out, "go mod init") || !strings.Contains(out, "go get github.com/glincker/theauth-go/v2") {
				t.Errorf("missing next steps:\n%s", out)
			}
		})
	}
}

func TestInitNoComposeWithoutFlag(t *testing.T) {
	dir := t.TempDir()
	if code, _, _ := runInit(t, "--dir", dir, "--storage", "postgres"); code != 0 {
		t.Fatal("init failed")
	}
	if _, err := os.Stat(filepath.Join(dir, "docker-compose.yml")); err == nil {
		t.Fatal("docker-compose.yml written without --with-postgres")
	}
}

func TestInitDetectsGoMod(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte("module x\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, out, _ := runInit(t, "--dir", dir)
	if strings.Contains(out, "go mod init") {
		t.Errorf("should not suggest go mod init when go.mod exists:\n%s", out)
	}
}

func TestInitIdempotent(t *testing.T) {
	dir := t.TempDir()
	mainPath := filepath.Join(dir, "main.go")
	if err := os.WriteFile(mainPath, []byte("package main // mine\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	code, out, _ := runInit(t, "--dir", dir)
	if code != 0 || !strings.Contains(out, "skip main.go") {
		t.Fatalf("code %d out %s", code, out)
	}
	if got, _ := os.ReadFile(mainPath); string(got) != "package main // mine\n" {
		t.Fatalf("main.go overwritten: %s", got)
	}
	if _, err := os.Stat(filepath.Join(dir, ".env.example")); err != nil {
		t.Error(".env.example should still be written")
	}
	if code, out, _ = runInit(t, "--dir", dir, "--force"); code != 0 || !strings.Contains(out, "wrote main.go") {
		t.Fatalf("force: code %d out %s", code, out)
	}
	if got, _ := os.ReadFile(mainPath); strings.Contains(string(got), "// mine") {
		t.Error("--force did not overwrite")
	}
}

func TestInitPrint(t *testing.T) {
	dir := t.TempDir()
	code, out, _ := runInit(t, "--dir", dir, "--print")
	if code != 0 || !strings.Contains(out, "theauth.New(") {
		t.Fatalf("code %d out %s", code, out)
	}
	if entries, _ := os.ReadDir(dir); len(entries) != 0 {
		t.Errorf("--print wrote files: %v", entries)
	}
}

func TestInitErrors(t *testing.T) {
	if code, _, errOut := runInit(t, "--storage", "oracle"); code != 2 || !strings.Contains(errOut, "unknown --storage") {
		t.Errorf("code %d err %s", code, errOut)
	}
	if code, _, _ := runInit(t, "--nope"); code != 2 {
		t.Errorf("code %d", code)
	}
}

func TestInitEnvFilePrivate(t *testing.T) {
	dir := t.TempDir()
	runInit(t, "--dir", dir)
	st, err := os.Stat(filepath.Join(dir, ".env.example"))
	if err != nil || st.Mode().Perm() != 0o600 {
		t.Fatalf("stat %v mode %v", err, st)
	}
}

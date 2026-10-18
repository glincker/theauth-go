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

func TestInitSeedFlag(t *testing.T) {
	const call = "a.CreateUser(ctx, theauth.CreateUserInput{Email: \"ada@example.com\""
	tests := []struct {
		name     string
		args     []string
		wantCode int
		wantCall bool
		errHas   string
	}{
		{"absent", nil, 0, false, ""},
		{"present", []string{"--seed-email", "Ada@Example.com", "--seed-name", " Ada "}, 0, true, ""},
		{"present without name", []string{"--seed-email", "ada@example.com"}, 0, true, ""},
		{"invalid email", []string{"--seed-email", "not-an-email"}, 2, false, "invalid --seed-email"},
		{"display name form rejected", []string{"--seed-email", "Ada <ada@example.com>"}, 2, false, "invalid --seed-email"},
		{"email with two at signs", []string{"--seed-email", "a@b@example.com"}, 2, false, "invalid --seed-email"},
		{"name without email", []string{"--seed-name", "Ada"}, 2, false, "needs --seed-email"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			code, _, errOut := runInit(t, append([]string{"--dir", dir}, tt.args...)...)
			if code != tt.wantCode {
				t.Fatalf("code %d, want %d: %s", code, tt.wantCode, errOut)
			}
			if tt.errHas != "" && !strings.Contains(errOut, tt.errHas) {
				t.Errorf("stderr %q missing %q", errOut, tt.errHas)
			}
			src, err := os.ReadFile(filepath.Join(dir, "main.go"))
			if tt.wantCode != 0 {
				if err == nil {
					t.Fatal("main.go written for rejected input")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if got := strings.Contains(string(src), call); got != tt.wantCall {
				t.Errorf("CreateUser call present=%v, want %v:\n%s", got, tt.wantCall, src)
			}
			if tt.wantCall {
				requireSeedDisabled(t, string(src))
			}
			if tt.wantCall && strings.Contains(string(src), "Name:") != (len(tt.args) > 2) {
				t.Errorf("Name field presence does not match the flags:\n%s", src)
			}
			if _, err := parser.ParseFile(token.NewFileSet(), "main.go", src, parser.AllErrors); err != nil {
				t.Errorf("main.go does not parse: %v", err)
			}
			env, _ := os.ReadFile(filepath.Join(dir, ".env.example"))
			if strings.Contains(string(env), "ada@") {
				t.Errorf("seed address leaked into .env.example")
			}
		})
	}
}

// requireSeedDisabled fails when any non-comment line of main.go calls CreateUser, and when the
// explanation of why the seed is disabled is missing.
func requireSeedDisabled(t *testing.T, src string) {
	t.Helper()
	for _, line := range strings.Split(src, "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.Contains(trimmed, "CreateUser") && !strings.HasPrefix(trimmed, "//") {
			t.Errorf("active CreateUser line in generated main.go: %q", line)
		}
	}
	if !strings.Contains(src, "closes the Bootstrap gate") {
		t.Error("generated main.go does not explain why the seed is disabled")
	}
}

func TestInitSeedCompilesPerStorage(t *testing.T) {
	for _, storage := range []string{"memory", "postgres", "mysql"} {
		t.Run(storage, func(t *testing.T) {
			dir := t.TempDir()
			code, _, errOut := runInit(t, "--dir", dir, "--storage", storage, "--seed-email", "ada@example.com", "--seed-name", "Ada")
			if code != 0 {
				t.Fatalf("code %d: %s", code, errOut)
			}
			src, err := os.ReadFile(filepath.Join(dir, "main.go"))
			if err != nil {
				t.Fatal(err)
			}
			if _, err := parser.ParseFile(token.NewFileSet(), "main.go", src, parser.AllErrors); err != nil {
				t.Fatalf("main.go does not parse: %v", err)
			}
			body := string(src)
			requireSeedDisabled(t, body)
			order := []string{"theauth.New(", "a.CreateUser(", "mux := http.NewServeMux()"}
			last := -1
			for _, want := range order {
				idx := strings.Index(body, want)
				if idx <= last {
					t.Fatalf("%q not after the previous step (index %d, previous %d)", want, idx, last)
				}
				last = idx
			}
			if !strings.Contains(body, "Bootstrap: &theauth.BootstrapConfig{") {
				t.Error("Bootstrap gating removed from seeded main.go")
			}
		})
	}
}

func TestInitSeedNotOverwrittenWithoutForce(t *testing.T) {
	dir := t.TempDir()
	mainPath := filepath.Join(dir, "main.go")
	if err := os.WriteFile(mainPath, []byte("package main // mine\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	code, out, _ := runInit(t, "--dir", dir, "--seed-email", "ada@example.com")
	if code != 0 || !strings.Contains(out, "skip main.go") {
		t.Fatalf("code %d out %s", code, out)
	}
	if got, _ := os.ReadFile(mainPath); string(got) != "package main // mine\n" {
		t.Fatalf("main.go overwritten without --force: %s", got)
	}
	if code, out, _ = runInit(t, "--dir", dir, "--seed-email", "ada@example.com", "--force"); code != 0 || !strings.Contains(out, "wrote main.go") {
		t.Fatalf("force: code %d out %s", code, out)
	}
	if got, _ := os.ReadFile(mainPath); !strings.Contains(string(got), "CreateUserInput{Email: \"ada@example.com\"}") {
		t.Error("--force did not write the seed call")
	}
}

func TestInitPrintSeed(t *testing.T) {
	dir := t.TempDir()
	code, out, errOut := runInit(t, "--dir", dir, "--print", "--seed-email", "ada@example.com")
	if !strings.Contains(errOut, "commented-out CreateUser") {
		t.Errorf("stderr notice missing: %q", errOut)
	}
	if code != 0 || !strings.Contains(out, "CreateUserInput{Email: \"ada@example.com\"}") {
		t.Fatalf("code %d out %s", code, out)
	}
	requireSeedDisabled(t, out)
	if strings.Contains(out, "note: the seed user") {
		t.Error("notice must go to stderr with --print")
	}
	if entries, _ := os.ReadDir(dir); len(entries) != 0 {
		t.Errorf("--print wrote files: %v", entries)
	}
}

func TestInitSeedNoticeOnStdout(t *testing.T) {
	code, out, _ := runInit(t, "--dir", t.TempDir(), "--seed-email", "ada@example.com")
	if code != 0 || !strings.Contains(out, "commented-out CreateUser") {
		t.Fatalf("code %d out %s", code, out)
	}
}

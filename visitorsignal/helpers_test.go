package visitorsignal

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func readTestdata(t testing.TB, rel string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", rel))
	if err != nil {
		t.Fatalf("read %s: %v", rel, err)
	}
	return b
}

func loadJSON(t testing.TB, rel string, v any) {
	t.Helper()
	if err := json.Unmarshal(readTestdata(t, rel), v); err != nil {
		t.Fatalf("decode %s: %v", rel, err)
	}
}

func ptr[T any](v T) *T { return &v }

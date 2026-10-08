package redis

import (
	"context"
	"strconv"
	"sync"
	"testing"
	"time"
)

// fake interprets the adapter's scripts against a map, honoring PX expiry with
// an injected clock. It stands in for a real Redis.
type fake struct {
	mu   sync.Mutex
	now  time.Time
	data map[string]string
	exp  map[string]time.Time
}

func newFake() *fake {
	return &fake{now: time.Unix(1_700_000_000, 0), data: map[string]string{}, exp: map[string]time.Time{}}
}

func (f *fake) alive(k string) bool {
	if e, ok := f.exp[k]; ok && !f.now.Before(e) {
		delete(f.data, k)
		delete(f.exp, k)
	}
	_, ok := f.data[k]
	return ok
}

func (f *fake) setTTL(k, ms string) {
	delete(f.exp, k)
	if n, _ := strconv.Atoi(ms); n > 0 {
		f.exp[k] = f.now.Add(time.Duration(n) * time.Millisecond)
	}
}

func (f *fake) Eval(_ context.Context, script string, keys []string, args ...any) (any, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	k := keys[0]
	switch script {
	case ScriptGet:
		if !f.alive(k) {
			return nil, nil
		}
		return f.data[k], nil
	case ScriptSet:
		f.data[k] = args[0].(string)
		f.setTTL(k, args[1].(string))
		return "OK", nil
	case ScriptSetNX:
		if f.alive(k) {
			return int64(0), nil
		}
		f.data[k] = args[0].(string)
		f.setTTL(k, args[1].(string))
		return int64(1), nil
	case ScriptDel:
		delete(f.data, k)
		delete(f.exp, k)
		return int64(1), nil
	case ScriptIncr:
		f.alive(k)
		n, _ := strconv.ParseInt(f.data[k], 10, 64)
		n++
		f.data[k] = strconv.FormatInt(n, 10)
		if n == 1 {
			f.setTTL(k, args[0].(string))
		}
		return n, nil
	}
	panic("unknown script")
}

func TestStore(t *testing.T) {
	ctx := context.Background()
	f := newFake()
	s := New(f, "t:")

	if _, ok, err := s.Get(ctx, "a"); ok || err != nil {
		t.Fatalf("missing key: ok=%v err=%v", ok, err)
	}
	if err := s.Set(ctx, "a", []byte("v"), time.Second); err != nil {
		t.Fatal(err)
	}
	if v, ok, _ := s.Get(ctx, "a"); !ok || string(v) != "v" {
		t.Fatalf("get: %q %v", v, ok)
	}
	if _, ok := f.data["t:a"]; !ok {
		t.Fatal("prefix not applied")
	}
	f.now = f.now.Add(2 * time.Second)
	if _, ok, _ := s.Get(ctx, "a"); ok {
		t.Fatal("expired key visible")
	}

	cases := []struct {
		name string
		do   func() (any, error)
		want any
	}{
		{"setnx first", func() (any, error) { return s.SetNX(ctx, "n", []byte("1"), time.Minute) }, true},
		{"setnx second", func() (any, error) { return s.SetNX(ctx, "n", []byte("1"), time.Minute) }, false},
		{"incr 1", func() (any, error) { return s.Incr(ctx, "c", time.Minute) }, int64(1)},
		{"incr 2", func() (any, error) { return s.Incr(ctx, "c", time.Minute) }, int64(2)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := tc.do()
			if err != nil || got != tc.want {
				t.Fatalf("got %v err %v want %v", got, err, tc.want)
			}
		})
	}
	f.now = f.now.Add(2 * time.Minute)
	if n, _ := s.Incr(ctx, "c", time.Minute); n != 1 {
		t.Fatalf("counter should restart, got %d", n)
	}
	_ = s.Delete(ctx, "c")
	if _, ok, _ := s.Get(ctx, "c"); ok {
		t.Fatal("delete failed")
	}
}

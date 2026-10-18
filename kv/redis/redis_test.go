package redis

import (
	"context"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/glincker/theauth-go/v2/kv"
	"github.com/glincker/theauth-go/v2/kv/kvtest"
)

// fake interprets the adapter's scripts against a map, honoring PX expiry with
// an injected clock. It stands in for a real Redis.
type fake struct {
	mu   sync.Mutex
	clk  func() time.Time
	now  time.Time
	data map[string]string
	exp  map[string]time.Time
}

func newFake() *fake {
	return &fake{now: time.Unix(1_700_000_000, 0), data: map[string]string{}, exp: map[string]time.Time{}}
}

func (f *fake) alive(k string) bool {
	if f.clk != nil {
		f.now = f.clk()
	}
	if e, ok := f.exp[k]; ok && !f.now.Before(e) {
		delete(f.data, k)
		delete(f.exp, k)
	}
	_, ok := f.data[k]
	return ok
}

func (f *fake) setTTL(k, ms string) {
	if f.clk != nil {
		f.now = f.clk()
	}
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
	s := New(f, WithPrefix("t:"))

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

func TestContract(t *testing.T) {
	kvtest.Run(t, func(_ *testing.T, clk *kvtest.Clock) kv.Cache {
		f := newFake()
		f.clk = clk.Now
		return New(f, WithPrefix("t:"))
	})
}

func TestContractDefaultPrefix(t *testing.T) {
	kvtest.Run(t, func(_ *testing.T, clk *kvtest.Clock) kv.Cache {
		f := newFake()
		f.clk = clk.Now
		return New(f)
	})
}

func TestContractWithoutPrefix(t *testing.T) {
	kvtest.Run(t, func(_ *testing.T, clk *kvtest.Clock) kv.Cache {
		f := newFake()
		f.clk = clk.Now
		return New(f, WithoutPrefix())
	})
}

func TestDefaultPrefixApplied(t *testing.T) {
	ctx := context.Background()
	cases := []struct {
		name    string
		opts    []Option
		wantKey string
	}{
		{"no option uses the default", nil, "theauth:k"},
		{"custom prefix", []Option{WithPrefix("app1:")}, "app1:k"},
		{"WithoutPrefix disables the prefix", []Option{WithoutPrefix()}, "k"},
		{"explicit empty prefix disables the prefix", []Option{WithPrefix("")}, "k"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newFake()
			s := New(f, tc.opts...)
			if err := s.Set(ctx, "k", []byte("v"), time.Minute); err != nil {
				t.Fatal(err)
			}
			if len(f.data) != 1 {
				t.Fatalf("stored keys %v, want exactly one", f.data)
			}
			if _, ok := f.data[tc.wantKey]; !ok {
				t.Fatalf("stored keys %v, want %q", f.data, tc.wantKey)
			}
		})
	}
}

func TestEveryOperationIsPrefixed(t *testing.T) {
	ctx := context.Background()
	f := newFake()
	s := New(f, WithPrefix("p:"))
	if _, err := s.SetNX(ctx, "n", []byte("1"), time.Minute); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Incr(ctx, "c", time.Minute); err != nil {
		t.Fatal(err)
	}
	if err := s.Set(ctx, "a", []byte("v"), time.Minute); err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{"p:n", "p:c", "p:a"} {
		if _, ok := f.data[k]; !ok {
			t.Fatalf("key %q not written with prefix, have %v", k, f.data)
		}
	}
	if err := s.Delete(ctx, "a"); err != nil {
		t.Fatal(err)
	}
	if _, ok := f.data["p:a"]; ok {
		t.Fatal("Delete did not remove the prefixed key")
	}
	if len(f.data) != 2 {
		t.Fatalf("unexpected keys %v", f.data)
	}
}

func TestOptOutReadsLegacyKeys(t *testing.T) {
	ctx := context.Background()
	f := newFake()
	f.data["session"] = "legacy"
	if v, ok, _ := New(f, WithoutPrefix()).Get(ctx, "session"); !ok || string(v) != "legacy" {
		t.Fatalf("opt-out store cannot read pre-prefix key: %q %v", v, ok)
	}
	if _, ok, _ := New(f).Get(ctx, "session"); ok {
		t.Fatal("default prefix must not read unprefixed keys")
	}
}

func TestNoCrossPrefixLeakage(t *testing.T) {
	kvtest.RunNamespaces(t, func(_ *testing.T, clk *kvtest.Clock) (kv.Cache, kv.Cache) {
		f := newFake()
		f.clk = clk.Now
		return New(f, WithPrefix("app1:")), New(f, WithPrefix("app2:"))
	})
}

func TestDefaultAndOptOutDoNotCollide(t *testing.T) {
	kvtest.RunNamespaces(t, func(_ *testing.T, clk *kvtest.Clock) (kv.Cache, kv.Cache) {
		f := newFake()
		f.clk = clk.Now
		return New(f), New(f, WithoutPrefix())
	})
}

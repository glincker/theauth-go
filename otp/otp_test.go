package otp

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/glincker/theauth-go/v2/kv"
)

type capture struct {
	mu   sync.Mutex
	msgs []Message
	err  error
}

func (c *capture) Send(_ context.Context, m Message) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.err != nil {
		return c.err
	}
	c.msgs = append(c.msgs, m)
	return nil
}

func (c *capture) last() Message {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.msgs[len(c.msgs)-1]
}

type clock struct{ t time.Time }

func (c *clock) now() time.Time          { return c.t }
func (c *clock) advance(d time.Duration) { c.t = c.t.Add(d) }

func setup(t *testing.T, mod func(*Config)) (*Service, *capture, *clock) {
	t.Helper()
	ck := &clock{t: time.Unix(1_800_000_000, 0)}
	cp := &capture{}
	cfg := Config{
		Cache:  kv.NewMemory(kv.WithClock(ck.now)),
		Sender: cp,
		Secret: []byte(strings.Repeat("s", 32)),
	}
	if mod != nil {
		mod(&cfg)
	}
	s, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return s, cp, ck
}

func TestNewValidation(t *testing.T) {
	good := Config{Cache: kv.NewMemory(), Sender: &capture{}, Secret: []byte(strings.Repeat("k", 32))}
	tests := []struct {
		name string
		mod  func(*Config)
		ok   bool
	}{
		{"valid", func(*Config) {}, true},
		{"no cache", func(c *Config) { c.Cache = nil }, false},
		{"no sender", func(c *Config) { c.Sender = nil }, false},
		{"short secret", func(c *Config) { c.Secret = []byte("short") }, false},
		{"length too small", func(c *Config) { c.Length = 3 }, false},
		{"length too big", func(c *Config) { c.Length = 11 }, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfg := good
			tc.mod(&cfg)
			_, err := New(cfg)
			if (err == nil) != tc.ok {
				t.Fatalf("err=%v want ok=%v", err, tc.ok)
			}
		})
	}
}

func TestFlow(t *testing.T) {
	ctx := context.Background()
	tests := []struct {
		name string
		run  func(t *testing.T, s *Service, cp *capture, ck *clock)
	}{
		{"issue and verify consumes code", func(t *testing.T, s *Service, cp *capture, _ *clock) {
			if err := s.Issue(ctx, "login", "A@Example.com"); err != nil {
				t.Fatal(err)
			}
			m := cp.last()
			if m.To != "a@example.com" || len(m.Code) != 6 {
				t.Fatalf("unexpected message %+v", m)
			}
			if err := s.Verify(ctx, "login", "a@example.com", m.Code); err != nil {
				t.Fatalf("verify: %v", err)
			}
			if err := s.Verify(ctx, "login", "a@example.com", m.Code); !errors.Is(err, ErrInvalid) {
				t.Fatalf("replay: %v", err)
			}
		}},
		{"wrong purpose fails", func(t *testing.T, s *Service, cp *capture, _ *clock) {
			_ = s.Issue(ctx, "login", "a@example.com")
			if err := s.Verify(ctx, "reset", "a@example.com", cp.last().Code); !errors.Is(err, ErrInvalid) {
				t.Fatalf("got %v", err)
			}
		}},
		{"expired code fails", func(t *testing.T, s *Service, cp *capture, ck *clock) {
			_ = s.Issue(ctx, "login", "a@example.com")
			ck.advance(11 * time.Minute)
			if err := s.Verify(ctx, "login", "a@example.com", cp.last().Code); !errors.Is(err, ErrInvalid) {
				t.Fatalf("got %v", err)
			}
		}},
		{"cooldown then resend", func(t *testing.T, s *Service, _ *capture, ck *clock) {
			if err := s.Issue(ctx, "login", "a@example.com"); err != nil {
				t.Fatal(err)
			}
			if err := s.Issue(ctx, "login", "a@example.com"); !errors.Is(err, ErrCooldown) {
				t.Fatalf("got %v", err)
			}
			ck.advance(61 * time.Second)
			if err := s.Issue(ctx, "login", "a@example.com"); err != nil {
				t.Fatalf("resend: %v", err)
			}
		}},
		{"lockout after max attempts", func(t *testing.T, s *Service, cp *capture, ck *clock) {
			_ = s.Issue(ctx, "login", "a@example.com")
			real := cp.last().Code
			for i := 0; i < 5; i++ {
				if err := s.Verify(ctx, "login", "a@example.com", "000000x"); !errors.Is(err, ErrInvalid) {
					t.Fatalf("attempt %d: %v", i, err)
				}
			}
			if err := s.Verify(ctx, "login", "a@example.com", real); !errors.Is(err, ErrLocked) {
				t.Fatalf("correct code after lockout: %v", err)
			}
			if err := s.Issue(ctx, "login", "a@example.com"); !errors.Is(err, ErrLocked) {
				t.Fatalf("issue while locked: %v", err)
			}
			ck.advance(16 * time.Minute)
			if err := s.Issue(ctx, "login", "a@example.com"); err != nil {
				t.Fatalf("issue after lockout: %v", err)
			}
		}},
		{"send failure releases cooldown", func(t *testing.T, s *Service, cp *capture, _ *clock) {
			cp.err = errors.New("smtp down")
			if err := s.Issue(ctx, "login", "a@example.com"); err == nil {
				t.Fatal("want send error")
			}
			cp.err = nil
			if err := s.Issue(ctx, "login", "a@example.com"); err != nil {
				t.Fatalf("retry: %v", err)
			}
		}},
		{"new code resets attempts", func(t *testing.T, s *Service, cp *capture, ck *clock) {
			_ = s.Issue(ctx, "login", "a@example.com")
			for i := 0; i < 3; i++ {
				_ = s.Verify(ctx, "login", "a@example.com", "bad")
			}
			ck.advance(61 * time.Second)
			_ = s.Issue(ctx, "login", "a@example.com")
			if err := s.Verify(ctx, "login", "a@example.com", cp.last().Code); err != nil {
				t.Fatalf("got %v", err)
			}
		}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			s, cp, ck := setup(t, nil)
			tc.run(t, s, cp, ck)
		})
	}
}

func TestSMSNormalizeAndLength(t *testing.T) {
	ctx := context.Background()
	s, cp, _ := setup(t, func(c *Config) { c.Channel = ChannelSMS; c.Length = 8 })
	if err := s.Issue(ctx, "login", "+1 (555) 010-0000"); err != nil {
		t.Fatal(err)
	}
	m := cp.last()
	if m.To != "+15550100000" || len(m.Code) != 8 || m.Channel != ChannelSMS {
		t.Fatalf("unexpected %+v", m)
	}
	if err := s.Verify(ctx, "login", "+1 555 010 0000", " "+m.Code+" "); err != nil {
		t.Fatalf("verify: %v", err)
	}
}

func TestTwilioSender(t *testing.T) {
	tests := []struct {
		name   string
		status int
		wantOK bool
	}{
		{"ok", 201, true},
		{"rejected", 400, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				user, pass, _ := r.BasicAuth()
				if user != "AC1" || pass != "tok" || r.URL.Path != "/2010-04-01/Accounts/AC1/Messages.json" {
					t.Errorf("bad request %s %s", r.URL.Path, user)
				}
				_ = r.ParseForm()
				if r.PostForm.Get("To") != "+15550100000" || !strings.Contains(r.PostForm.Get("Body"), "123456") {
					t.Errorf("bad form %v", r.PostForm)
				}
				w.WriteHeader(tc.status)
				_, _ = w.Write([]byte(`{"message":"nope"}`))
			}))
			defer srv.Close()
			ts := TwilioSender{AccountSID: "AC1", AuthToken: "tok", From: "+15550199999", BaseURL: srv.URL}
			err := ts.Send(context.Background(), Message{To: "+15550100000", Code: "123456"})
			if (err == nil) != tc.wantOK {
				t.Fatalf("err=%v", err)
			}
		})
	}
}

package as

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/glincker/theauth-go/v2/crypto"
	"github.com/glincker/theauth-go/v2/internal/models"
)

func TestVerifyClientSecretConcurrencyCap(t *testing.T) {
	hash, err := crypto.HashPassword("s3cret")
	if err != nil {
		t.Fatal(err)
	}
	newSvc := func(slots int) *Service {
		s := &Service{Cfg: Config{RateLimits: &RateLimits{SecretVerifyWait: time.Millisecond}}}
		if slots > 0 {
			s.verifySem = make(chan struct{}, slots)
		}
		return s
	}

	t.Run("a free slot verifies and is released", func(t *testing.T) {
		s := newSvc(1)
		for i := 0; i < 3; i++ {
			ok, err := s.verifyClientSecret(context.Background(), "s3cret", hash)
			if err != nil || !ok {
				t.Fatalf("attempt %d: ok=%v err=%v", i, ok, err)
			}
		}
		if len(s.verifySem) != 0 {
			t.Fatal("slot leaked")
		}
	})
	t.Run("a wrong secret still releases the slot", func(t *testing.T) {
		s := newSvc(1)
		if ok, _ := s.verifyClientSecret(context.Background(), "nope", hash); ok {
			t.Fatal("wrong secret accepted")
		}
		if len(s.verifySem) != 0 {
			t.Fatal("slot leaked")
		}
	})
	t.Run("a full cap sheds load instead of queueing forever", func(t *testing.T) {
		s := newSvc(1)
		s.verifySem <- struct{}{} // another verification is running
		_, err := s.verifyClientSecret(context.Background(), "s3cret", hash)
		if !errors.Is(err, models.ErrOAuthServerBusy) {
			t.Fatalf("err = %v, want ErrOAuthServerBusy", err)
		}
	})
	t.Run("a cancelled request gives up its wait", func(t *testing.T) {
		s := newSvc(1)
		s.Cfg.RateLimits.SecretVerifyWait = time.Hour
		s.verifySem <- struct{}{}
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		if _, err := s.verifyClientSecret(ctx, "s3cret", hash); !errors.Is(err, context.Canceled) {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("no cap configured verifies directly", func(t *testing.T) {
		s := newSvc(0)
		if ok, err := s.verifyClientSecret(context.Background(), "s3cret", hash); err != nil || !ok {
			t.Fatalf("ok=%v err=%v", ok, err)
		}
	})
}

func TestApplyRateLimitDefaults(t *testing.T) {
	cases := []struct {
		name string
		in   *RateLimits
		want RateLimits
	}{
		{"nil takes defaults", nil, RateLimits{PerIPPerMinute: DefaultPerIPPerMinute, PerClientPerMinute: DefaultPerClientPerMinute, SecretVerifyWait: DefaultSecretVerifyWait}},
		{"negative stays off", &RateLimits{PerIPPerMinute: -1, PerClientPerMinute: -1, MaxConcurrentSecretVerifications: -1},
			RateLimits{PerIPPerMinute: -1, PerClientPerMinute: -1, MaxConcurrentSecretVerifications: -1, SecretVerifyWait: DefaultSecretVerifyWait}},
		{"explicit values kept", &RateLimits{PerIPPerMinute: 7, PerClientPerMinute: 9, MaxConcurrentSecretVerifications: 3, SecretVerifyWait: time.Second},
			RateLimits{PerIPPerMinute: 7, PerClientPerMinute: 9, MaxConcurrentSecretVerifications: 3, SecretVerifyWait: time.Second}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := Config{RateLimits: tc.in}
			applyRateLimitDefaults(&cfg)
			got := *cfg.RateLimits
			if tc.want.MaxConcurrentSecretVerifications == 0 {
				if got.MaxConcurrentSecretVerifications < 2 || got.MaxConcurrentSecretVerifications > maxDefaultSecretVerifies {
					t.Fatalf("default cap %d out of range", got.MaxConcurrentSecretVerifications)
				}
				got.MaxConcurrentSecretVerifications = 0
			}
			if got != tc.want {
				t.Fatalf("got %+v want %+v", got, tc.want)
			}
		})
	}
}

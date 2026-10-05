package memory

import (
	"context"
	"testing"

	"github.com/glincker/theauth-go/v2"
	"github.com/glincker/theauth-go/v2/internal/ulid"
)

func TestAdvanceTOTPStep(t *testing.T) {
	s := New()
	ctx := context.Background()
	u1, u2 := ulid.New(), ulid.New()
	steps := []struct {
		user theauth.ULID
		step int64
		want bool
	}{
		{u1, 100, true},
		{u1, 100, false},
		{u1, 99, false},
		{u1, 101, true},
		{u2, 100, true},
	}
	for i, st := range steps {
		got, err := s.AdvanceTOTPStep(ctx, st.user, st.step)
		if err != nil || got != st.want {
			t.Fatalf("step %d: got %v err %v, want %v", i, got, err, st.want)
		}
	}
}

func TestCountUsers(t *testing.T) {
	s := New()
	ctx := context.Background()
	if n, _ := s.CountUsers(ctx); n != 0 {
		t.Fatalf("empty store count %d", n)
	}
	_, _ = s.CreateUser(ctx, theauth.User{ID: ulid.New(), Email: "a@b.c"})
	if n, _ := s.CountUsers(ctx); n != 1 {
		t.Fatalf("count %d", n)
	}
}

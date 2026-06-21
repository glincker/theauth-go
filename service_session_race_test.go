package theauth_test

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/glincker/theauth-go"
	"github.com/glincker/theauth-go/internal/ulid"
	"github.com/glincker/theauth-go/storage/memory"
)

func newRaceAuth(t *testing.T) (*theauth.TheAuth, theauth.Storage) {
	t.Helper()
	store := memory.New()
	a, err := theauth.New(theauth.Config{
		Storage:      store,
		BaseURL:      "http://localhost",
		SecureCookie: false,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(a.Close)
	return a, store
}

// TestSessionCreationRaceSameUser issues two concurrent session creations
// for the same user and asserts both succeed with distinct IDs. The
// in-memory adapter must not deadlock and must not produce a primary key
// collision.
func TestSessionCreationRaceSameUser(t *testing.T) {
	t.Parallel()
	a, store := newRaceAuth(t)
	ctx := context.Background()

	user := theauth.User{
		ID:        ulid.New(),
		Email:     "race@example.com",
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}
	if _, err := store.CreateUser(ctx, user); err != nil {
		t.Fatal(err)
	}

	var (
		t1, t2 string
		s1, s2 theauth.Session
		e1, e2 error
		wg     sync.WaitGroup
	)
	wg.Add(2)
	go func() {
		defer wg.Done()
		t1, s1, e1 = theauth.IssueSessionForTest(a, ctx, user, "ua", "ip")
	}()
	go func() {
		defer wg.Done()
		t2, s2, e2 = theauth.IssueSessionForTest(a, ctx, user, "ua", "ip")
	}()
	wg.Wait()

	if e1 != nil || e2 != nil {
		t.Fatalf("issueSession errors: e1=%v e2=%v", e1, e2)
	}
	if t1 == "" || t2 == "" {
		t.Fatalf("blank tokens: t1=%q t2=%q", t1, t2)
	}
	if t1 == t2 {
		t.Fatalf("tokens collided: %q", t1)
	}
	if s1.ID == s2.ID {
		t.Fatalf("session IDs collided: %s", s1.ID)
	}
}

// TestSessionLookupUnderWrites runs concurrent session creators against
// concurrent lookups. Lookups must never observe a zero-value or
// partially-initialized session struct.
func TestSessionLookupUnderWrites(t *testing.T) {
	t.Parallel()
	a, store := newRaceAuth(t)
	ctx := context.Background()

	const users = 100
	created := make([]theauth.User, users)
	tokens := make([]string, users)
	for i := 0; i < users; i++ {
		u := theauth.User{
			ID:        ulid.New(),
			Email:     "u" + ulid.New().String() + "@example.com",
			CreatedAt: time.Now(),
			UpdatedAt: time.Now(),
		}
		created[i], _ = store.CreateUser(ctx, u)
		tok, _, err := theauth.IssueSessionForTest(a, ctx, created[i], "", "")
		if err != nil {
			t.Fatal(err)
		}
		tokens[i] = tok
	}

	var wg sync.WaitGroup
	stop := make(chan struct{})

	// Writers: keep issuing new sessions.
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
					_, _, _ = theauth.IssueSessionForTest(a, ctx, created[i%users], "ua", "ip")
				}
			}
		}(i)
	}

	// Readers: validate the known tokens; must always find a fully
	// populated session.
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			for j := 0; j < 50; j++ {
				sess, user, err := theauth.ValidateSessionForTest(a, ctx, tokens[i%users])
				if err != nil {
					t.Errorf("validate err: %v", err)
					return
				}
				if sess == nil || user == nil {
					t.Errorf("nil sess or user")
					return
				}
				if sess.UserID != user.ID {
					t.Errorf("session userID mismatch")
					return
				}
			}
		}(i)
	}

	// Let the workers churn briefly then stop.
	time.Sleep(50 * time.Millisecond)
	close(stop)
	wg.Wait()
}

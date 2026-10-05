// Package bootstrap gates creation of the first user behind a one-time setup token.
package bootstrap

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"fmt"
	"log/slog"
	"sync"
	"sync/atomic"

	"github.com/glincker/theauth-go/v2/crypto"
	"github.com/glincker/theauth-go/v2/internal/models"
	"github.com/glincker/theauth-go/v2/internal/password"
	"github.com/glincker/theauth-go/v2/internal/throttle"
)

// Config closes public signup and gates creation of the first user
// behind a one-time setup token. The storage must implement UserCountStorage.
//
// While no user exists, password signup requires the token in the
// X-Setup-Token header or a "setupToken" body field. After the first user
// exists, signup is refused with CodeSignupClosed unless
// OpenSignupAfterFirstUser is set. Magic-link account creation follows the
// same rule but can never present a token, so the first admin must sign up
// with a password. Granting the new user an admin role is left to OnFirstUser.
type Config struct {
	// SetupToken is the operator-supplied token. When empty a random one is
	// generated at startup (if no user exists yet) and logged once.
	SetupToken string
	// OpenSignupAfterFirstUser reopens ordinary signup once the first user exists.
	OpenSignupAfterFirstUser bool
	// SuppressSetupTokenLog stops the generated token being logged; read it
	// with TheAuth.SetupToken instead.
	SuppressSetupTokenLog bool
	// OnFirstUser runs after the first user is created, for example to
	// grant the super admin role. Errors are logged and do not fail signup.
	OnFirstUser func(ctx context.Context, user *models.User) error
}

type Gate struct {
	counter   UserCounter
	tokenHash [sha256.Size]byte
	hasToken  bool
	open      bool
	onFirst   func(ctx context.Context, user *models.User) error
	limiter   *throttle.Limiter
	token     string

	mu       sync.Mutex
	hasUsers atomic.Bool
}

// UserCounter is the storage capability the gate needs.
type UserCounter interface {
	CountUsers(ctx context.Context) (int, error)
}

func New(cfg *Config, counter UserCounter, limiter *throttle.Limiter) (*Gate, error) {
	g := &Gate{counter: counter, open: cfg.OpenSignupAfterFirstUser, onFirst: cfg.OnFirstUser, limiter: limiter}
	n, err := counter.CountUsers(context.Background())
	if err != nil {
		return nil, fmt.Errorf("theauth: bootstrap: count users: %w", err)
	}
	if n > 0 {
		g.hasUsers.Store(true)
		return g, nil
	}
	tok := cfg.SetupToken
	if tok == "" {
		tok, err = crypto.NewToken()
		if err != nil {
			return nil, fmt.Errorf("theauth: bootstrap: generate setup token: %w", err)
		}
		if !cfg.SuppressSetupTokenLog {
			slog.Warn("theauth: first-run setup token (required to create the first admin)", "setup_token", tok)
		}
	}
	g.token = tok
	g.tokenHash = sha256.Sum256([]byte(tok))
	g.hasToken = true
	return g, nil
}

func (g *Gate) closedErr() error {
	if g.open {
		return nil
	}
	return models.NewError(models.CodeSignupClosed, "signup is closed", nil)
}

// Begin implements password.SignupGate and magiclink.SignupGate.
func (g *Gate) Begin(ctx context.Context) (func(*models.User), error) {
	noop := func(*models.User) {}
	if g.hasUsers.Load() {
		return noop, g.closedErr()
	}
	g.mu.Lock()
	n, err := g.counter.CountUsers(ctx)
	if err != nil {
		g.mu.Unlock()
		return nil, fmt.Errorf("theauth: bootstrap: count users: %w", err)
	}
	if n > 0 {
		g.hasUsers.Store(true)
		g.mu.Unlock()
		return noop, g.closedErr()
	}
	meta := password.SignupMetaFromContext(ctx)
	ident := "setup:" + meta.IP
	if g.limiter != nil {
		if terr := g.limiter.CheckLogin(ctx, meta.IP, ident); terr != nil {
			g.mu.Unlock()
			return nil, password.ThrottleError(terr)
		}
	}
	presented := sha256.Sum256([]byte(meta.SetupToken))
	if !g.hasToken || meta.SetupToken == "" || subtle.ConstantTimeCompare(presented[:], g.tokenHash[:]) != 1 {
		if g.limiter != nil {
			if rerr := g.limiter.RecordLoginFailure(ctx, meta.IP, ident); rerr != nil {
				slog.Warn("theauth: record setup token failure", "err", rerr.Error())
			}
		}
		g.mu.Unlock()
		return nil, models.NewError(models.CodeSetupTokenInvalid, "setup token required", nil)
	}
	return func(created *models.User) {
		defer g.mu.Unlock()
		if created == nil {
			return
		}
		g.hasUsers.Store(true)
		g.hasToken = false
		g.token = ""
		if g.onFirst != nil {
			if herr := g.onFirst(ctx, created); herr != nil {
				slog.Warn("theauth: bootstrap OnFirstUser failed", "user_id", created.ID.String(), "err", herr.Error())
			}
		}
	}, nil
}

// Token returns the pending setup token, or "" once the first user exists.
func (g *Gate) Token() string {
	if g == nil || g.hasUsers.Load() {
		return ""
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.token
}

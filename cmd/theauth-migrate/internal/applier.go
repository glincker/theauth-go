package internal

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/oklog/ulid/v2"

	theauth "github.com/glincker/theauth-go"
)

const batchSize = 500

// Storage is the subset of theauth.Storage the applier needs. Using a
// narrower interface makes the applier easier to test and keeps the
// dependency explicit.
type Storage interface {
	CreateUser(ctx context.Context, u theauth.User) (theauth.User, error)
	UserByEmail(ctx context.Context, email string) (*theauth.User, error)
	SetUserPassword(ctx context.Context, userID theauth.ULID, passwordHash string) error
	UpsertOAuthAccount(ctx context.Context, a theauth.OAuthAccount) (theauth.OAuthAccount, error)
}

// ApplyOptions controls behaviour of ApplyBundle.
type ApplyOptions struct {
	// DryRun performs validation and conflict detection only, no writes.
	DryRun bool
	// Out receives progress log lines. Defaults to io.Discard.
	Out io.Writer
}

// ApplyResult summarises the outcome of an apply run.
type ApplyResult struct {
	UsersInserted         int
	UsersDuplicate        int
	OAuthAccountsInserted int
	PasswordsSet          int
	// PasswordResets is the list of (email, source_id) pairs for users who
	// need a password-reset email. The caller should wire this to an email
	// service.
	PasswordResets []PasswordResetNeeded
	Errors         []string
}

// PasswordResetNeeded is emitted for every user that has RequiresPasswordReset
// set in the bundle.
type PasswordResetNeeded struct {
	Email    string
	SourceID string
}

// ApplyBundle writes b into st in batches. It is idempotent: users whose
// email already exists in storage are skipped (reported in Duplicate) rather
// than double-inserted. On any hard error the function returns early with a
// non-nil error; partial writes are noted in the result.
func ApplyBundle(ctx context.Context, st Storage, b *Bundle, opts ApplyOptions) (ApplyResult, error) {
	if opts.Out == nil {
		opts.Out = io.Discard
	}
	log := func(format string, args ...interface{}) {
		_, _ = fmt.Fprintf(opts.Out, format+"\n", args...)
	}

	vr := ValidateBundle(b)
	for _, w := range vr.Warnings {
		log("WARN %s", w)
	}
	if !vr.OK() {
		return ApplyResult{Errors: vr.Errors}, fmt.Errorf("bundle validation failed with %d error(s)", len(vr.Errors))
	}

	if opts.DryRun {
		log("DRY-RUN: validation passed (%d users, %d oauth, %d passwords)",
			len(b.Users), len(b.OAuthAccounts), len(b.Passwords))
		log("DRY-RUN: no writes performed")
		return ApplyResult{}, nil
	}

	// Build a lookup map: source_id -> theauth ULID so we can link oauth +
	// password rows after users are inserted.
	sourceToULID := make(map[string]theauth.ULID, len(b.Users))

	var result ApplyResult

	// ----- Insert users in batches -----
	for i := 0; i < len(b.Users); i += batchSize {
		end := i + batchSize
		if end > len(b.Users) {
			end = len(b.Users)
		}
		batch := b.Users[i:end]
		log("inserting users %d-%d of %d ...", i+1, end, len(b.Users))

		for _, ur := range batch {
			existing, err := st.UserByEmail(ctx, strings.ToLower(ur.Email))
			if err != nil && !errors.Is(err, theauth.ErrStorageNotFound) {
				return result, fmt.Errorf("UserByEmail(%q): %w", ur.Email, err)
			}
			if existing != nil {
				log("SKIP duplicate email %q (source_id=%s)", ur.Email, ur.SourceID)
				sourceToULID[ur.SourceID] = existing.ID
				result.UsersDuplicate++
				continue
			}

			now := time.Now().UTC()
			var emailVerifiedAt *time.Time
			if ur.EmailVerified {
				emailVerifiedAt = &now
			}
			u := theauth.User{
				ID:              newULID(),
				Email:           strings.ToLower(ur.Email),
				Name:            ur.Name,
				EmailVerifiedAt: emailVerifiedAt,
				CreatedAt:       ur.CreatedAt,
				UpdatedAt:       ur.UpdatedAt,
			}
			created, err := st.CreateUser(ctx, u)
			if err != nil {
				result.Errors = append(result.Errors, fmt.Sprintf("CreateUser(%q): %v", ur.Email, err))
				continue
			}
			sourceToULID[ur.SourceID] = created.ID
			result.UsersInserted++

			if ur.RequiresPasswordReset {
				result.PasswordResets = append(result.PasswordResets, PasswordResetNeeded{
					Email:    ur.Email,
					SourceID: ur.SourceID,
				})
			}
		}
	}

	// ----- Insert OAuth accounts -----
	for i, oa := range b.OAuthAccounts {
		uid, ok := sourceToULID[oa.SourceUserID]
		if !ok {
			log("SKIP oauth_account[%d]: source_user_id %q not mapped to a user", i, oa.SourceUserID)
			continue
		}
		row := theauth.OAuthAccount{
			ID:             newULID(),
			UserID:         uid,
			Provider:       oa.Provider,
			ProviderUserID: oa.ProviderUserID,
		}
		if _, err := st.UpsertOAuthAccount(ctx, row); err != nil {
			result.Errors = append(result.Errors, fmt.Sprintf("UpsertOAuthAccount(%s/%s): %v",
				oa.Provider, oa.ProviderUserID, err))
			continue
		}
		result.OAuthAccountsInserted++
	}

	// ----- Set passwords -----
	for i, pr := range b.Passwords {
		if pr.Hash == "" {
			continue
		}
		uid, ok := sourceToULID[pr.SourceUserID]
		if !ok {
			log("SKIP passwords[%d]: source_user_id %q not mapped to a user", i, pr.SourceUserID)
			continue
		}
		if err := st.SetUserPassword(ctx, uid, pr.Hash); err != nil {
			result.Errors = append(result.Errors, fmt.Sprintf("SetUserPassword(%s): %v", pr.SourceUserID, err))
			continue
		}
		result.PasswordsSet++
	}

	// ----- Emit password reset instructions -----
	if len(result.PasswordResets) > 0 {
		log("\n--- PASSWORD RESET REQUIRED ---")
		log("The following %d users need a password-reset email.", len(result.PasswordResets))
		log("Wire these to your email service or call POST /auth/email-password/forgot for each.")
		for _, pr := range result.PasswordResets {
			log("  email=%s source_id=%s", pr.Email, pr.SourceID)
		}
		log("--- END PASSWORD RESET LIST ---\n")
	}

	log("apply complete: inserted=%d duplicate=%d oauth=%d passwords=%d errors=%d",
		result.UsersInserted, result.UsersDuplicate,
		result.OAuthAccountsInserted, result.PasswordsSet, len(result.Errors))

	if len(result.Errors) > 0 {
		return result, fmt.Errorf("%d error(s) during apply; see result.Errors", len(result.Errors))
	}
	return result, nil
}

// newULID generates a fresh ULID using crypto/rand.
func newULID() theauth.ULID {
	return ulid.MustNew(ulid.Timestamp(time.Now()), rand.Reader)
}

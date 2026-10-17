package models

import (
	"context"
	"time"
)

type authRecordKey struct{}

// AuthRecord is the authentication record a sign-in flow asks the session
// service to store on the session it is about to mint.
type AuthRecord struct {
	Methods []string
	// At is the AuthTime to record; zero means the moment of issue.
	At time.Time
}

// WithAuthMethods returns a context that makes the session service record
// methods (RFC 8176 values, see the AMR constants) and an AuthTime of now on
// the session created from it. Sign-in services wrap the context just before
// they mint a session; contexts without it create sessions with no record.
func WithAuthMethods(ctx context.Context, methods ...string) context.Context {
	return WithAuthRecord(ctx, time.Time{}, methods...)
}

// WithAuthRecord is WithAuthMethods with an explicit AuthTime, used when a
// session is replaced and must keep the original authentication time.
func WithAuthRecord(ctx context.Context, at time.Time, methods ...string) context.Context {
	return context.WithValue(ctx, authRecordKey{}, AuthRecord{Methods: MergeAuthMethods(nil, methods...), At: at})
}

// AuthRecordFrom returns the record attached by WithAuthRecord.
func AuthRecordFrom(ctx context.Context) AuthRecord {
	r, _ := ctx.Value(authRecordKey{}).(AuthRecord)
	return r
}

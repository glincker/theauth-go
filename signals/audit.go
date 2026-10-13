package signals

import (
	"context"
	"time"
)

// SubjectFunc builds the subject identifier for a local user id.
type SubjectFunc func(ctx context.Context, userID string) Subject

// IssSubSubjects returns a SubjectFunc that emits iss_sub subjects with the
// given issuer and the user id as sub.
func IssSubSubjects(issuer string) SubjectFunc {
	return func(_ context.Context, userID string) Subject { return IssSub(issuer, userID) }
}

// EventsFromAudit maps one theauth audit action to zero or more SSF events.
// userID is the affected user when known (empty otherwise). It returns nil
// for actions that have no SSF counterpart.
//
// Mapping:
//
//	session.revoked / user.logout, session target   -> CAEP session-revoked
//	session.revoked, user target (scope all)        -> RISC sessions-revoked
//	session.revoked_others, user target             -> CAEP session-revoked
//	password.changed                                -> CAEP credential-change (password, update)
//	passkey.registered / passkey.deleted            -> CAEP credential-change (fido2-platform, create / delete)
//	totp.enrolled / totp.disabled                   -> CAEP credential-change (app, create / delete)
//	account.disabled / account.enabled              -> RISC account-disabled / account-enabled
func EventsFromAudit(ctx context.Context, subj SubjectFunc, action, targetType, targetID string, metadata map[string]any, userID string, at time.Time) []Event {
	if subj == nil {
		return nil
	}
	user := func() (Subject, bool) {
		id := userID
		if targetType == "user" && targetID != "" {
			id = targetID
		}
		if id == "" {
			return Subject{}, false
		}
		return subj(ctx, id), true
	}
	switch action {
	case "session.revoked", "user.logout":
		if targetType == "user" {
			if s, ok := user(); ok {
				return []Event{NewSessionsRevoked(s)}
			}
			return nil
		}
		members := map[string]Subject{}
		if targetID != "" {
			members["session"] = Opaque(targetID)
		}
		if s, ok := user(); ok {
			members["user"] = s
		}
		if len(members) == 0 {
			return nil
		}
		var s Subject
		if len(members) == 1 && members["user"].Format != "" {
			s = members["user"]
		} else {
			s = ComplexSubject(members)
		}
		return []Event{NewSessionRevoked(s, at, "user", "")}
	case "session.revoked_others":
		if s, ok := user(); ok {
			return []Event{NewSessionRevoked(s, at, "user", "")}
		}
	case "password.changed":
		if s, ok := user(); ok {
			return []Event{NewCredentialChange(s, at, "password", "update")}
		}
	case "passkey.registered":
		if s, ok := user(); ok {
			return []Event{NewCredentialChange(s, at, "fido2-platform", "create")}
		}
	case "passkey.deleted":
		if s, ok := user(); ok {
			return []Event{NewCredentialChange(s, at, "fido2-platform", "delete")}
		}
	case "totp.enrolled":
		if s, ok := user(); ok {
			return []Event{NewCredentialChange(s, at, "app", "create")}
		}
	case "totp.disabled":
		if s, ok := user(); ok {
			return []Event{NewCredentialChange(s, at, "app", "delete")}
		}
	case "account.disabled":
		if s, ok := user(); ok {
			return []Event{NewAccountDisabled(s, "")}
		}
	case "account.enabled":
		if s, ok := user(); ok {
			return []Event{NewAccountEnabled(s)}
		}
	}
	return nil
}

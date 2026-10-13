package signals

import "time"

// CAEP event type URIs (OpenID CAEP 1.0).
const (
	EventSessionRevoked         = "https://schemas.openid.net/secevent/caep/event-type/session-revoked"
	EventTokenClaimsChange      = "https://schemas.openid.net/secevent/caep/event-type/token-claims-change"
	EventCredentialChange       = "https://schemas.openid.net/secevent/caep/event-type/credential-change"
	EventAssuranceLevelChange   = "https://schemas.openid.net/secevent/caep/event-type/assurance-level-change"
	EventDeviceComplianceChange = "https://schemas.openid.net/secevent/caep/event-type/device-compliance-change"
)

// RISC event type URIs (OpenID RISC Profile 1.0).
const (
	EventAccountDisabled      = "https://schemas.openid.net/secevent/risc/event-type/account-disabled"
	EventAccountEnabled       = "https://schemas.openid.net/secevent/risc/event-type/account-enabled"
	EventCredentialCompromise = "https://schemas.openid.net/secevent/risc/event-type/credential-compromise"
	EventSessionsRevoked      = "https://schemas.openid.net/secevent/risc/event-type/sessions-revoked"
)

// SSF stream event type URIs (SSF 1.0 section 8.1.4).
const (
	EventVerification  = "https://schemas.openid.net/secevent/ssf/event-type/verification"
	EventStreamUpdated = "https://schemas.openid.net/secevent/ssf/event-type/stream-updated"
)

// SupportedEvents lists every event type the transmitter can carry.
func SupportedEvents() []string {
	return []string{
		EventSessionRevoked, EventTokenClaimsChange, EventCredentialChange,
		EventAssuranceLevelChange, EventDeviceComplianceChange,
		EventAccountDisabled, EventAccountEnabled, EventCredentialCompromise, EventSessionsRevoked,
	}
}

func isSupported(t string) bool {
	for _, s := range SupportedEvents() {
		if s == t {
			return true
		}
	}
	return false
}

func withTime(props map[string]any, at time.Time) map[string]any {
	if props == nil {
		props = map[string]any{}
	}
	if _, ok := props["event_timestamp"]; !ok && !at.IsZero() {
		props["event_timestamp"] = at.Unix()
	}
	return props
}

// NewSessionRevoked builds a CAEP session-revoked event.
func NewSessionRevoked(subject Subject, at time.Time, initiatingEntity, reasonAdmin string) Event {
	p := map[string]any{}
	if initiatingEntity != "" {
		p["initiating_entity"] = initiatingEntity
	}
	if reasonAdmin != "" {
		p["reason_admin"] = map[string]string{"en": reasonAdmin}
	}
	return Event{Type: EventSessionRevoked, Subject: subject, Properties: withTime(p, at)}
}

// NewCredentialChange builds a CAEP credential-change event. changeType is
// create, revoke, update or delete; credentialType is for example password,
// fido2-platform or app.
func NewCredentialChange(subject Subject, at time.Time, credentialType, changeType string) Event {
	return Event{Type: EventCredentialChange, Subject: subject, Properties: withTime(map[string]any{
		"credential_type": credentialType, "change_type": changeType,
	}, at)}
}

// NewTokenClaimsChange builds a CAEP token-claims-change event.
func NewTokenClaimsChange(subject Subject, at time.Time, claims map[string]any) Event {
	return Event{Type: EventTokenClaimsChange, Subject: subject, Properties: withTime(map[string]any{"claims": claims}, at)}
}

// NewAssuranceLevelChange builds a CAEP assurance-level-change event.
// direction is increase or decrease.
func NewAssuranceLevelChange(subject Subject, at time.Time, previous, current, direction string) Event {
	return Event{Type: EventAssuranceLevelChange, Subject: subject, Properties: withTime(map[string]any{
		"current_level": current, "previous_level": previous, "change_direction": direction,
	}, at)}
}

// NewDeviceComplianceChange builds a CAEP device-compliance-change event.
// Statuses are compliant or not-compliant.
func NewDeviceComplianceChange(subject Subject, at time.Time, previous, current string) Event {
	return Event{Type: EventDeviceComplianceChange, Subject: subject, Properties: withTime(map[string]any{
		"previous_status": previous, "current_status": current,
	}, at)}
}

// NewAccountDisabled builds a RISC account-disabled event. reason is
// hijacking, bulk-account or empty.
func NewAccountDisabled(subject Subject, reason string) Event {
	p := map[string]any{}
	if reason != "" {
		p["reason"] = reason
	}
	return Event{Type: EventAccountDisabled, Subject: subject, Properties: p}
}

// NewAccountEnabled builds a RISC account-enabled event.
func NewAccountEnabled(subject Subject) Event {
	return Event{Type: EventAccountEnabled, Subject: subject}
}

// NewCredentialCompromise builds a RISC credential-compromise event.
func NewCredentialCompromise(subject Subject, at time.Time, credentialType, reasonAdmin string) Event {
	p := map[string]any{"credential_type": credentialType}
	if reasonAdmin != "" {
		p["reason_admin"] = map[string]string{"en": reasonAdmin}
	}
	return Event{Type: EventCredentialCompromise, Subject: subject, Properties: withTime(p, at)}
}

// NewSessionsRevoked builds a RISC sessions-revoked event.
func NewSessionsRevoked(subject Subject) Event {
	return Event{Type: EventSessionsRevoked, Subject: subject}
}

package visitorsignal

import "errors"

// Mode is the collection mode of a payload or a site setting.
type Mode string

// Supported modes. ModeOff is a site setting only and never appears in a payload.
const (
	ModeOff             Mode = "off"
	ModeAnalytics       Mode = "analytics"
	ModeFraudPrevention Mode = "fraud_prevention"
)

// Valid reports whether m can appear in a payload.
func (m Mode) Valid() bool { return m == ModeAnalytics || m == ModeFraudPrevention }

// Status is the collector outcome carried in a payload.
type Status string

// Payload statuses.
const (
	StatusOK         Status = "ok"
	StatusSuppressed Status = "suppressed"
	StatusPartial    Status = "partial"
)

// SuppressedReason says why a collector sent no components.
type SuppressedReason string

// Suppression reasons from schema v1.
const (
	ReasonConsentDenied     SuppressedReason = "consent_denied"
	ReasonConsentUnknown    SuppressedReason = "consent_unknown"
	ReasonDNT               SuppressedReason = "dnt"
	ReasonGPC               SuppressedReason = "gpc"
	ReasonRouteNotProtected SuppressedReason = "route_not_protected"
)

// ConsentState is the visitor consent input. Unknown counts as denied.
type ConsentState string

// Consent states.
const (
	ConsentGranted ConsentState = "granted"
	ConsentDenied  ConsentState = "denied"
	ConsentUnknown ConsentState = "unknown"
)

// LawfulBasis is an integrator assertion that replaces consent for protected routes.
type LawfulBasis string

// LawfulBasisLegitimateInterestSecurity is the only basis the contract defines.
const LawfulBasisLegitimateInterestSecurity LawfulBasis = "legitimate_interest_security"

// SchemaVersion is the only payload major version this package accepts.
const SchemaVersion = 1

// Payload mirrors schema/v1.json.
type Payload struct {
	V                int              `json:"v"`
	Mode             Mode             `json:"mode"`
	Status           Status           `json:"status"`
	SuppressedReason SuppressedReason `json:"suppressedReason,omitempty"`
	TS               int64            `json:"ts"`
	Nonce            string           `json:"nonce"`
	Challenge        string           `json:"challenge,omitempty"`
	Components       Components       `json:"components"`
	Unavailable      []string         `json:"unavailable,omitempty"`
	Flags            Flags            `json:"flags"`
	CollectMs        int              `json:"collectMs,omitempty"`
}

// Components are the coarse attributes. A nil field is absent, never null.
type Components struct {
	TZ            *string  `json:"tz,omitempty"`
	TZOffsetMin   *int     `json:"tzOffsetMin,omitempty"`
	Lang          *string  `json:"lang,omitempty"`
	LangCount     *int     `json:"langCount,omitempty"`
	Platform      *string  `json:"platform,omitempty"`
	UABrand       *string  `json:"uaBrand,omitempty"`
	UAMajor       *int     `json:"uaMajor,omitempty"`
	Mobile        *bool    `json:"mobile,omitempty"`
	ScreenBucket  *string  `json:"screenBucket,omitempty"`
	ColorDepth    *int     `json:"colorDepth,omitempty"`
	TouchPoints   *int     `json:"touchPoints,omitempty"`
	Cores         *int     `json:"cores,omitempty"`
	MemoryGB      *float64 `json:"memoryGb,omitempty"`
	ReducedMotion *bool    `json:"reducedMotion,omitempty"`
	ColorScheme   *string  `json:"colorScheme,omitempty"`
	Caps          *uint32  `json:"caps,omitempty"`
	RenderHash    *string  `json:"renderHash,omitempty"`
}

// Count returns how many components are present.
func (c Components) Count() int {
	n := 0
	for _, present := range []bool{
		c.TZ != nil, c.TZOffsetMin != nil, c.Lang != nil, c.LangCount != nil,
		c.Platform != nil, c.UABrand != nil, c.UAMajor != nil, c.Mobile != nil,
		c.ScreenBucket != nil, c.ColorDepth != nil, c.TouchPoints != nil,
		c.Cores != nil, c.MemoryGB != nil, c.ReducedMotion != nil,
		c.ColorScheme != nil, c.Caps != nil, c.RenderHash != nil,
	} {
		if present {
			n++
		}
	}
	return n
}

// Flags are the automation and privacy hints reported by the collector.
type Flags struct {
	ProtectedBrowser  bool `json:"protectedBrowser"`
	Webdriver         bool `json:"webdriver"`
	HeadlessHint      bool `json:"headlessHint"`
	Inconsistent      bool `json:"inconsistent"`
	AutomationGlobals int  `json:"automationGlobals,omitempty"`
	NoInputObserved   bool `json:"noInputObserved,omitempty"`
	DNT               bool `json:"dnt,omitempty"`
	GPC               bool `json:"gpc,omitempty"`
}

// ErrorCode is a typed error code from the contract.
type ErrorCode string

// Error codes from SPEC.md.
const (
	CodeUnsupportedVersion ErrorCode = "unsupported_version"
	CodeSchemaInvalid      ErrorCode = "schema_invalid"
	CodeChallengeInvalid   ErrorCode = "challenge_invalid"
	CodeChallengeExpired   ErrorCode = "challenge_expired"
	CodeNonceReplayed      ErrorCode = "nonce_replayed"
	CodeModeNotAllowed     ErrorCode = "mode_not_allowed"
	CodeConsentRequired    ErrorCode = "consent_required"
	CodeRateLimited        ErrorCode = "rate_limited"
)

// Error is a contract error. Match it with errors.Is(err, &Error{Code: c})
// or read the code with CodeOf.
type Error struct {
	Code   ErrorCode
	Detail string
}

func (e *Error) Error() string {
	if e.Detail == "" {
		return "visitorsignal: " + string(e.Code)
	}
	return "visitorsignal: " + string(e.Code) + ": " + e.Detail
}

// Is matches any *Error with the same code, so detail text never affects matching.
func (e *Error) Is(target error) bool {
	t, ok := target.(*Error)
	return ok && t.Code == e.Code
}

// CodeOf returns the contract code carried by err, or "" when there is none.
func CodeOf(err error) ErrorCode {
	var e *Error
	if errors.As(err, &e) {
		return e.Code
	}
	return ""
}

func newError(code ErrorCode, detail string) *Error {
	return &Error{Code: code, Detail: detail}
}

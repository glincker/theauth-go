package doctor

import (
	"fmt"
	"strings"
	"time"
)

// Doctor finding IDs. They are stable and appear in docs/SECURITY-DOCTOR.md.
const (
	DoctorSignupOpen        = "signup.open_no_allowlist"
	DoctorBootstrapOff      = "bootstrap.gate_off_no_users"
	DoctorTrustedProxies    = "network.trusted_proxies_empty"
	DoctorSecureCookie      = "cookie.insecure_http"
	DoctorCSRFDisabled      = "csrf.disabled"
	DoctorThrottleDisabled  = "throttle.disabled"
	DoctorThrottleLax       = "throttle.lax"
	DoctorPasswordMinLength = "password.min_length_low"
	DoctorPasswordNoBreach  = "password.no_breach_checker"
	DoctorAdminNoTOTP       = "mfa.admin_without_totp"
	DoctorNoSecondFactor    = "mfa.none_enabled"
	DoctorSessionTTLLong    = "session.ttl_long"
	DoctorSessionNoIdle     = "session.no_idle_timeout"
	DoctorTokenNoExpiry     = "token.no_expiry"
	DoctorTokenLongExpiry   = "token.expiry_beyond_year"
	DoctorTokenRoot         = "token.root_ability"
	DoctorAgentTokenLong    = "token.agent_beyond_24h"
	DoctorTokensUnpruned    = "token.expired_unpruned"
	DoctorSessionsUnpruned  = "session.expired_unpruned"
	DoctorEncryptionKey     = "crypto.encryption_key_missing"
	DoctorAuditSink         = "audit.no_sink"
	DoctorWebAuthnRPID      = "webauthn.rpid_mismatch"
	DoctorRedirectAllowList = "redirect.allowlist_empty"
)

// DoctorFindingIDs lists every finding ID a check can emit.
func DoctorFindingIDs() []string {
	return []string{
		DoctorSignupOpen, DoctorBootstrapOff, DoctorTrustedProxies, DoctorSecureCookie,
		DoctorCSRFDisabled, DoctorThrottleDisabled, DoctorThrottleLax, DoctorPasswordMinLength,
		DoctorPasswordNoBreach, DoctorAdminNoTOTP, DoctorNoSecondFactor, DoctorSessionTTLLong,
		DoctorSessionNoIdle, DoctorTokenNoExpiry, DoctorTokenLongExpiry, DoctorTokenRoot,
		DoctorAgentTokenLong, DoctorTokensUnpruned, DoctorSessionsUnpruned, DoctorEncryptionKey,
		DoctorAuditSink, DoctorWebAuthnRPID, DoctorRedirectAllowList,
	}
}

var doctorChecks = []func(Input) []Finding{
	checkSignupOpen, checkBootstrap, checkTrustedProxies, checkSecureCookie, checkCSRF,
	checkThrottle, checkPasswordPolicy, checkMFA, checkSessionLifetime, checkTokens,
	checkUnpruned, checkEncryptionKey, checkAudit, checkWebAuthnRPID, checkRedirects,
}

func checkSignupOpen(in Input) []Finding {
	passwordOpen := !in.BootstrapOn || in.BootstrapOpen
	oauthOpen := in.HasProviders && in.OAuthSignupOpen
	if !passwordOpen && !oauthOpen {
		return nil
	}
	var where []string
	if passwordOpen {
		where = append(where, "password and magic-link signup")
	}
	if oauthOpen {
		where = append(where, "OAuth signup")
	}
	return []Finding{fnd(DoctorSignupOpen, SeverityMedium,
		"Public signup is open with no domain allow-list",
		"Anyone can create an account through "+strings.Join(where, " and ")+".",
		"Set Config.Bootstrap to close signup, or set OAuthConfig.Signup to allowed_domains or invite.")}
}

func checkBootstrap(in Input) []Finding {
	if in.BootstrapOn || in.UserCount != 0 {
		return nil
	}
	return []Finding{fnd(DoctorBootstrapOff, SeverityCritical,
		"No users exist and the bootstrap gate is off",
		"The first account to sign up wins. On a public host that is whoever arrives first.",
		"Set Config.Bootstrap so the first admin needs a one-time setup token.")}
}

func checkTrustedProxies(in Input) []Finding {
	if in.TrustedProxies > 0 || (in.RateLimitPerIP <= 0 && in.ThrottleDisabled) {
		return nil
	}
	return []Finding{fnd(DoctorTrustedProxies, SeverityMedium,
		"TrustedProxies is empty while IP rate limiting is on",
		"Behind a reverse proxy every client shares one bucket, or a spoofed forwarding header picks the bucket.",
		"List your proxy CIDRs in Config.TrustedProxies. Leave it empty only when exposed directly.")}
}

func checkSecureCookie(in Input) []Finding {
	host, https := baseHost(in.BaseURL)
	if in.SecureCookie || https || isLocalHost(host) {
		return nil
	}
	return []Finding{fnd(DoctorSecureCookie, SeverityHigh,
		"Session cookie is not Secure and BaseURL is plain http",
		"Cookies can travel over cleartext connections to "+host+".",
		"Serve over https and set Config.SecureCookie to true.")}
}

func checkCSRF(in Input) []Finding {
	if !in.CSRFDisabled {
		return nil
	}
	return []Finding{fnd(DoctorCSRFDisabled, SeverityHigh,
		"CSRF protection is disabled",
		"Cookie-authenticated state-changing requests are not origin checked.",
		"Remove Config.DisableCSRFProtection and list real origins in Config.TrustedOrigins.")}
}

func checkThrottle(in Input) []Finding {
	if in.ThrottleDisabled {
		return []Finding{fnd(DoctorThrottleDisabled, SeverityHigh,
			"Login throttle is disabled",
			"Password and MFA guessing is not slowed down or locked out.",
			"Remove LoginThrottle.Disabled or supply your own limiter in front of the login routes.")}
	}
	var lax []string
	if in.GraceFailures > 20 {
		lax = append(lax, fmt.Sprintf("GraceFailures=%d", in.GraceFailures))
	}
	if in.UserMaxFailures > 50 {
		lax = append(lax, fmt.Sprintf("UserMaxFailures=%d", in.UserMaxFailures))
	}
	if in.MFAMaxFailures > 20 {
		lax = append(lax, fmt.Sprintf("MFAMaxFailures=%d", in.MFAMaxFailures))
	}
	if len(lax) == 0 {
		return nil
	}
	return []Finding{fnd(DoctorThrottleLax, SeverityMedium,
		"Login throttle thresholds are very lax",
		"Thresholds allow extensive guessing before any lockout: "+strings.Join(lax, ", ")+".",
		"Use the defaults (3, 10, 5) or stricter.")}
}

func checkPasswordPolicy(in Input) []Finding {
	var out []Finding
	if in.PasswordMinLength < 12 {
		out = append(out, fnd(DoctorPasswordMinLength, SeverityMedium,
			"Minimum password length is below 12",
			fmt.Sprintf("PasswordPolicy.MinLength is %d.", in.PasswordMinLength),
			"Set PasswordPolicy.MinLength to 12 or more."))
	}
	if !in.HasBreachChecker {
		out = append(out, fnd(DoctorPasswordNoBreach, SeverityInfo,
			"No breached-password checker configured",
			"Passwords found in public breach corpora are accepted.",
			"Set PasswordPolicy.BreachChecker, for example the HIBP checker."))
	}
	return out
}

func checkMFA(in Input) []Finding {
	var out []Finding
	if !in.TOTPEnabled && !in.WebAuthnEnabled {
		out = append(out, fnd(DoctorNoSecondFactor, SeverityMedium,
			"No second factor is enabled",
			"Neither TOTP nor passkeys are configured, so accounts rely on one factor.",
			"Enable Config.TOTP or Config.WebAuthn."))
	}
	if in.AdminsWithoutMF > 0 {
		out = append(out, fnd(DoctorAdminNoTOTP, SeverityHigh,
			"Administrators without TOTP",
			fmt.Sprintf("%d of %d admin accounts have no confirmed TOTP secret.", in.AdminsWithoutMF, in.AdminCount),
			"Require admins to enroll TOTP or a passkey."))
	}
	return out
}

func checkSessionLifetime(in Input) []Finding {
	var out []Finding
	if in.SessionTTL > 30*24*time.Hour {
		out = append(out, fnd(DoctorSessionTTLLong, SeverityMedium,
			"Session absolute lifetime exceeds 30 days",
			fmt.Sprintf("SessionTTL is %s.", in.SessionTTL),
			"Lower Config.SessionTTL to 30 days or less."))
	}
	if in.IdleTimeout <= 0 {
		out = append(out, fnd(DoctorSessionNoIdle, SeverityLow,
			"No session idle timeout",
			"A stolen but unused session stays valid until its absolute expiry.",
			"Set Config.SessionIdleTimeout (needs SessionManagementStorage)."))
	}
	return out
}

func checkTokens(in Input) []Finding {
	if !in.TokensKnown {
		return nil
	}
	var out []Finding
	if in.TokensNoExpiry > 0 {
		out = append(out, fnd(DoctorTokenNoExpiry, SeverityHigh,
			"API tokens without an expiry",
			plural(in.TokensNoExpiry, "live token")+" never expire.",
			"Rotate them with an expiry and set APITokensConfig.MaxTTL."))
	}
	if in.TokensBeyondYear > 0 {
		out = append(out, fnd(DoctorTokenLongExpiry, SeverityMedium,
			"API tokens valid for more than a year",
			plural(in.TokensBeyondYear, "live token")+" outlive a year.",
			"Lower APITokensConfig.MaxTTL and rotate the tokens."))
	}
	if in.TokensRoot > 0 {
		out = append(out, fnd(DoctorTokenRoot, SeverityHigh,
			"API tokens holding the root ability",
			plural(in.TokensRoot, "live token")+" imply every ability.",
			"Replace root tokens with narrowly scoped abilities."))
	}
	if in.AgentTokensLong > 0 {
		out = append(out, fnd(DoctorAgentTokenLong, SeverityMedium,
			"Agent tokens valid for more than 24 hours",
			plural(in.AgentTokensLong, "live agent token")+" outlive a day.",
			"Set APITokensConfig.AgentMaxTTL to 24h or less."))
	}
	return out
}

func checkUnpruned(in Input) []Finding {
	var out []Finding
	if in.TokensExpired > 0 {
		out = append(out, fnd(DoctorTokensUnpruned, SeverityInfo,
			"Expired API tokens are still stored",
			plural(in.TokensExpired, "expired token")+" remain in storage.",
			"Revoke or delete expired tokens on a schedule."))
	}
	if in.SessionsExpired > 0 {
		out = append(out, fnd(DoctorSessionsUnpruned, SeverityInfo,
			"Expired sessions are still stored",
			plural(in.SessionsExpired, "expired session")+" remain in storage.",
			"Delete expired sessions on a schedule."))
	}
	return out
}

func checkEncryptionKey(in Input) []Finding {
	if in.EncryptionKeyLen == 32 {
		return nil
	}
	sev := SeverityLow
	if in.EncryptionNeeded {
		sev = SeverityHigh
	}
	return []Finding{fnd(DoctorEncryptionKey, sev,
		"EncryptionKey is missing or the wrong length",
		fmt.Sprintf("Config.EncryptionKey is %d bytes, 32 are required for OAuth tokens and TOTP secrets at rest.", in.EncryptionKeyLen),
		"Set Config.EncryptionKey to 32 random bytes from a secret store.")}
}

func checkAudit(in Input) []Finding {
	if in.AuditConfigured && in.AuditSinkCount > 0 {
		return nil
	}
	detail := "Config.Audit is not set, so security events are not recorded."
	if in.AuditConfigured {
		detail = "Audit events are stored locally only, with no external sink for tamper-resistant retention."
	}
	return []Finding{fnd(DoctorAuditSink, SeverityLow,
		"Audit sink is not configured", detail,
		"Set Config.Audit with at least one AuditSink.")}
}

func checkWebAuthnRPID(in Input) []Finding {
	if !in.WebAuthnConfigured {
		return nil
	}
	host, _ := baseHost(in.BaseURL)
	if host == "" || isLocalHost(host) && in.WebAuthnRPID == host {
		return nil
	}
	rp := strings.ToLower(in.WebAuthnRPID)
	if host == rp || strings.HasSuffix(host, "."+rp) {
		return nil
	}
	return []Finding{fnd(DoctorWebAuthnRPID, SeverityHigh,
		"WebAuthn RP ID does not match BaseURL host",
		fmt.Sprintf("RPID %q is not the host %q or a parent domain of it, so passkeys will fail.", in.WebAuthnRPID, host),
		"Set WebAuthnConfig.RPID to the BaseURL host or its registrable parent.")}
}

func checkRedirects(in Input) []Finding {
	if !in.HasProviders && !in.HasSAML || in.OAuthReturnTo > 0 {
		return nil
	}
	return []Finding{fnd(DoctorRedirectAllowList, SeverityInfo,
		"No post-login redirect allow-list",
		"OAuthConfig.AllowedReturnTo is empty, so every login lands on PostLoginRedirect and return_to is ignored.",
		"List permitted destinations in OAuthConfig.AllowedReturnTo if you need return_to support.")}
}

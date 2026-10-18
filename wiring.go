package theauth

import (
	"context"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"log/slog"
	"strconv"
	"strings"
	"time"

	"github.com/glincker/theauth-go/v2/internal/bootstrap"

	"github.com/glincker/theauth-go/v2/crypto"
	"github.com/glincker/theauth-go/v2/email"
	"github.com/glincker/theauth-go/v2/internal/agent"
	internalas "github.com/glincker/theauth-go/v2/internal/as"
	internalaudit "github.com/glincker/theauth-go/v2/internal/audit"
	"github.com/glincker/theauth-go/v2/internal/delegation"
	"github.com/glincker/theauth-go/v2/internal/httpsec"
	"github.com/glincker/theauth-go/v2/internal/identitylink"
	"github.com/glincker/theauth-go/v2/internal/magiclink"
	"github.com/glincker/theauth-go/v2/internal/models"
	internaloauth "github.com/glincker/theauth-go/v2/internal/oauth"
	"github.com/glincker/theauth-go/v2/internal/organizations"
	"github.com/glincker/theauth-go/v2/internal/password"
	"github.com/glincker/theauth-go/v2/internal/pathprefix"
	"github.com/glincker/theauth-go/v2/internal/rbac"
	internalsaml "github.com/glincker/theauth-go/v2/internal/saml"
	internalscim "github.com/glincker/theauth-go/v2/internal/scim"
	"github.com/glincker/theauth-go/v2/internal/session"
	internaltotp "github.com/glincker/theauth-go/v2/internal/totp"
	internalwebauthn "github.com/glincker/theauth-go/v2/internal/webauthn"
)

// wiring.go holds the config translation helpers (xxxConfigFromRoot) and the wiring steps called from New.

// samlParsed is the pre-parsed SAML keypair, bundled so New and wireServices pass one value.
type samlParsed struct {
	cert *x509.Certificate
	key  *rsa.PrivateKey
}

// applyConfigDefaults fills zero-value Config fields with library defaults. It must run before validation.
func applyConfigDefaults(cfg *Config) {
	applySessionDefaults(cfg)
	if cfg.SessionTTL == 0 {
		cfg.SessionTTL = 24 * time.Hour
	}
	if cfg.MagicLinkTTL == 0 {
		cfg.MagicLinkTTL = 15 * time.Minute
	}
	if cfg.CookieName == "" {
		cfg.CookieName = "theauth_session"
	}
	if cfg.EmailSender == nil {
		cfg.EmailSender = email.Noop{}
	}
	if cfg.RateLimitPerIP <= 0 {
		cfg.RateLimitPerIP = 5
	}
	if cfg.RateLimitPerEmail <= 0 {
		cfg.RateLimitPerEmail = 3
	}
	if cfg.PostLoginRedirect == "" {
		cfg.PostLoginRedirect = "/"
	}
	if cfg.WebAuthn != nil && cfg.WebAuthn.ChallengeTTL == 0 {
		cfg.WebAuthn.ChallengeTTL = 5 * time.Minute
	}
	if cfg.TOTP != nil && cfg.TOTP.RecoveryCodeCount == 0 {
		cfg.TOTP.RecoveryCodeCount = 10
	}
	if cfg.SAML != nil {
		if cfg.SAML.AuthnRequestTTL == 0 {
			cfg.SAML.AuthnRequestTTL = 10 * time.Minute
		}
		if cfg.SAML.ClockSkew == 0 {
			cfg.SAML.ClockSkew = 30 * time.Second
		}
	}
	if cfg.SCIM != nil && cfg.SCIM.MaxPageSize == 0 {
		cfg.SCIM.MaxPageSize = 200
	}
}

// validateConfig checks operator-supplied fields that defaults cannot cover. It returns the parsed
// providers, the SAML keypair (set only when SAML is configured) and the pre-hashed DCR tokens.
func validateConfig(cfg *Config) (providers map[string]Provider, sp samlParsed, dcrTokenHashes [][32]byte, err error) {
	if err := selectStorage(cfg); err != nil {
		return nil, samlParsed{}, nil, err
	}
	if cfg.BaseURL == "" {
		return nil, samlParsed{}, nil, errors.New("theauth: Config.BaseURL is required")
	}

	if err := pathprefix.Validate(cfg.PathPrefix); err != nil {
		return nil, samlParsed{}, nil, errors.New("theauth: Config.PathPrefix " + strconv.Quote(cfg.PathPrefix) + ": " + err.Error())
	}

	if err := applyCookiesConfig(cfg); err != nil {
		return nil, samlParsed{}, nil, err
	}

	// SecureCookie false is a security warning (security audit M3).
	if !cfg.SecureCookie && !cfg.SuppressSecureCookieWarning && !strings.HasPrefix(strings.ToLower(cfg.BaseURL), "https://") {
		slog.Warn("SecureCookie: false with a non-https BaseURL; cookies are Secure only when the request arrives over TLS or via a trusted proxy. Set Config.SuppressSecureCookieWarning=true to suppress this warning in dev.")
	}
	if cfg.RateLimitPerIP > 0 && len(cfg.TrustedProxies) == 0 && !cfg.SuppressTrustedProxiesWarning {
		slog.Warn("TrustedProxies is empty: behind a reverse proxy every client shares one per-IP rate-limit bucket. List the proxy CIDRs in Config.TrustedProxies, or set Config.SuppressTrustedProxiesWarning=true if exposed directly.")
	}

	providers = map[string]Provider{}
	if len(cfg.Providers) > 0 || cfg.ProviderResolver != nil {
		if len(cfg.EncryptionKey) != crypto.AESKeyLen {
			return nil, samlParsed{}, nil, errors.New("theauth: Config.EncryptionKey must be 32 bytes when Providers or ProviderResolver are configured")
		}
		for _, p := range cfg.Providers {
			if p == nil {
				return nil, samlParsed{}, nil, errors.New("theauth: Config.Providers contains a nil entry")
			}
			name := p.Name()
			if name == "" {
				return nil, samlParsed{}, nil, errors.New("theauth: provider returned an empty Name()")
			}
			if _, dup := providers[name]; dup {
				return nil, samlParsed{}, nil, errors.New("theauth: duplicate provider name: " + name)
			}
			providers[name] = p
		}
	}

	if cfg.WebAuthn != nil {
		if cfg.WebAuthn.RPID == "" {
			return nil, samlParsed{}, nil, errors.New("theauth: Config.WebAuthn.RPID is required")
		}
		if len(cfg.WebAuthn.RPOrigins) == 0 {
			return nil, samlParsed{}, nil, errors.New("theauth: Config.WebAuthn.RPOrigins must have at least one entry")
		}
	}

	if cfg.TOTP != nil {
		if len(cfg.EncryptionKey) != crypto.AESKeyLen {
			return nil, samlParsed{}, nil, errors.New("theauth: Config.EncryptionKey must be 32 bytes when TOTP is configured")
		}
		if cfg.TOTP.Issuer == "" {
			return nil, samlParsed{}, nil, errors.New("theauth: Config.TOTP.Issuer is required")
		}
	}

	if cfg.SCIM != nil && cfg.Organizations == nil {
		return nil, samlParsed{}, nil, ErrSCIMRequiresOrganizations
	}
	if cfg.SAML != nil && cfg.Organizations == nil {
		return nil, samlParsed{}, nil, ErrSAMLRequiresOrganizations
	}

	if cfg.SAML != nil {
		var parseErr error
		sp, parseErr = parseSAMLConfig(cfg.SAML)
		if parseErr != nil {
			return nil, samlParsed{}, nil, parseErr
		}
	}

	if cfg.Admin != nil && cfg.RBAC == nil {
		return nil, samlParsed{}, nil, ErrAdminRequiresRBAC
	}

	if cfg.AuthorizationServer != nil {
		if err := validateASConfig(cfg.AuthorizationServer, cfg.EncryptionKey); err != nil {
			return nil, samlParsed{}, nil, err
		}
		if _, ok := cfg.storageRaw.(OAuthServerStorage); !ok {
			return nil, samlParsed{}, nil, ErrStorageMissingOAuthMethods
		}
		if tp := cfg.AuthorizationServer.TokenPolicy; tp != nil && tp.DefaultAccessTokenFormat == AccessTokenFormatOpaque {
			if _, ok := cfg.storageRaw.(OpaqueTokenStorage); !ok {
				return nil, samlParsed{}, nil, errors.New("theauth: TokenPolicy.DefaultAccessTokenFormat opaque needs a storage that implements OpaqueTokenStorage")
			}
		}
	}

	if cfg.AgentIdentity != nil {
		if cfg.AuthorizationServer == nil {
			return nil, samlParsed{}, nil, ErrAgentRequiresAS
		}
		if err := validateAgentConfig(cfg.AgentIdentity); err != nil {
			return nil, samlParsed{}, nil, err
		}
	}
	if cfg.AccountUX && cfg.AgentIdentity == nil {
		return nil, samlParsed{}, nil, ErrAccountUXRequiresAgents
	}

	// Security audit H1: DCR registration tokens are hashed up front so the plaintext is dropped.
	if cfg.AuthorizationServer != nil && len(cfg.AuthorizationServer.RegistrationTokens) > 0 {
		dcrTokenHashes = make([][32]byte, 0, len(cfg.AuthorizationServer.RegistrationTokens))
		for _, tok := range cfg.AuthorizationServer.RegistrationTokens {
			if tok == "" {
				return nil, samlParsed{}, nil, errors.New("theauth: AuthorizationServer.RegistrationTokens contains an empty entry")
			}
			dcrTokenHashes = append(dcrTokenHashes, sha256.Sum256([]byte(tok)))
		}
	}

	if err := checkStorageCapabilities(cfg); err != nil {
		return nil, samlParsed{}, nil, err
	}

	return providers, sp, dcrTokenHashes, nil
}

// parseSAMLConfig decodes and parses the PEM SP certificate and private key. It accepts PKCS1 and
// PKCS8 RSA keys only.
func parseSAMLConfig(cfg *SAMLConfig) (samlParsed, error) {
	if len(cfg.SPCertificatePEM) == 0 {
		return samlParsed{}, errors.New("theauth: Config.SAML.SPCertificatePEM is required")
	}
	if len(cfg.SPPrivateKeyPEM) == 0 {
		return samlParsed{}, errors.New("theauth: Config.SAML.SPPrivateKeyPEM is required")
	}
	certBlock, _ := pem.Decode(cfg.SPCertificatePEM)
	if certBlock == nil {
		return samlParsed{}, errors.New("theauth: Config.SAML.SPCertificatePEM is not valid PEM")
	}
	c, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return samlParsed{}, errors.New("theauth: Config.SAML.SPCertificatePEM parse: " + err.Error())
	}
	keyBlock, _ := pem.Decode(cfg.SPPrivateKeyPEM)
	if keyBlock == nil {
		return samlParsed{}, errors.New("theauth: Config.SAML.SPPrivateKeyPEM is not valid PEM")
	}
	// PKCS8 is accepted because Microsoft tooling often emits it even for RSA keys.
	var key *rsa.PrivateKey
	switch keyBlock.Type {
	case "RSA PRIVATE KEY":
		k, kerr := x509.ParsePKCS1PrivateKey(keyBlock.Bytes)
		if kerr != nil {
			return samlParsed{}, errors.New("theauth: Config.SAML.SPPrivateKeyPEM PKCS1 parse: " + kerr.Error())
		}
		key = k
	case "PRIVATE KEY":
		anyKey, kerr := x509.ParsePKCS8PrivateKey(keyBlock.Bytes)
		if kerr != nil {
			return samlParsed{}, errors.New("theauth: Config.SAML.SPPrivateKeyPEM PKCS8 parse: " + kerr.Error())
		}
		rk, ok := anyKey.(*rsa.PrivateKey)
		if !ok {
			return samlParsed{}, errors.New("theauth: Config.SAML.SPPrivateKeyPEM must be an RSA key")
		}
		key = rk
	default:
		return samlParsed{}, errors.New("theauth: Config.SAML.SPPrivateKeyPEM unrecognised PEM type: " + keyBlock.Type)
	}
	return samlParsed{cert: c, key: key}, nil
}

// wireServices constructs and wires the internal services onto a. It runs once from New, after allocation.
func wireServices(a *TheAuth, cfg Config, providers map[string]Provider, sp samlParsed) error {
	// Audit is wired first so constructors taking an audit.Emitter receive the live writer.
	if cfg.Audit != nil {
		hasher, err := internalaudit.NewInputHasher(cfg.Audit.InputHashKey)
		if err != nil {
			return fmt.Errorf("theauth: Config.Audit.InputHashKey: %w", err)
		}
		if r := cfg.Audit.PseudonymRotation; r != nil {
			rot, ok := cfg.storageRaw.(AuditPseudonymRotator)
			if !ok {
				return errors.New("theauth: Config.Audit.PseudonymRotation needs a storage backend that implements AuditPseudonymRotator")
			}
			if err := rot.SetAuditPseudonymRotation(*r); err != nil {
				return fmt.Errorf("theauth: Config.Audit.PseudonymRotation: %w", err)
			}
		}
		internalSinks := make([]internalaudit.Sink, len(cfg.Audit.Sinks))
		for i, s := range cfg.Audit.Sinks {
			internalSinks[i] = auditSinkAdapter{s}
		}
		a.auditSvc = internalaudit.NewService(cfg.Storage, internalaudit.Config{
			BufferSize:      cfg.Audit.BufferSize,
			BatchSize:       cfg.Audit.BatchSize,
			FlushInterval:   cfg.Audit.FlushInterval,
			CustomRedactor:  internalaudit.Redactor(cfg.Audit.Redactor),
			DefaultRedactor: internalaudit.Redactor(DefaultRedactor),
			DrainTimeout:    cfg.Audit.DrainTimeout,
			Sinks:           internalSinks,
			InputHasher:     hasher,

			FailClosed:             cfg.Audit.FailClosed,
			DecisionActionPrefixes: cfg.Audit.DecisionActionPrefixes,
		})
		a.auditHasher = hasher
		a.auditSvc.SetHooks(a.hooks)
	}

	if cfg.AuthorizationServer != nil {
		oss := cfg.storageRaw.(OAuthServerStorage)
		var policy *internalas.AgentPolicy
		if cfg.AgentIdentity != nil {
			policy = &internalas.AgentPolicy{
				MaxChainDepth:            cfg.AgentIdentity.MaxChainDepth,
				DefaultDelegatedTokenTTL: cfg.AgentIdentity.DefaultDelegatedTokenTTL,
			}
		}
		var jwtBearerStore internalas.JWTBearerStorageAdapter
		if jbs, ok := cfg.storageRaw.(JWTBearerStorage); ok {
			jwtBearerStore = jwtBearerStorageAdapter{jbs}
		}
		if cfg.AuthorizationServer.DeviceTokens != nil {
			if _, ok := cfg.storageRaw.(DeviceIdentityStorage); !ok {
				return missingCapability("DeviceIdentityStorage (required by AuthorizationServer.DeviceTokens)")
			}
		}
		asCfg := asConfigFromRoot(cfg.AuthorizationServer)
		asCfg.Stores = cfg.Stores
		if asCfg.LoginURL == "" {
			asCfg.LoginURL = a.pathPrefix + "/login"
		}
		if cfg.LifecycleHooks != nil {
			asCfg.OnTokenIssued = cfg.LifecycleHooks.OnTokenIssued
		}
		a.as = internalas.New(internalas.Deps{
			Cfg:              asCfg,
			Storage:          oss,
			EncryptionKey:    cfg.EncryptionKey,
			AgentPolicy:      policy,
			Audit:            a,
			Hooks:            a.hooks,
			JWTBearerStorage: jwtBearerStore,
			Users:            cfg.Storage,
		})
		var agentPolicy *agent.Config
		if cfg.AgentIdentity != nil {
			agentPolicy = &agent.Config{
				MaxChainDepth:            cfg.AgentIdentity.MaxChainDepth,
				MaxDelegationDuration:    cfg.AgentIdentity.MaxDelegationDuration,
				DefaultDelegatedTokenTTL: cfg.AgentIdentity.DefaultDelegatedTokenTTL,
				AgentSecretLength:        cfg.AgentIdentity.AgentSecretLength,
			}
		}
		a.agentSvc = agent.New(oss, agentPolicy, a, a.as.InvalidateClientAuthCache)
		a.agentSvc.SetHooks(a.hooks)
		a.agentSvc.SetChainCacheInvalidator(a.as.InvalidateChainCache)
		if cfg.AgentIdentity != nil {
			a.agentGate = agent.NewGate(agent.GateConfig{
				Storage:   oss,
				Engine:    cfg.AgentIdentity.PolicyEngine,
				RateLimit: cfg.AgentIdentity.RateLimit.window(),
				Audit:     a,
				Hooks:     a.hooks,
			})
			if a.agentGate != nil {
				a.as.AgentGate = a.agentGate
			}
		}
		var delegationPolicy *delegation.Config
		if cfg.AgentIdentity != nil {
			delegationPolicy = &delegation.Config{
				MaxDelegationDuration: cfg.AgentIdentity.MaxDelegationDuration,
			}
		}
		a.delegationSvc = delegation.New(oss, delegationPolicy, a.as, a)
		a.delegationSvc.SetHooks(a.hooks)
		a.as.AgentLookup = internalas.AgentLookupFunc(a.agentSvc.AgentBySubjectClaim)
		if _, err := a.as.SubscribeRevocations(a.revocations); err != nil {
			return errors.New("theauth: subscribe authorization server to revocations: " + err.Error())
		}
	}

	permCatalog, permIndex, defaultSeeds := a.permCatalog, a.permIndex, a.defaultRoleSeeds
	a.sessionSvc = session.New(cfg.Storage, cfg.SessionTTL)
	a.sx.install(a.sessionSvc)
	a.magicSvc = magiclink.New(cfg.Storage, cfg.EmailSender, cfg.BaseURL, cfg.MagicLinkTTL, a.sessionSvc, a)
	a.magicSvc.SetPathPrefix(a.pathPrefix)
	a.scimSvc = internalscim.NewService(cfg.Storage, scimConfigFromRoot(cfg.SCIM))
	a.orgsSvc = organizations.New(cfg.Storage, orgsConfigFromRoot(cfg.Organizations))
	a.rbacSvc = rbac.New(cfg.Storage, rbacConfigFromValidated(cfg.RBAC, permCatalog, permIndex, defaultSeeds), a)

	// TOTP is constructed before password, which depends on it as its PendingTOTPIssuer.
	a.throttle = cfg.LoginThrottle.limiter()
	var gate *bootstrap.Gate
	if cfg.Bootstrap != nil {
		counter, ok := cfg.storageRaw.(UserCountStorage)
		if !ok {
			return missingCapability("UserCountStorage (required by Config.Bootstrap)")
		}
		g, gerr := bootstrap.New(cfg.Bootstrap, counter, a.throttle)
		if gerr != nil {
			return gerr
		}
		gate = g
		a.bootstrap = g
		a.magicSvc.SetHardening(a.emailNorm, g)
	} else {
		a.magicSvc.SetHardening(a.emailNorm, nil)
	}
	a.totpSvc = internaltotp.NewService(cfg.Storage, a.sessionSvc, a, totpConfigFromRoot(cfg.TOTP), cfg.EncryptionKey)
	replay, _ := cfg.storageRaw.(internaltotp.ReplayStore)
	a.totpSvc.SetHardening(a.throttle, replay)
	if rc, ok := cfg.storageRaw.(RecoveryCodeStorage); ok {
		a.totpSvc.SetRecoveryStore(rc)
	}
	if err := a.setupLifecycle(&cfg); err != nil {
		return err
	}
	if err := a.setupSharedSignals(&cfg); err != nil {
		return err
	}
	if a.sessionSvc != nil {
		a.totpSvc.SetSessionCap(a.sessionSvc)
	}
	pwCfg := password.Config{
		BaseURL:              cfg.BaseURL,
		PathPrefix:           a.pathPrefix,
		TOTPEnabled:          cfg.TOTP != nil,
		MinLength:            cfg.PasswordPolicy.MinLength,
		MaxBytes:             cfg.PasswordPolicy.MaxBytes,
		AllowLegacyBcrypt:    cfg.PasswordPolicy.AllowLegacyBcrypt,
		OnLegacyHashAccepted: cfg.PasswordPolicy.OnLegacyHashAccepted,
		Breach:               cfg.PasswordPolicy.BreachChecker,
		Email:                a.emailNorm,
		Throttle:             a.throttle,
	}
	if gate != nil {
		pwCfg.Gate = gate
	}
	if a.acct != nil {
		pwCfg.Account = a.acct
	}
	if a.devices != nil {
		pwCfg.Devices = a.devices
	}
	pwSvc, err := password.NewService(cfg.Storage, cfg.EmailSender, a.sessionSvc, a.magicSvc, a.totpSvc, a, pwCfg)
	if err != nil {
		return err
	}
	a.passwordSvc = pwSvc
	waSvc, err := internalwebauthn.NewService(cfg.Storage, a.sessionSvc, a, webauthnConfigFromRoot(cfg.WebAuthn))
	if err != nil {
		return err
	}
	if rn, ok := cfg.storageRaw.(WebAuthnRenameStorage); ok {
		waSvc.SetRenamer(rn)
	}
	a.webauthnSvc = waSvc
	samlCfg := samlConfigFromRoot(cfg.SAML, sp.cert, sp.key)
	if samlCfg != nil {
		samlCfg.Email = a.emailNorm
		if cfg.Stores.Cache != nil {
			samlCfg.Tracker = internalsaml.NewKVTracker(cfg.Stores.Cache)
		}
	}
	a.samlSvc = internalsaml.NewService(cfg.Storage, a.sessionSvc, a, samlCfg)

	// The OAuth GC goroutine starts inside internal/oauth, so no separate Start call is needed.
	if len(providers) > 0 || cfg.ProviderResolver != nil {
		var onConflict func(ctx context.Context, p internaloauth.ConflictPayload) (string, error)
		if cfg.LifecycleHooks != nil && cfg.LifecycleHooks.OnOAuthConflict != nil {
			hook := cfg.LifecycleHooks.OnOAuthConflict
			onConflict = func(ctx context.Context, p internaloauth.ConflictPayload) (string, error) {
				return hook(ctx, OAuthConflictPayload{
					Provider:        p.Provider,
					ProviderUserID:  p.ProviderUserID,
					ProviderEmail:   p.ProviderEmail,
					ProviderName:    p.ProviderName,
					ProviderAvatar:  p.ProviderAvatar,
					ExistingUserID:  p.ExistingUserID,
					AccessTokenEnc:  p.AccessTokenEnc,
					RefreshTokenEnc: p.RefreshTokenEnc,
					ExpiresAt:       p.ExpiresAt,
					Scope:           p.Scope,
				})
			}
		}
		a.oauthSvc = internaloauth.New(
			providers,
			a.storage,
			a.baseURL,
			a.encryptionKey,
			oauthSessionAdapter{svc: a.sessionSvc},
			a,
			onConflict,
			oauthConfigFromRoot(cfg.OAuth, a.pathPrefix),
		)
		a.providerReg = internaloauth.NewRegistry(providers, cfg.ProviderResolver, cfg.ProviderResolverFirst, cfg.ProviderResolverTTL)
		a.oauthSvc.SetLookup(a.providerReg)
	}

	// Identity linking is always constructed; mountAccount decides whether its HTTP endpoints are exposed.
	a.identityLinkSvc = identitylink.New(a.storage, a.encryptionKey, a)

	// Every background goroutine started here has a matching stop in Close.
	if a.auditSvc != nil {
		if err := a.auditSvc.Start(); err != nil {
			return err
		}
	}
	a.webauthnSvc.Start()
	a.totpSvc.Start()
	a.samlSvc.Start()
	if a.as != nil {
		if err := a.as.Start(context.Background()); err != nil {
			return err
		}
	}
	return nil
}

// auditSinkAdapter bridges AuditSink to internal/audit.Sink. AuditEvent is an alias, so the bridge
// is purely nominal.
type auditSinkAdapter struct{ inner AuditSink }

func (a auditSinkAdapter) Stream(ctx context.Context, batch []models.AuditEvent) error {
	return a.inner.Stream(ctx, batch)
}

func (a auditSinkAdapter) Name() string { return a.inner.Name() }

// oauthSessionAdapter satisfies internal/oauth.SessionIssuer with *session.Service without an import cycle.
type oauthSessionAdapter struct{ svc *session.Service }

func (a oauthSessionAdapter) Issue(ctx context.Context, user models.User, userAgent, ip string) (string, models.Session, error) {
	return a.svc.Issue(ctx, user, userAgent, ip)
}

// totpConfigFromRoot translates TOTPConfig into the internal/totp Config. Nil input yields nil,
// which disables the service.
func totpConfigFromRoot(c *TOTPConfig) *internaltotp.Config {
	if c == nil {
		return nil
	}
	return &internaltotp.Config{
		Issuer:            c.Issuer,
		RecoveryCodeCount: c.RecoveryCodeCount,
	}
}

// webauthnConfigFromRoot translates WebAuthnConfig into the internal/webauthn Config. Nil input
// yields nil, which disables it.
func webauthnConfigFromRoot(c *WebAuthnConfig) *internalwebauthn.Config {
	if c == nil {
		return nil
	}
	return &internalwebauthn.Config{
		RPID:          c.RPID,
		RPDisplayName: c.RPDisplayName,
		RPOrigins:     append([]string(nil), c.RPOrigins...),
		ChallengeTTL:  c.ChallengeTTL,

		RequireUserVerification: c.RequireUserVerification,
		CloneWarning:            string(c.CloneWarning),
		UserHandleResolver:      c.UserHandleResolver,

		AttestationPreference:       c.AttestationPreference,
		RequireAttestationStatement: c.RequireAttestationStatement,
		AAGUIDAllowlist:             append([]string(nil), c.AAGUIDAllowlist...),
		AAGUIDDenylist:              append([]string(nil), c.AAGUIDDenylist...),
		AuthenticatorNames:          c.AuthenticatorNames,
		AuthenticatorName:           c.AuthenticatorName,
	}
}

// samlConfigFromRoot translates SAMLConfig and the parsed keypair into the internal/saml Config.
// Nil input yields nil.
func samlConfigFromRoot(c *SAMLConfig, cert *x509.Certificate, key *rsa.PrivateKey) *internalsaml.Config {
	if c == nil {
		return nil
	}
	return &internalsaml.Config{
		SPCert:          cert,
		SPKey:           key,
		AuthnRequestTTL: c.AuthnRequestTTL,
		ClockSkew:       c.ClockSkew,
	}
}

// scimConfigFromRoot translates SCIMConfig into the internal/scim Config. Nil input yields nil.
func scimConfigFromRoot(c *SCIMConfig) *internalscim.Config {
	if c == nil {
		return nil
	}
	return &internalscim.Config{RequireHTTPS: c.RequireHTTPS, MaxPageSize: c.MaxPageSize}
}

// orgsConfigFromRoot translates OrganizationsConfig into the internal/organizations Config. Nil
// input yields nil.
func orgsConfigFromRoot(c *OrganizationsConfig) *organizations.Config {
	if c == nil {
		return nil
	}
	return &organizations.Config{}
}

// asConfigFromRoot translates AuthorizationServerConfig into the internal/as Config. The field sets
// match; the translation lives here so internal/as does not import root. It runs once in New, after
// validateASConfig.
func asConfigFromRoot(c *AuthorizationServerConfig) internalas.Config {
	if c == nil {
		return internalas.Config{}
	}
	return internalas.Config{
		Issuer:                         c.Issuer,
		Resources:                      append([]ProtectedResource(nil), c.Resources...),
		SigningAlg:                     c.SigningAlg,
		KeyRotationPeriod:              c.KeyRotationPeriod,
		KeyRetention:                   c.KeyRetention,
		AccessTokenTTL:                 c.AccessTokenTTL,
		RefreshTokenTTL:                c.RefreshTokenTTL,
		AuthorizationCodeTTL:           c.AuthorizationCodeTTL,
		RegistrationAccessTokenTTL:     c.RegistrationAccessTokenTTL,
		AllowAnonymousRegistration:     c.AllowAnonymousRegistration,
		RegistrationTokens:             append([]string(nil), c.RegistrationTokens...),
		RegistrationRateLimitPerMinute: c.RegistrationRateLimitPerMinute,
		IntrospectionCacheTTL:          c.IntrospectionCacheTTL,
		SubjectActiveCacheTTL:          c.SubjectActiveCacheTTL,
		Clock:                          c.Clock,
		LoginURL:                       c.LoginURL,
		DisableRotation:                c.DisableRotation,
		CIMD:                           c.CIMD,
		DPoP:                           dpopConfigFromRoot(c.DPoP),
		RequireState:                   c.RequireState,
		AccessTokenRevocation:          c.AccessTokenRevocation,
		ClientCompat:                   c.ClientCompat,
		ACRValues:                      internalas.NormalizeACRValues(c.ACRValues),
		SessionAMR:                     c.SessionAMR,
		PAR:                            c.PAR,
		JAR:                            c.JAR,
		JWTBearer:                      jwtBearerConfigFromRoot(c.JWTBearer),
		CIBA:                           cibaConfigToInternal(c.CIBA),
		DeviceAuthorization:            c.DeviceAuthorization,
		TokenPolicy:                    c.TokenPolicy,
		RAR:                            c.RAR,
		IDJAG:                          c.IDJAG,
		RateLimits:                     c.RateLimits,
		RegistrationTokenTTL:           c.RegistrationTokenTTL,
		DeviceTokens:                   c.DeviceTokens,
		OIDC:                           c.OIDC,
		ConsentHandler:                 c.ConsentHandler,
		ConsentMaxGrantTTL:             c.ConsentMaxGrantTTL,
		ConsentTicketTTL:               c.ConsentTicketTTL,
		CORS:                           c.CORS,
	}
}

// jwtBearerStorageAdapter bridges the root JWTBearerStorage to the internal/as interface.
type jwtBearerStorageAdapter struct {
	s JWTBearerStorage
}

func (a jwtBearerStorageAdapter) InsertJTI(ctx context.Context, jti string, expiresAt time.Time) error {
	return a.s.InsertJTI(ctx, jti, expiresAt)
}

// rbacConfigFromValidated builds the internal/rbac Config from the validated catalog, index and
// seeds. Nil RBAC yields nil, and every method then returns ErrRBACDisabled.
func rbacConfigFromValidated(cfg *RBACConfig, catalog []Permission, index map[string]Permission, seeds []RoleSeed) *rbac.Config {
	if cfg == nil {
		return nil
	}
	return &rbac.Config{PermCatalog: catalog, PermIndex: index, DefaultRoleSeeds: seeds}
}

// applyCookiesConfig validates Config.Cookies, prefixes the session cookie name per Cookies.Prefix
// and checks the resulting cookie policy, so an invalid combination fails New rather than a
// request.
func applyCookiesConfig(cfg *Config) error {
	prefix := ""
	switch strings.ToLower(strings.TrimSpace(cfg.Cookies.Prefix)) {
	case "":
	case "secure":
		prefix = httpsec.SecurePrefix
	case "host":
		prefix = httpsec.HostPrefix
	default:
		return errors.New("theauth: Config.Cookies.Prefix " + strconv.Quote(cfg.Cookies.Prefix) + " is not one of \"\", \"secure\", \"host\"")
	}
	if _, err := httpsec.ParseSameSite(cfg.Cookies.SameSite); err != nil {
		return errors.New("theauth: Config.Cookies." + err.Error())
	}
	if prefix != "" {
		name := cfg.CookieName
		switch {
		case strings.HasPrefix(name, prefix):
		case strings.HasPrefix(name, httpsec.HostPrefix) || strings.HasPrefix(name, httpsec.SecurePrefix):
			return errors.New("theauth: Config.CookieName " + strconv.Quote(name) + " already carries a different prefix than Config.Cookies.Prefix")
		default:
			cfg.CookieName = prefix + name
		}
	}
	p := cookiePolicyOf(cfg)
	if err := p.Validate(cfg.CookieName, "/"); err != nil {
		return errors.New("theauth: Config.Cookies: " + err.Error() + " (Secure needs Config.SecureCookie or an https BaseURL)")
	}
	return nil
}

// cookiePolicyOf builds the shared cookie policy from a validated Config.
func cookiePolicyOf(cfg *Config) httpsec.CookiePolicy {
	ss, _ := httpsec.ParseSameSite(cfg.Cookies.SameSite)
	return httpsec.CookiePolicy{
		Secure:      cfg.SecureCookie || strings.HasPrefix(strings.ToLower(cfg.BaseURL), "https://"),
		Domain:      strings.TrimSpace(cfg.Cookies.Domain),
		SameSite:    ss,
		Partitioned: cfg.Cookies.Partitioned,
	}
}

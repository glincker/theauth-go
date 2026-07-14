package theauth

import (
	"context"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"log/slog"
	"time"

	"github.com/glincker/theauth-go/crypto"
	"github.com/glincker/theauth-go/email"
	"github.com/glincker/theauth-go/internal/agent"
	internalas "github.com/glincker/theauth-go/internal/as"
	internalaudit "github.com/glincker/theauth-go/internal/audit"
	"github.com/glincker/theauth-go/internal/delegation"
	"github.com/glincker/theauth-go/internal/identitylink"
	"github.com/glincker/theauth-go/internal/magiclink"
	"github.com/glincker/theauth-go/internal/models"
	internaloauth "github.com/glincker/theauth-go/internal/oauth"
	"github.com/glincker/theauth-go/internal/organizations"
	"github.com/glincker/theauth-go/internal/password"
	"github.com/glincker/theauth-go/internal/rbac"
	internalsaml "github.com/glincker/theauth-go/internal/saml"
	internalscim "github.com/glincker/theauth-go/internal/scim"
	"github.com/glincker/theauth-go/internal/session"
	internaltotp "github.com/glincker/theauth-go/internal/totp"
	internalwebauthn "github.com/glincker/theauth-go/internal/webauthn"
)

// wiring.go holds the config-translation helpers (xxxConfigFromRoot) and
// the extracted wiring steps called from New(). Split from theauth.go in
// PR H (2026-06-22) to bring theauth.go below the 500 LOC ceiling. No
// behaviour change; all functions remain package-private.

// samlParsed is the pre-parsed SAML keypair returned by parseSAMLConfig.
// Bundling cert + key avoids threading two separate return values through
// New() and wireServices.
type samlParsed struct {
	cert *x509.Certificate
	key  *rsa.PrivateKey
}

// applyConfigDefaults fills in zero-value Config fields with library
// defaults. Must be called before any validation or wiring.
func applyConfigDefaults(cfg *Config) {
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

// validateConfig checks operator-supplied fields that cannot be covered by
// defaults. Returns the pre-parsed SAML keypair (non-nil only when
// cfg.SAML != nil), the parsed provider map, and the pre-hashed DCR tokens.
func validateConfig(cfg *Config) (providers map[string]Provider, sp samlParsed, dcrTokenHashes [][32]byte, err error) {
	if cfg.Storage == nil {
		return nil, samlParsed{}, nil, errors.New("theauth: Config.Storage is required")
	}
	if cfg.BaseURL == "" {
		return nil, samlParsed{}, nil, errors.New("theauth: Config.BaseURL is required")
	}

	// M3 (security audit 2026-06-21): warn when SecureCookie is false.
	if !cfg.SecureCookie && !cfg.SuppressSecureCookieWarning {
		slog.Warn("SecureCookie: false is deprecated; v3.0 will default to true. Set Config.SuppressSecureCookieWarning=true to suppress this warning in dev.")
	}

	// OAuth providers: need a 32-byte key, unique names.
	providers = map[string]Provider{}
	if len(cfg.Providers) > 0 {
		if len(cfg.EncryptionKey) != crypto.AESKeyLen {
			return nil, samlParsed{}, nil, errors.New("theauth: Config.EncryptionKey must be 32 bytes when Providers are configured")
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

	// WebAuthn: RPID + at least one origin required.
	if cfg.WebAuthn != nil {
		if cfg.WebAuthn.RPID == "" {
			return nil, samlParsed{}, nil, errors.New("theauth: Config.WebAuthn.RPID is required")
		}
		if len(cfg.WebAuthn.RPOrigins) == 0 {
			return nil, samlParsed{}, nil, errors.New("theauth: Config.WebAuthn.RPOrigins must have at least one entry")
		}
	}

	// TOTP: encryption key + issuer required.
	if cfg.TOTP != nil {
		if len(cfg.EncryptionKey) != crypto.AESKeyLen {
			return nil, samlParsed{}, nil, errors.New("theauth: Config.EncryptionKey must be 32 bytes when TOTP is configured")
		}
		if cfg.TOTP.Issuer == "" {
			return nil, samlParsed{}, nil, errors.New("theauth: Config.TOTP.Issuer is required")
		}
	}

	// v0.7: SAML and SCIM require Organizations.
	if cfg.SCIM != nil && cfg.Organizations == nil {
		return nil, samlParsed{}, nil, ErrSCIMRequiresOrganizations
	}
	if cfg.SAML != nil && cfg.Organizations == nil {
		return nil, samlParsed{}, nil, ErrSAMLRequiresOrganizations
	}

	// SAML: parse SP cert + key.
	if cfg.SAML != nil {
		var parseErr error
		sp, parseErr = parseSAMLConfig(cfg.SAML)
		if parseErr != nil {
			return nil, samlParsed{}, nil, parseErr
		}
	}

	// v1.0 RBAC + Admin.
	if cfg.Admin != nil && cfg.RBAC == nil {
		return nil, samlParsed{}, nil, ErrAdminRequiresRBAC
	}

	// v2.0 authorization server.
	if cfg.AuthorizationServer != nil {
		if err := validateASConfig(cfg.AuthorizationServer, cfg.EncryptionKey); err != nil {
			return nil, samlParsed{}, nil, err
		}
		if _, ok := cfg.Storage.(OAuthServerStorage); !ok {
			return nil, samlParsed{}, nil, ErrStorageMissingOAuthMethods
		}
	}

	// v2.0 agent identity + delegation.
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

	// Security audit H1 (2026-06-20): pre-hash DCR registration tokens.
	if cfg.AuthorizationServer != nil && len(cfg.AuthorizationServer.RegistrationTokens) > 0 {
		dcrTokenHashes = make([][32]byte, 0, len(cfg.AuthorizationServer.RegistrationTokens))
		for _, tok := range cfg.AuthorizationServer.RegistrationTokens {
			if tok == "" {
				return nil, samlParsed{}, nil, errors.New("theauth: AuthorizationServer.RegistrationTokens contains an empty entry")
			}
			dcrTokenHashes = append(dcrTokenHashes, sha256.Sum256([]byte(tok)))
		}
	}

	return providers, sp, dcrTokenHashes, nil
}

// parseSAMLConfig decodes and parses the PEM-encoded SP cert and private key
// from cfg. Accepts PKCS1 RSA, PKCS8 RSA. Returns an error for unsupported
// key types or malformed PEM.
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
	// Accept PKCS1 RSA, PKCS8 RSA, and EC-as-PKCS8 (Microsoft tooling
	// often emits PKCS8 even for RSA keys); other key types reject.
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

// wireServices constructs and wires all internal services onto a. Called once
// from New after the TheAuth struct is allocated. Returns any constructor
// error (password.NewService, webauthn.NewService, as.Start).
func wireServices(a *TheAuth, cfg Config, providers map[string]Provider, sp samlParsed) error {
	// Wire audit first so subsequent constructors that take an audit.Emitter
	// receive the live writer.
	if cfg.Audit != nil {
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
		})
		a.auditSvc.SetHooks(a.hooks)
	}

	// v2.0 authorization server + agent identity + delegation.
	if cfg.AuthorizationServer != nil {
		oss := cfg.Storage.(OAuthServerStorage)
		var policy *internalas.AgentPolicy
		if cfg.AgentIdentity != nil {
			policy = &internalas.AgentPolicy{
				MaxChainDepth:            cfg.AgentIdentity.MaxChainDepth,
				DefaultDelegatedTokenTTL: cfg.AgentIdentity.DefaultDelegatedTokenTTL,
			}
		}
		var jwtBearerStore internalas.JWTBearerStorageAdapter
		if jbs, ok := cfg.Storage.(JWTBearerStorage); ok {
			jwtBearerStore = jwtBearerStorageAdapter{jbs}
		}
		a.as = internalas.New(internalas.Deps{
			Cfg:              asConfigFromRoot(cfg.AuthorizationServer),
			Storage:          oss,
			EncryptionKey:    cfg.EncryptionKey,
			AgentPolicy:      policy,
			Audit:            a,
			Hooks:            a.hooks,
			JWTBearerStorage: jwtBearerStore,
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
		var delegationPolicy *delegation.Config
		if cfg.AgentIdentity != nil {
			delegationPolicy = &delegation.Config{
				MaxDelegationDuration: cfg.AgentIdentity.MaxDelegationDuration,
			}
		}
		a.delegationSvc = delegation.New(oss, delegationPolicy, a.as, a)
		a.delegationSvc.SetHooks(a.hooks)
		a.as.AgentLookup = internalas.AgentLookupFunc(a.agentSvc.AgentBySubjectClaim)
	}

	// Core services (session, magic link, SCIM, organizations, RBAC).
	permCatalog, permIndex, defaultSeeds := a.permCatalog, a.permIndex, a.defaultRoleSeeds
	a.sessionSvc = session.New(cfg.Storage, cfg.SessionTTL)
	a.magicSvc = magiclink.New(cfg.Storage, cfg.EmailSender, cfg.BaseURL, cfg.MagicLinkTTL, a.sessionSvc, a)
	a.scimSvc = internalscim.NewService(cfg.Storage, scimConfigFromRoot(cfg.SCIM))
	a.orgsSvc = organizations.New(cfg.Storage, orgsConfigFromRoot(cfg.Organizations))
	a.rbacSvc = rbac.New(cfg.Storage, rbacConfigFromValidated(cfg.RBAC, permCatalog, permIndex, defaultSeeds), a)

	// High-complexity services: TOTP before password (password depends on
	// totpSvc as its PendingTOTPIssuer).
	a.totpSvc = internaltotp.NewService(cfg.Storage, a.sessionSvc, a, totpConfigFromRoot(cfg.TOTP), cfg.EncryptionKey)
	pwSvc, err := password.NewService(cfg.Storage, cfg.EmailSender, a.sessionSvc, a.magicSvc, a.totpSvc, a, password.Config{
		BaseURL:     cfg.BaseURL,
		TOTPEnabled: cfg.TOTP != nil,
	})
	if err != nil {
		return err
	}
	a.passwordSvc = pwSvc
	waSvc, err := internalwebauthn.NewService(cfg.Storage, a.sessionSvc, a, webauthnConfigFromRoot(cfg.WebAuthn))
	if err != nil {
		return err
	}
	a.webauthnSvc = waSvc
	a.samlSvc = internalsaml.NewService(cfg.Storage, a.sessionSvc, a, samlConfigFromRoot(cfg.SAML, sp.cert, sp.key))

	// Wire OAuth provider service. The GC goroutine is started inside
	// internaloauth.New so there is no separate Start call needed.
	if len(providers) > 0 {
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
		)
	}

	// Wire identity-linking service (v2.3). Always constructed so that the
	// service methods are available regardless of whether AccountUX is
	// enabled; mountAccount gates whether the HTTP endpoints are exposed.
	a.identityLinkSvc = identitylink.New(a.storage, a.encryptionKey, a)

	// Start background loops. Every goroutine has a matching Stop in Close.
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

// auditSinkAdapter bridges the public AuditSink interface (which uses the
// root-package type alias AuditEvent = models.AuditEvent) to the
// internalaudit.Sink interface (which names models.AuditEvent directly).
// Because AuditEvent is a type alias, the slice types are identical at
// compile time; the adapter is purely a nominal bridge.
type auditSinkAdapter struct{ inner AuditSink }

func (a auditSinkAdapter) Stream(ctx context.Context, batch []models.AuditEvent) error {
	return a.inner.Stream(ctx, batch)
}

func (a auditSinkAdapter) Name() string { return a.inner.Name() }

// oauthSessionAdapter adapts *session.Service to the internaloauth.SessionIssuer
// interface without creating an import cycle. session.Service.Issue has the
// right signature already; this thin wrapper satisfies the interface declared
// in internal/oauth.
type oauthSessionAdapter struct{ svc *session.Service }

func (a oauthSessionAdapter) Issue(ctx context.Context, user models.User, userAgent, ip string) (string, models.Session, error) {
	return a.svc.Issue(ctx, user, userAgent, ip)
}

// ---------- xxxConfigFromRoot translators ----------

// totpConfigFromRoot translates the root TOTPConfig pointer into the
// internal/totp Config the extracted service consumes. Returns nil when
// the root config is nil so the service's "disabled" branch fires.
func totpConfigFromRoot(c *TOTPConfig) *internaltotp.Config {
	if c == nil {
		return nil
	}
	return &internaltotp.Config{
		Issuer:            c.Issuer,
		RecoveryCodeCount: c.RecoveryCodeCount,
	}
}

// webauthnConfigFromRoot translates the root WebAuthnConfig pointer into
// the internal/webauthn Config the extracted service consumes. Returns
// nil when the root config is nil so the service's "disabled" branch
// fires (every entry point returns "WebAuthn not configured").
func webauthnConfigFromRoot(c *WebAuthnConfig) *internalwebauthn.Config {
	if c == nil {
		return nil
	}
	return &internalwebauthn.Config{
		RPID:          c.RPID,
		RPDisplayName: c.RPDisplayName,
		RPOrigins:     append([]string(nil), c.RPOrigins...),
		ChallengeTTL:  c.ChallengeTTL,
	}
}

// samlConfigFromRoot translates the root SAMLConfig pointer plus the
// pre-parsed cert/key into the internal/saml Config the extracted service
// consumes. Returns nil when the root config is nil so the service's
// "disabled" branch fires.
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

// scimConfigFromRoot translates the root SCIMConfig pointer into the
// internal/scim Config the extracted service consumes. Returns nil when
// the root config is nil so the service's "disabled" branch fires.
func scimConfigFromRoot(c *SCIMConfig) *internalscim.Config {
	if c == nil {
		return nil
	}
	return &internalscim.Config{RequireHTTPS: c.RequireHTTPS, MaxPageSize: c.MaxPageSize}
}

// orgsConfigFromRoot translates the root OrganizationsConfig pointer into
// the internal/organizations Config. Returns nil when the root config is
// nil so the service's "disabled" branch fires.
func orgsConfigFromRoot(c *OrganizationsConfig) *organizations.Config {
	if c == nil {
		return nil
	}
	return &organizations.Config{}
}

// asConfigFromRoot translates the root AuthorizationServerConfig into
// the internal/as Config the extracted service consumes. The root and
// internal structs intentionally have identical field sets; the
// translation lives here so the internal package does not import root.
// Called once at New() time after validateASConfig has applied defaults.
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
		Clock:                          c.Clock,
		LoginURL:                       c.LoginURL,
		DisableRotation:                c.DisableRotation,
		CIMD:                           c.CIMD,
		DPoP:                           dpopConfigFromRoot(c.DPoP),
		RequireState:                   c.RequireState,
		PAR:                            c.PAR,
		JAR:                            c.JAR,
		JWTBearer:                      jwtBearerConfigFromRoot(c.JWTBearer),
		CIBA:                           cibaConfigToInternal(c.CIBA),
	}
}

// jwtBearerStorageAdapter bridges the root JWTBearerStorage to the
// internal/as.JWTBearerStorageAdapter interface. A thin wrapper is needed
// because the root and internal interfaces live in different packages.
type jwtBearerStorageAdapter struct {
	s JWTBearerStorage
}

func (a jwtBearerStorageAdapter) InsertJTI(ctx context.Context, jti string, expiresAt time.Time) error {
	return a.s.InsertJTI(ctx, jti, expiresAt)
}

// rbacConfigFromValidated produces the internal/rbac Config from the
// already-validated catalog, index, and default-role seeds. Returns nil
// when the root RBAC config is nil so the service's "disabled" branch
// fires (every method returns models.ErrRBACDisabled, matching the legacy
// root behavior).
func rbacConfigFromValidated(cfg *RBACConfig, catalog []Permission, index map[string]Permission, seeds []RoleSeed) *rbac.Config {
	if cfg == nil {
		return nil
	}
	internalSeeds := make([]rbac.RoleSeed, len(seeds))
	for i, s := range seeds {
		internalSeeds[i] = rbac.RoleSeed{Name: s.Name, Description: s.Description, Permissions: s.Permissions}
	}
	return &rbac.Config{PermCatalog: catalog, PermIndex: index, DefaultRoleSeeds: internalSeeds}
}

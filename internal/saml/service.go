// Package saml's Service owns the v0.7 SAML SP surface: connection CRUD,
// SP-initiated login (BeginLogin), the ACS endpoint backend
// (FinishLogin), the per-connection SP metadata serialiser (MetadataXML),
// the in-memory AuthnRequest tracker for replay protection, and the GC
// goroutine that sweeps expired AuthnRequest IDs.
//
// Extracted from root service_saml.go and saml.go in PR D of the 2026-06
// architecture reorg, alongside the existing base64.go helper. The root
// *theauth.TheAuth holds a *Service and exposes CreateSAMLConnection /
// UpdateSAMLConnection / DeleteSAMLConnection / SAMLConnectionByID /
// ListSAMLConnections / BeginSAMLLogin / FinishSAMLLogin / SAMLMetadataXML
// as thin forwarders so the v0.7 public surface is unchanged.
//
// The crewjam/saml ServiceProvider is rebuilt per call (cheap; a few
// struct copies and an IdP cert parse) so IdP cert rotation flows through
// the saml_connections row without a server restart. The
// per-connection IdP metadata cache crewjam maintains internally is
// scoped to one *saml.ServiceProvider; we do not keep them alive across
// calls.
//
// The AuthnRequest in-flight map (authnInFlight) lives on the Service.
// The GC goroutine for expired AuthnRequest IDs starts in Start and stops
// in Stop; every "go ..." in this package has a matching stop path so
// there is no goroutine leak.
package saml

import (
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"encoding/xml"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/crewjam/saml"
	"github.com/glincker/theauth-go/internal/audit"
	"github.com/glincker/theauth-go/internal/models"
	"github.com/glincker/theauth-go/internal/ulid"
)

// StdEnc returns the standard base64 encoding of b. Used by the SAML SP
// when emitting raw certificate bytes inside the IdP-signed assertion
// envelope; standard encoding is required by the SAML XML signature
// canonicalisation rules. Retained as a package-level helper because the
// root saml.go forwarder still calls it via the same import path.
func StdEnc(b []byte) string {
	return base64.StdEncoding.EncodeToString(b)
}

// authnGCEvery sweeps expired AuthnRequest IDs.
const authnGCEvery = time.Minute

// Storage is the minimal persistence subset this package needs.
type Storage interface {
	// Connections
	InsertSAMLConnection(ctx context.Context, c models.SAMLConnection) (models.SAMLConnection, error)
	UpdateSAMLConnectionRow(ctx context.Context, c models.SAMLConnection) error
	DeleteSAMLConnection(ctx context.Context, id models.ULID) error
	SAMLConnectionByID(ctx context.Context, id models.ULID) (*models.SAMLConnection, error)
	SAMLConnectionsByOrg(ctx context.Context, orgID models.ULID) ([]models.SAMLConnection, error)

	// Identities
	UpsertSAMLIdentity(ctx context.Context, i models.SAMLIdentity) (models.SAMLIdentity, error)
	SAMLIdentityByConnectionAndNameID(ctx context.Context, connectionID models.ULID, nameID string) (*models.SAMLIdentity, error)
	TouchSAMLIdentityLastLogin(ctx context.Context, id models.ULID, at time.Time) error

	// User + org membership for find-or-create + session pre-binding.
	UserByID(ctx context.Context, id models.ULID) (*models.User, error)
	UserByEmail(ctx context.Context, email string) (*models.User, error)
	CreateUser(ctx context.Context, u models.User) (models.User, error)
	UpsertOrganizationMember(ctx context.Context, m models.OrganizationMember) error
	OrganizationMemberRole(ctx context.Context, orgID, userID models.ULID) (string, error)
	SetSessionActiveOrganization(ctx context.Context, sessionID models.ULID, orgID *models.ULID) error
}

// SessionIssuer abstracts the session.Issue call so FinishLogin can mint a
// session without importing internal/session.
type SessionIssuer interface {
	Issue(ctx context.Context, user models.User, userAgent, ip string) (string, models.Session, error)
}

// Config bundles the SAML SP keypair and replay-protection knobs.
// Mirrors the root theauth.SAMLConfig field set; the cert + key are
// pre-parsed.
type Config struct {
	SPCert          *x509.Certificate
	SPKey           *rsa.PrivateKey
	AuthnRequestTTL time.Duration
	ClockSkew       time.Duration
}

// SAMLConnectionInput is the consumer-facing payload for create / update.
// Mirrors the root theauth.SAMLConnectionInput shape; the root forwarder
// translates between the two so the public type alias is unchanged.
type SAMLConnectionInput struct {
	OrganizationID models.ULID
	IdPEntityID    string
	IdPSSOURL      string
	IdPX509Cert    string
	SPEntityID     string
	SPACSURL       string
	AttributeMap   models.SAMLAttributeMap
}

// Sentinels re-exported via root errors.go.
var (
	ErrSAMLUnsignedAssertion = errors.New("theauth: saml assertion not signed")
	ErrSAMLInvalidAssertion  = errors.New("theauth: saml assertion invalid")
	ErrSAMLMissingEmail      = errors.New("theauth: saml assertion missing email attribute")
)

// Service holds the dependencies needed for SAML flows.
type Service struct {
	storage  Storage
	sessions SessionIssuer
	auditEm  audit.Emitter
	cfg      *Config

	// authnInFlight is the in-memory tracker of outstanding AuthnRequest
	// IDs, keyed by the request ID with the deadline as value.
	authnInFlight sync.Map

	// stopGC signals the AuthnRequest GC goroutine to exit. nil before
	// Start; closed by Stop.
	stopGC  chan struct{}
	started bool
	stopped bool
	mu      sync.Mutex // guards started / stopped / stopGC
}

// NewService constructs a SAML Service. cfg may be nil; in that case
// every public method returns "SAML not configured" matching the legacy
// root behavior. em may be nil; the constructor swaps in
// audit.NoopEmitter.
func NewService(storage Storage, sessions SessionIssuer, em audit.Emitter, cfg *Config) *Service {
	if em == nil {
		em = audit.NoopEmitter{}
	}
	return &Service{
		storage:  storage,
		sessions: sessions,
		auditEm:  em,
		cfg:      cfg,
	}
}

// Start spawns the AuthnRequest GC goroutine. Idempotent: a second call is
// a no-op. No-op when cfg is nil.
func (s *Service) Start() {
	if s.cfg == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.started {
		return
	}
	s.started = true
	s.stopGC = make(chan struct{})
	go s.gcLoop(s.stopGC)
}

// Stop closes the stop channel and signals the GC goroutine to return.
// Idempotent: a second call is a no-op.
func (s *Service) Stop() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.started || s.stopped {
		return
	}
	s.stopped = true
	if s.stopGC != nil {
		select {
		case <-s.stopGC:
		default:
			close(s.stopGC)
		}
	}
}

// gcLoop drops AuthnRequest IDs whose TTL has expired. Runs every minute;
// a missed sweep is harmless because the SP's ParseResponse also enforces
// the request-ID match.
func (s *Service) gcLoop(stop chan struct{}) {
	tick := time.NewTicker(authnGCEvery)
	defer tick.Stop()
	for {
		select {
		case <-stop:
			return
		case now := <-tick.C:
			s.authnInFlight.Range(func(k, v interface{}) bool {
				deadline, ok := v.(time.Time)
				if !ok || now.After(deadline) {
					s.authnInFlight.Delete(k)
				}
				return true
			})
		}
	}
}

// CreateConnection inserts a fresh saml_connections row. AttributeMap is
// normalised: empty fields fall back to the WS-Federation defaults.
func (s *Service) CreateConnection(ctx context.Context, in SAMLConnectionInput) (models.SAMLConnection, error) {
	if s.cfg == nil {
		return models.SAMLConnection{}, errors.New("theauth: SAML not enabled")
	}
	if err := validateInput(&in); err != nil {
		return models.SAMLConnection{}, err
	}
	c := models.SAMLConnection{
		ID:             ulid.New(),
		OrganizationID: in.OrganizationID,
		IdPEntityID:    in.IdPEntityID,
		IdPSSOURL:      in.IdPSSOURL,
		IdPX509Cert:    in.IdPX509Cert,
		SPEntityID:     in.SPEntityID,
		SPACSURL:       in.SPACSURL,
		AttributeMap:   in.AttributeMap,
	}
	return s.storage.InsertSAMLConnection(ctx, c)
}

// UpdateConnection rewrites an existing connection in place.
func (s *Service) UpdateConnection(ctx context.Context, id models.ULID, in SAMLConnectionInput) (models.SAMLConnection, error) {
	if s.cfg == nil {
		return models.SAMLConnection{}, errors.New("theauth: SAML not enabled")
	}
	if err := validateInput(&in); err != nil {
		return models.SAMLConnection{}, err
	}
	c := models.SAMLConnection{
		ID:             id,
		OrganizationID: in.OrganizationID,
		IdPEntityID:    in.IdPEntityID,
		IdPSSOURL:      in.IdPSSOURL,
		IdPX509Cert:    in.IdPX509Cert,
		SPEntityID:     in.SPEntityID,
		SPACSURL:       in.SPACSURL,
		AttributeMap:   in.AttributeMap,
	}
	if err := s.storage.UpdateSAMLConnectionRow(ctx, c); err != nil {
		return models.SAMLConnection{}, err
	}
	row, err := s.storage.SAMLConnectionByID(ctx, id)
	if err != nil {
		return models.SAMLConnection{}, err
	}
	return *row, nil
}

// DeleteConnection removes the connection + cascades its identities.
func (s *Service) DeleteConnection(ctx context.Context, id models.ULID) error {
	return s.storage.DeleteSAMLConnection(ctx, id)
}

// ConnectionByID looks up one connection.
func (s *Service) ConnectionByID(ctx context.Context, id models.ULID) (*models.SAMLConnection, error) {
	return s.storage.SAMLConnectionByID(ctx, id)
}

// ListConnections returns every connection for one organization.
func (s *Service) ListConnections(ctx context.Context, orgID models.ULID) ([]models.SAMLConnection, error) {
	return s.storage.SAMLConnectionsByOrg(ctx, orgID)
}

// BeginLogin returns the redirect URL for an SP-initiated SSO and records
// the AuthnRequest ID in the in-memory tracker for replay protection.
func (s *Service) BeginLogin(ctx context.Context, connectionID models.ULID, relayState string) (string, error) {
	conn, err := s.storage.SAMLConnectionByID(ctx, connectionID)
	if err != nil {
		return "", err
	}
	sp, err := s.serviceProviderFor(conn)
	if err != nil {
		return "", err
	}
	req, err := sp.MakeAuthenticationRequest(sp.GetSSOBindingLocation(saml.HTTPRedirectBinding), saml.HTTPRedirectBinding, saml.HTTPPostBinding)
	if err != nil {
		return "", err
	}
	s.authnInFlight.Store(req.ID, time.Now().Add(s.cfg.AuthnRequestTTL))
	redirectURL, err := req.Redirect(relayState, sp)
	if err != nil {
		return "", err
	}
	return redirectURL.String(), nil
}

// FinishLogin validates an inbound SAMLResponse, runs find-or-create,
// issues a session, and returns its token. ua + ip annotate the session
// for audit. The third return value reports whether the user row was
// created during this call, so callers can dispatch
// LifecycleHooks.OnSignup with SignupMethodSAML.
func (s *Service) FinishLogin(ctx context.Context, connectionID models.ULID, samlResponseB64 string, ua, ip string) (string, models.Session, bool, error) {
	conn, err := s.storage.SAMLConnectionByID(ctx, connectionID)
	if err != nil {
		return "", models.Session{}, false, err
	}
	sp, err := s.serviceProviderFor(conn)
	if err != nil {
		return "", models.Session{}, false, err
	}

	// Collect outstanding request IDs for replay protection. The IdP-
	// initiated path passes an empty slice so the library accepts the
	// assertion as unsolicited (AllowIDPInitiated is on in our SP builder).
	ids := s.outstandingAuthnRequestIDs()

	rawBytes, err := base64.StdEncoding.DecodeString(samlResponseB64)
	if err != nil {
		return "", models.Session{}, false, fmt.Errorf("theauth: saml response base64 decode: %w", err)
	}
	// Explicit signed-assertion gate runs against the raw XML before we
	// hand it to crewjam/saml. Once ParseXMLResponse normalises the
	// document it may strip the signature element after verification, so
	// post-parse introspection is unreliable across crewjam versions. The
	// raw-text check is what catches a syntactically valid but unsigned
	// assertion before any state mutation happens.
	if !rawHasAssertionSignature(rawBytes) {
		return "", models.Session{}, false, ErrSAMLUnsignedAssertion
	}
	acsURL, err := url.Parse(conn.SPACSURL)
	if err != nil {
		return "", models.Session{}, false, fmt.Errorf("theauth: sp acs url invalid: %w", err)
	}
	assertion, err := sp.ParseXMLResponse(rawBytes, ids, *acsURL)
	if err != nil {
		return "", models.Session{}, false, errors.Join(ErrSAMLInvalidAssertion, err)
	}

	// Once an InResponseTo lands, consume it so a replay against the same
	// ID is rejected on the second hit.
	if assertion.Subject != nil && assertion.Subject.SubjectConfirmations != nil {
		for _, sc := range assertion.Subject.SubjectConfirmations {
			if sc.SubjectConfirmationData != nil && sc.SubjectConfirmationData.InResponseTo != "" {
				s.authnInFlight.Delete(sc.SubjectConfirmationData.InResponseTo)
			}
		}
	}

	mapped := mapAssertion(conn, assertion)
	if mapped.Email == "" {
		return "", models.Session{}, false, ErrSAMLMissingEmail
	}

	user, isNew, err := s.findOrCreateUser(ctx, conn, assertion, mapped)
	if err != nil {
		return "", models.Session{}, false, err
	}

	token, sess, err := s.issueSessionForOrg(ctx, user, conn.OrganizationID, ua, ip)
	if err != nil {
		return "", models.Session{}, false, err
	}

	auditCtx := audit.WithAuditMetadata(ctx, audit.AuditMetadata{
		OrganizationID: &conn.OrganizationID,
		ActorUserID:    &user.ID,
		IP:             ip,
		UserAgent:      ua,
	})
	s.auditEm.EmitAudit(auditCtx, "saml.login_success", models.TargetRef{Type: "user", ID: user.ID.String()}, map[string]any{
		"connection_id": conn.ID.String(),
	})

	return token, sess, isNew, nil
}

// MetadataXML serialises the per-connection SP metadata as XML, ready to
// hand to an IdP admin.
func (s *Service) MetadataXML(ctx context.Context, connectionID models.ULID) ([]byte, error) {
	conn, err := s.storage.SAMLConnectionByID(ctx, connectionID)
	if err != nil {
		return nil, err
	}
	sp, err := s.serviceProviderFor(conn)
	if err != nil {
		return nil, err
	}
	md := sp.Metadata()
	return xml.MarshalIndent(md, "", "  ")
}

// serviceProviderFor builds a per-connection crewjam/saml ServiceProvider
// using the global SP keypair (cfg.SAML) and the connection-specific IdP
// metadata stored on the SAMLConnection row. We do not cache the SP
// across calls; building one is cheap and rebuilding on every login keeps
// the IdP cert rotation flow simple.
func (s *Service) serviceProviderFor(conn *models.SAMLConnection) (*saml.ServiceProvider, error) {
	if s.cfg == nil || s.cfg.SPCert == nil || s.cfg.SPKey == nil {
		return nil, errors.New("theauth: SAML not configured")
	}
	idpCert, err := parseIdPCert(conn.IdPX509Cert)
	if err != nil {
		return nil, fmt.Errorf("theauth: idp cert: %w", err)
	}
	ssoURL, err := url.Parse(conn.IdPSSOURL)
	if err != nil {
		return nil, fmt.Errorf("theauth: idp sso url: %w", err)
	}
	acsURL, err := url.Parse(conn.SPACSURL)
	if err != nil {
		return nil, fmt.Errorf("theauth: sp acs url: %w", err)
	}
	mdURL := *acsURL
	mdURL.Path = mdURL.Path + "/metadata"
	idpMD := &saml.EntityDescriptor{
		EntityID: conn.IdPEntityID,
		IDPSSODescriptors: []saml.IDPSSODescriptor{
			{
				SSODescriptor: saml.SSODescriptor{
					RoleDescriptor: saml.RoleDescriptor{
						KeyDescriptors: []saml.KeyDescriptor{
							{
								Use: "signing",
								KeyInfo: saml.KeyInfo{
									X509Data: saml.X509Data{
										X509Certificates: []saml.X509Certificate{
											{Data: StdEnc(idpCert.Raw)},
										},
									},
								},
							},
						},
					},
				},
				SingleSignOnServices: []saml.Endpoint{
					{
						Binding:  saml.HTTPRedirectBinding,
						Location: ssoURL.String(),
					},
					{
						Binding:  saml.HTTPPostBinding,
						Location: ssoURL.String(),
					},
				},
			},
		},
	}
	sp := &saml.ServiceProvider{
		EntityID:          conn.SPEntityID,
		Key:               s.cfg.SPKey,
		Certificate:       s.cfg.SPCert,
		MetadataURL:       mdURL,
		AcsURL:            *acsURL,
		IDPMetadata:       idpMD,
		AllowIDPInitiated: true,
	}
	return sp, nil
}

// mappedAttrs is the projection of a SAML assertion through the per-
// connection attribute map + WS-Federation defaults.
type mappedAttrs struct {
	Email      string
	Name       string
	GivenName  string
	FamilyName string
	Groups     []string
}

func mapAssertion(conn *models.SAMLConnection, a *saml.Assertion) mappedAttrs {
	defaults := models.DefaultSAMLAttributeMap()
	pick := func(connKey, defKey string) string {
		if connKey != "" {
			return connKey
		}
		return defKey
	}
	attrs := flattenAttributes(a)
	get := func(name string) string {
		if v, ok := attrs[name]; ok && len(v) > 0 {
			return v[0]
		}
		return ""
	}
	getAll := func(name string) []string {
		if v, ok := attrs[name]; ok {
			return v
		}
		return nil
	}
	return mappedAttrs{
		Email:      strings.ToLower(strings.TrimSpace(get(pick(conn.AttributeMap.Email, defaults.Email)))),
		Name:       strings.TrimSpace(get(pick(conn.AttributeMap.Name, defaults.Name))),
		GivenName:  strings.TrimSpace(get(pick(conn.AttributeMap.GivenName, defaults.GivenName))),
		FamilyName: strings.TrimSpace(get(pick(conn.AttributeMap.FamilyName, defaults.FamilyName))),
		Groups:     getAll(pick(conn.AttributeMap.Groups, defaults.Groups)),
	}
}

// flattenAttributes turns a SAML Assertion's AttributeStatements into a
// flat name -> []values map. Names match the SAML attribute Name (not
// FriendlyName), which is what enterprise IdPs configure.
func flattenAttributes(a *saml.Assertion) map[string][]string {
	out := map[string][]string{}
	for _, stmt := range a.AttributeStatements {
		for _, attr := range stmt.Attributes {
			name := attr.Name
			vals := make([]string, 0, len(attr.Values))
			for _, v := range attr.Values {
				vals = append(vals, v.Value)
			}
			out[name] = append(out[name], vals...)
		}
	}
	return out
}

// rawHasAssertionSignature scans the raw XML response (post-base64) for a
// ds:Signature element nested inside an Assertion. This is a textual
// check rather than a full XML parse because:
//
//  1. crewjam/saml's ParseXMLResponse normalises and may strip the
//     signature element after verification; post-parse introspection
//     varies across versions.
//  2. We only need a defensive "did anyone bother to sign?" gate; the
//     cryptographic validation is owned by ParseXMLResponse downstream.
//
// We accept either the default ds:Signature prefix or the local-name
// "Signature" inside the Assertion subtree. A response with a Signature
// only on the Response wrapper (and not on the Assertion itself) is still
// flagged as unsigned, matching the v0.7 spec requirement that the
// assertion be signed.
func rawHasAssertionSignature(raw []byte) bool {
	s := string(raw)
	open := indexOpenTag(s, "Assertion")
	if open < 0 {
		return false
	}
	closeIdx := indexCloseTag(s[open:], "Assertion")
	if closeIdx < 0 {
		return false
	}
	subtree := s[open : open+closeIdx]
	return indexOpenTag(subtree, "Signature") >= 0
}

// indexOpenTag returns the index of the first opening tag with the given
// local name (i.e. "<name " or "<prefix:name "), or -1 if absent.
func indexOpenTag(s, name string) int {
	for i := 0; i < len(s); i++ {
		if s[i] != '<' {
			continue
		}
		if i+1 < len(s) && (s[i+1] == '/' || s[i+1] == '!' || s[i+1] == '?') {
			continue
		}
		j := i + 1
		colon := -1
		for k := j; k < len(s) && (isNameChar(s[k]) || s[k] == ':'); k++ {
			if s[k] == ':' {
				colon = k
			}
		}
		nameStart := j
		if colon > 0 {
			nameStart = colon + 1
		}
		nameEnd := nameStart
		for nameEnd < len(s) && isNameChar(s[nameEnd]) {
			nameEnd++
		}
		if nameEnd > nameStart && s[nameStart:nameEnd] == name {
			return i
		}
	}
	return -1
}

// indexCloseTag returns the index of the closing tag </name> (with or
// without namespace prefix) relative to the start of s, or -1 if absent.
func indexCloseTag(s, name string) int {
	for i := 0; i+1 < len(s); i++ {
		if s[i] != '<' || s[i+1] != '/' {
			continue
		}
		j := i + 2
		colon := -1
		for k := j; k < len(s) && (isNameChar(s[k]) || s[k] == ':'); k++ {
			if s[k] == ':' {
				colon = k
			}
		}
		nameStart := j
		if colon > 0 {
			nameStart = colon + 1
		}
		nameEnd := nameStart
		for nameEnd < len(s) && isNameChar(s[nameEnd]) {
			nameEnd++
		}
		if nameEnd > nameStart && s[nameStart:nameEnd] == name {
			for k := nameEnd; k < len(s); k++ {
				if s[k] == '>' {
					return k + 1
				}
			}
		}
	}
	return -1
}

func isNameChar(b byte) bool {
	return (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z') || (b >= '0' && b <= '9') || b == '_' || b == '-' || b == '.'
}

// findOrCreateUser resolves the find-or-create cascade documented in
// section 8 of the v0.7 spec.
func (s *Service) findOrCreateUser(ctx context.Context, conn *models.SAMLConnection, assertion *saml.Assertion, mapped mappedAttrs) (models.User, bool, error) {
	nameID := ""
	nameIDFormat := ""
	if assertion.Subject != nil && assertion.Subject.NameID != nil {
		nameID = assertion.Subject.NameID.Value
		nameIDFormat = assertion.Subject.NameID.Format
	}
	if nameID == "" {
		// Some IdPs put the user identifier in a NameID-less subject;
		// fall back to the mapped email so the identity row still keys
		// to something stable.
		nameID = mapped.Email
		nameIDFormat = "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"
	}

	// Branch 1: existing identity for (connection, name_id).
	if ident, err := s.storage.SAMLIdentityByConnectionAndNameID(ctx, conn.ID, nameID); err == nil {
		user, err := s.storage.UserByID(ctx, ident.UserID)
		if err != nil {
			return models.User{}, false, err
		}
		_ = s.storage.TouchSAMLIdentityLastLogin(ctx, ident.ID, time.Now())
		return *user, false, nil
	} else if !errors.Is(err, models.ErrStorageNotFound) {
		return models.User{}, false, err
	}

	// Branch 2: email fallback. If a user already exists with the mapped
	// email, link them to this connection and ensure org membership.
	if user, err := s.storage.UserByEmail(ctx, mapped.Email); err == nil {
		if err := s.ensureOrgMembership(ctx, conn.OrganizationID, user.ID); err != nil {
			return models.User{}, false, err
		}
		if _, err := s.storage.UpsertSAMLIdentity(ctx, models.SAMLIdentity{
			ID:           ulid.New(),
			ConnectionID: conn.ID,
			UserID:       user.ID,
			NameID:       nameID,
			NameIDFormat: nameIDFormat,
		}); err != nil {
			return models.User{}, false, err
		}
		return *user, false, nil
	} else if !errors.Is(err, models.ErrStorageNotFound) {
		return models.User{}, false, err
	}

	// Branch 3: create a fresh user.
	now := time.Now()
	verified := now
	displayName := mapped.Name
	if displayName == "" {
		if mapped.GivenName != "" || mapped.FamilyName != "" {
			displayName = strings.TrimSpace(mapped.GivenName + " " + mapped.FamilyName)
		}
	}
	if displayName == "" {
		// Fall back to the email local part so the user has something
		// human-readable in the UI.
		if at := strings.IndexByte(mapped.Email, '@'); at > 0 {
			displayName = mapped.Email[:at]
		}
	}
	u := models.User{
		ID:              ulid.New(),
		Email:           mapped.Email,
		EmailVerifiedAt: &verified,
		Name:            displayName,
		GivenName:       mapped.GivenName,
		FamilyName:      mapped.FamilyName,
		DisplayName:     displayName,
		CreatedAt:       now,
		UpdatedAt:       now,
	}
	created, err := s.storage.CreateUser(ctx, u)
	if err != nil {
		return models.User{}, false, err
	}
	if err := s.storage.UpsertOrganizationMember(ctx, models.OrganizationMember{
		OrganizationID: conn.OrganizationID,
		UserID:         created.ID,
		Role:           models.OrgRoleMember,
	}); err != nil {
		return models.User{}, false, err
	}
	if _, err := s.storage.UpsertSAMLIdentity(ctx, models.SAMLIdentity{
		ID:           ulid.New(),
		ConnectionID: conn.ID,
		UserID:       created.ID,
		NameID:       nameID,
		NameIDFormat: nameIDFormat,
	}); err != nil {
		return models.User{}, false, err
	}
	return created, true, nil
}

// ensureOrgMembership upserts a "member" role row when the user is not
// already a member of the supplied organization.
func (s *Service) ensureOrgMembership(ctx context.Context, orgID, userID models.ULID) error {
	_, err := s.storage.OrganizationMemberRole(ctx, orgID, userID)
	if err == nil {
		return nil
	}
	if !errors.Is(err, models.ErrStorageNotFound) {
		return err
	}
	return s.storage.UpsertOrganizationMember(ctx, models.OrganizationMember{
		OrganizationID: orgID,
		UserID:         userID,
		Role:           models.OrgRoleMember,
	})
}

// outstandingAuthnRequestIDs returns the IDs of every AuthnRequest still
// inside its TTL. Used to drive crewjam/saml's InResponseTo validation.
func (s *Service) outstandingAuthnRequestIDs() []string {
	now := time.Now()
	var ids []string
	s.authnInFlight.Range(func(k, v interface{}) bool {
		deadline, ok := v.(time.Time)
		if !ok || now.After(deadline) {
			s.authnInFlight.Delete(k)
			return true
		}
		if id, ok := k.(string); ok {
			ids = append(ids, id)
		}
		return true
	})
	return ids
}

// issueSessionForOrg mints a session with the supplied active org pre-set.
func (s *Service) issueSessionForOrg(ctx context.Context, user models.User, orgID models.ULID, ua, ip string) (string, models.Session, error) {
	token, sess, err := s.sessions.Issue(ctx, user, ua, ip)
	if err != nil {
		return "", models.Session{}, err
	}
	id := orgID
	if err := s.storage.SetSessionActiveOrganization(ctx, sess.ID, &id); err != nil {
		return "", models.Session{}, err
	}
	sess.ActiveOrganizationID = &id
	return token, sess, nil
}

// parseIdPCert parses a PEM-encoded X.509 certificate. Accepts CRLF and
// LF line endings; trims surrounding whitespace.
func parseIdPCert(pemText string) (*x509.Certificate, error) {
	block, _ := pem.Decode([]byte(pemText))
	if block == nil {
		return nil, errors.New("invalid PEM")
	}
	c, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, err
	}
	return c, nil
}

// validateInput rejects SAMLConnectionInput payloads missing required
// fields. Mutates the AttributeMap to fill in the email default when the
// caller omits it.
func validateInput(in *SAMLConnectionInput) error {
	if in.OrganizationID == (models.ULID{}) {
		return errors.New("theauth: SAML connection requires an organization id")
	}
	if in.IdPEntityID == "" || in.IdPSSOURL == "" || in.IdPX509Cert == "" {
		return errors.New("theauth: SAML connection requires idP entity id, sso url, and x509 cert")
	}
	if _, err := url.Parse(in.IdPSSOURL); err != nil {
		return fmt.Errorf("theauth: SAML idP sso url invalid: %w", err)
	}
	if in.SPEntityID == "" || in.SPACSURL == "" {
		return errors.New("theauth: SAML connection requires sp entity id and acs url")
	}
	if _, err := url.Parse(in.SPACSURL); err != nil {
		return fmt.Errorf("theauth: SAML sp acs url invalid: %w", err)
	}
	if in.AttributeMap.Email == "" {
		// The find-or-create email fallback path keys on email; refuse
		// to store a map that would always go down the "missing email"
		// branch. Per the v0.7 spec defaults still apply when the field
		// is empty, so we only enforce non-empty here if the consumer
		// passes a partial map that wipes the default.
		in.AttributeMap.Email = models.DefaultSAMLAttributeMap().Email
	}
	return nil
}

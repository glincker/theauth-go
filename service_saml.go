package theauth

import (
	"context"
	"encoding/base64"
	"encoding/xml"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/crewjam/saml"
	"github.com/glincker/theauth-go/internal/ulid"
)

// SAMLConnectionInput is the consumer-facing payload for create / update.
type SAMLConnectionInput struct {
	OrganizationID ULID
	IdPEntityID    string
	IdPSSOURL      string
	IdPX509Cert    string
	SPEntityID     string
	SPACSURL       string
	AttributeMap   SAMLAttributeMap
}

// CreateSAMLConnection inserts a fresh saml_connections row. AttributeMap
// is normalised: empty fields fall back to the WS-Federation defaults.
func (a *TheAuth) CreateSAMLConnection(ctx context.Context, in SAMLConnectionInput) (SAMLConnection, error) {
	if a.samlCfg == nil {
		return SAMLConnection{}, errors.New("theauth: SAML not enabled")
	}
	if err := validateSAMLInput(in); err != nil {
		return SAMLConnection{}, err
	}
	c := SAMLConnection{
		ID:             ulid.New(),
		OrganizationID: in.OrganizationID,
		IdPEntityID:    in.IdPEntityID,
		IdPSSOURL:      in.IdPSSOURL,
		IdPX509Cert:    in.IdPX509Cert,
		SPEntityID:     in.SPEntityID,
		SPACSURL:       in.SPACSURL,
		AttributeMap:   in.AttributeMap,
	}
	return a.storage.InsertSAMLConnection(ctx, c)
}

// UpdateSAMLConnection rewrites an existing connection in place.
func (a *TheAuth) UpdateSAMLConnection(ctx context.Context, id ULID, in SAMLConnectionInput) (SAMLConnection, error) {
	if a.samlCfg == nil {
		return SAMLConnection{}, errors.New("theauth: SAML not enabled")
	}
	if err := validateSAMLInput(in); err != nil {
		return SAMLConnection{}, err
	}
	c := SAMLConnection{
		ID:             id,
		OrganizationID: in.OrganizationID,
		IdPEntityID:    in.IdPEntityID,
		IdPSSOURL:      in.IdPSSOURL,
		IdPX509Cert:    in.IdPX509Cert,
		SPEntityID:     in.SPEntityID,
		SPACSURL:       in.SPACSURL,
		AttributeMap:   in.AttributeMap,
	}
	if err := a.storage.UpdateSAMLConnectionRow(ctx, c); err != nil {
		return SAMLConnection{}, err
	}
	row, err := a.storage.SAMLConnectionByID(ctx, id)
	if err != nil {
		return SAMLConnection{}, err
	}
	return *row, nil
}

// DeleteSAMLConnection removes the connection + cascades its identities.
func (a *TheAuth) DeleteSAMLConnection(ctx context.Context, id ULID) error {
	return a.storage.DeleteSAMLConnection(ctx, id)
}

// SAMLConnectionByID looks up one connection.
func (a *TheAuth) SAMLConnectionByID(ctx context.Context, id ULID) (*SAMLConnection, error) {
	return a.storage.SAMLConnectionByID(ctx, id)
}

// ListSAMLConnections returns every connection for one organization.
func (a *TheAuth) ListSAMLConnections(ctx context.Context, orgID ULID) ([]SAMLConnection, error) {
	return a.storage.SAMLConnectionsByOrg(ctx, orgID)
}

// BeginSAMLLogin returns the redirect URL for an SP-initiated SSO and
// records the AuthnRequest ID in the in-memory tracker for replay
// protection.
func (a *TheAuth) BeginSAMLLogin(ctx context.Context, connectionID ULID, relayState string) (string, error) {
	conn, err := a.storage.SAMLConnectionByID(ctx, connectionID)
	if err != nil {
		return "", err
	}
	sp, err := a.samlServiceProviderFor(conn)
	if err != nil {
		return "", err
	}
	req, err := sp.MakeAuthenticationRequest(sp.GetSSOBindingLocation(saml.HTTPRedirectBinding), saml.HTTPRedirectBinding, saml.HTTPPostBinding)
	if err != nil {
		return "", err
	}
	a.samlAuthnInFlight.Store(req.ID, time.Now().Add(a.samlCfg.AuthnRequestTTL))
	redirectURL, err := req.Redirect(relayState, sp)
	if err != nil {
		return "", err
	}
	return redirectURL.String(), nil
}

// FinishSAMLLogin validates an inbound SAMLResponse, runs find-or-create,
// issues a session, and returns its token. ua + ip annotate the session
// for audit.
func (a *TheAuth) FinishSAMLLogin(ctx context.Context, connectionID ULID, samlResponseB64 string, ua, ip string) (string, Session, error) {
	conn, err := a.storage.SAMLConnectionByID(ctx, connectionID)
	if err != nil {
		return "", Session{}, err
	}
	sp, err := a.samlServiceProviderFor(conn)
	if err != nil {
		return "", Session{}, err
	}

	// Collect outstanding request IDs for replay protection. The IdP-
	// initiated path passes an empty slice so the library accepts the
	// assertion as unsolicited (AllowIDPInitiated is on in our SP builder).
	ids := a.outstandingAuthnRequestIDs()

	rawBytes, err := base64.StdEncoding.DecodeString(samlResponseB64)
	if err != nil {
		return "", Session{}, fmt.Errorf("theauth: saml response base64 decode: %w", err)
	}
	acsURL, err := url.Parse(conn.SPACSURL)
	if err != nil {
		return "", Session{}, fmt.Errorf("theauth: sp acs url invalid: %w", err)
	}
	assertion, err := sp.ParseXMLResponse(rawBytes, ids, *acsURL)
	if err != nil {
		return "", Session{}, errors.Join(ErrSAMLInvalidAssertion, err)
	}

	// Once an InResponseTo lands, consume it so a replay against the same
	// ID is rejected on the second hit (the library refuses an unknown
	// InResponseTo when the slice is non-empty).
	if assertion.Subject != nil && assertion.Subject.SubjectConfirmations != nil {
		for _, sc := range assertion.Subject.SubjectConfirmations {
			if sc.SubjectConfirmationData != nil && sc.SubjectConfirmationData.InResponseTo != "" {
				a.samlAuthnInFlight.Delete(sc.SubjectConfirmationData.InResponseTo)
			}
		}
	}

	// Explicit "assertion must be signed" gate per spec note 2 of v0.7.
	if !assertionIsSigned(assertion) {
		return "", Session{}, ErrSAMLUnsignedAssertion
	}

	mapped := mapAssertion(conn, assertion)
	if mapped.Email == "" {
		return "", Session{}, ErrSAMLMissingEmail
	}

	user, isNew, err := a.findOrCreateSAMLUser(ctx, conn, assertion, mapped)
	if err != nil {
		return "", Session{}, err
	}
	_ = isNew

	// Issue session bound to the connection's organization (active org).
	token, sess, err := a.issueSAMLSession(ctx, user, conn.OrganizationID, ua, ip)
	if err != nil {
		return "", Session{}, err
	}

	// Audit hook (stub for v0.7; real writer in v1.0).
	a.auditHook(ctx, AuditEvent{
		Action:         "saml.login",
		OrganizationID: conn.OrganizationID,
		ActorID:        conn.ID,
		ResourceID:     user.ID,
		Detail:         "saml login",
		At:             time.Now(),
	})

	return token, sess, nil
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

func mapAssertion(conn *SAMLConnection, a *saml.Assertion) mappedAttrs {
	defaults := DefaultSAMLAttributeMap()
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

// assertionIsSigned verifies that the assertion carries an XML Signature
// element. crewjam/saml validates the signature at parse time when the SP
// is configured to do so; this gate makes the requirement explicit so a
// future library default flip cannot silently accept unsigned assertions.
func assertionIsSigned(a *saml.Assertion) bool {
	if a == nil || a.Signature == nil {
		return false
	}
	// etree.Element.FindElement("./SignedInfo") returns non-nil only when
	// the assertion was actually signed (the signature element carries a
	// SignedInfo child by definition).
	return a.Signature.FindElement("./SignedInfo") != nil
}

// findOrCreateSAMLUser resolves the find-or-create cascade documented in
// section 8 of the v0.7 spec.
func (a *TheAuth) findOrCreateSAMLUser(ctx context.Context, conn *SAMLConnection, assertion *saml.Assertion, mapped mappedAttrs) (User, bool, error) {
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
	if ident, err := a.storage.SAMLIdentityByConnectionAndNameID(ctx, conn.ID, nameID); err == nil {
		user, err := a.storage.UserByID(ctx, ident.UserID)
		if err != nil {
			return User{}, false, err
		}
		_ = a.storage.TouchSAMLIdentityLastLogin(ctx, ident.ID, time.Now())
		return *user, false, nil
	} else if !errors.Is(err, ErrStorageNotFound) {
		return User{}, false, err
	}

	// Branch 2: email fallback. If a user already exists with the mapped
	// email, link them to this connection and ensure org membership.
	if user, err := a.storage.UserByEmail(ctx, mapped.Email); err == nil {
		if err := a.ensureOrgMembership(ctx, conn.OrganizationID, user.ID); err != nil {
			return User{}, false, err
		}
		if _, err := a.storage.UpsertSAMLIdentity(ctx, SAMLIdentity{
			ID:           ulid.New(),
			ConnectionID: conn.ID,
			UserID:       user.ID,
			NameID:       nameID,
			NameIDFormat: nameIDFormat,
		}); err != nil {
			return User{}, false, err
		}
		return *user, false, nil
	} else if !errors.Is(err, ErrStorageNotFound) {
		return User{}, false, err
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
	u := User{
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
	created, err := a.storage.CreateUser(ctx, u)
	if err != nil {
		return User{}, false, err
	}
	if err := a.storage.UpsertOrganizationMember(ctx, OrganizationMember{
		OrganizationID: conn.OrganizationID,
		UserID:         created.ID,
		Role:           OrgRoleMember,
	}); err != nil {
		return User{}, false, err
	}
	if _, err := a.storage.UpsertSAMLIdentity(ctx, SAMLIdentity{
		ID:           ulid.New(),
		ConnectionID: conn.ID,
		UserID:       created.ID,
		NameID:       nameID,
		NameIDFormat: nameIDFormat,
	}); err != nil {
		return User{}, false, err
	}
	return created, true, nil
}

// ensureOrgMembership upserts a "member" role row when the user is not
// already a member of the supplied organization.
func (a *TheAuth) ensureOrgMembership(ctx context.Context, orgID, userID ULID) error {
	_, err := a.storage.OrganizationMemberRole(ctx, orgID, userID)
	if err == nil {
		return nil
	}
	if !errors.Is(err, ErrStorageNotFound) {
		return err
	}
	return a.storage.UpsertOrganizationMember(ctx, OrganizationMember{
		OrganizationID: orgID,
		UserID:         userID,
		Role:           OrgRoleMember,
	})
}

// outstandingAuthnRequestIDs returns the IDs of every AuthnRequest still
// inside its TTL. Used to drive crewjam/saml's InResponseTo validation.
func (a *TheAuth) outstandingAuthnRequestIDs() []string {
	now := time.Now()
	var ids []string
	a.samlAuthnInFlight.Range(func(k, v interface{}) bool {
		deadline, ok := v.(time.Time)
		if !ok || now.After(deadline) {
			a.samlAuthnInFlight.Delete(k)
			return true
		}
		if id, ok := k.(string); ok {
			ids = append(ids, id)
		}
		return true
	})
	return ids
}

// issueSAMLSession mints a session with the supplied active org pre-set.
func (a *TheAuth) issueSAMLSession(ctx context.Context, user User, orgID ULID, ua, ip string) (string, Session, error) {
	token, sess, err := a.issueSession(ctx, user, ua, ip)
	if err != nil {
		return "", Session{}, err
	}
	id := orgID
	if err := a.storage.SetSessionActiveOrganization(ctx, sess.ID, &id); err != nil {
		return "", Session{}, err
	}
	sess.ActiveOrganizationID = &id
	return token, sess, nil
}

// SAMLMetadataXML serialises the per-connection SP metadata as XML, ready
// to hand to an IdP admin.
func (a *TheAuth) SAMLMetadataXML(ctx context.Context, connectionID ULID) ([]byte, error) {
	conn, err := a.storage.SAMLConnectionByID(ctx, connectionID)
	if err != nil {
		return nil, err
	}
	sp, err := a.samlServiceProviderFor(conn)
	if err != nil {
		return nil, err
	}
	md := sp.Metadata()
	return xml.MarshalIndent(md, "", "  ")
}

func validateSAMLInput(in SAMLConnectionInput) error {
	if in.OrganizationID == (ULID{}) {
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
		// The find-or-create email fallback path keys on email; refuse to
		// store a map that would always go down the "missing email" branch.
		// Per the v0.7 spec defaults still apply when the field is empty,
		// so we only enforce non-empty here if the consumer passes a
		// partial map that wipes the default.
		in.AttributeMap.Email = DefaultSAMLAttributeMap().Email
	}
	return nil
}

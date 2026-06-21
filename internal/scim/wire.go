package scim

import (
	"encoding/json"
	"strings"
	"time"

	"github.com/glincker/theauth-go/internal/models"
)

// SCIM 2.0 wire formats and resource mapping. RFC 7643 (Core Schema)
// and RFC 7644 (Protocol). Lifted from root scim.go in PR F of the
// 2026-06 architecture reorg so the extracted internal/scim/handlers
// package can use them without re-implementing the projection layer.

// Wire-level constants and schema URIs.
const (
	ContentType    = "application/scim+json"
	ErrorSchema    = "urn:ietf:params:scim:api:messages:2.0:Error"
	ListSchema     = "urn:ietf:params:scim:api:messages:2.0:ListResponse"
	PatchSchema    = "urn:ietf:params:scim:api:messages:2.0:PatchOp"
	UserSchema     = "urn:ietf:params:scim:schemas:core:2.0:User"
	GroupSchema    = "urn:ietf:params:scim:schemas:core:2.0:Group"
	SPConfigSchema = "urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig"
	ResTypeSchema  = "urn:ietf:params:scim:schemas:core:2.0:ResourceType"
	SchemaSchema   = "urn:ietf:params:scim:schemas:core:2.0:Schema"
)

// Error is the wire format for SCIM 2.0 error responses (RFC 7644 §3.12).
type Error struct {
	Schemas  []string `json:"schemas"`
	Status   string   `json:"status"`
	ScimType string   `json:"scimType,omitempty"`
	Detail   string   `json:"detail,omitempty"`
}

// NewError constructs a SCIM error body with the canonical schema URN.
func NewError(status int, scimType, detail string) Error {
	return Error{
		Schemas:  []string{ErrorSchema},
		Status:   itoa(status),
		ScimType: scimType,
		Detail:   detail,
	}
}

// UserResource is the wire format for a SCIM User. We only emit a
// subset of RFC 7643 §4.1; see v0.7 spec §6.1 for the deviations.
type UserResource struct {
	Schemas     []string    `json:"schemas"`
	ID          string      `json:"id"`
	ExternalID  string      `json:"externalId,omitempty"`
	UserName    string      `json:"userName"`
	Name        *UserName   `json:"name,omitempty"`
	DisplayName string      `json:"displayName,omitempty"`
	Emails      []UserEmail `json:"emails,omitempty"`
	Active      bool        `json:"active"`
	Meta        Meta        `json:"meta"`
	Groups      []GroupRef  `json:"groups,omitempty"`
}

// UserName is the structured name subobject inside a UserResource.
type UserName struct {
	Formatted  string `json:"formatted,omitempty"`
	GivenName  string `json:"givenName,omitempty"`
	FamilyName string `json:"familyName,omitempty"`
}

// UserEmail is one element of UserResource.Emails.
type UserEmail struct {
	Value   string `json:"value"`
	Type    string `json:"type,omitempty"`
	Primary bool   `json:"primary,omitempty"`
}

// GroupRef is one $ref-style member of a GroupResource.
type GroupRef struct {
	Value   string `json:"value"`
	Ref     string `json:"$ref,omitempty"`
	Display string `json:"display,omitempty"`
	Type    string `json:"type,omitempty"`
}

// Meta is the common SCIM meta block.
type Meta struct {
	ResourceType string    `json:"resourceType"`
	Created      time.Time `json:"created,omitempty"`
	LastModified time.Time `json:"lastModified,omitempty"`
	Location     string    `json:"location,omitempty"`
	Version      string    `json:"version,omitempty"`
}

// GroupResource is the wire format for a SCIM Group (RFC 7643 §4.2).
type GroupResource struct {
	Schemas     []string   `json:"schemas"`
	ID          string     `json:"id"`
	ExternalID  string     `json:"externalId,omitempty"`
	DisplayName string     `json:"displayName"`
	Members     []GroupRef `json:"members,omitempty"`
	Meta        Meta       `json:"meta"`
}

// ListResponse wraps a list endpoint payload.
type ListResponse struct {
	Schemas      []string          `json:"schemas"`
	TotalResults int               `json:"totalResults"`
	StartIndex   int               `json:"startIndex"`
	ItemsPerPage int               `json:"itemsPerPage"`
	Resources    []json.RawMessage `json:"Resources"`
}

// UserToSCIM projects a domain User into the SCIM wire format.
func UserToSCIM(u models.User, baseURL string) UserResource {
	res := UserResource{
		Schemas:    []string{UserSchema},
		ID:         u.ID.String(),
		ExternalID: u.ExternalID,
		UserName:   u.Email,
		Active:     true,
		Emails: []UserEmail{
			{Value: u.Email, Type: "work", Primary: true},
		},
		DisplayName: NonEmpty(u.DisplayName, u.Name),
		Meta: Meta{
			ResourceType: "User",
			Created:      u.CreatedAt,
			LastModified: u.UpdatedAt,
			Location:     baseURL + "/scim/v2/Users/" + u.ID.String(),
		},
	}
	if u.GivenName != "" || u.FamilyName != "" || u.Name != "" {
		res.Name = &UserName{
			Formatted:  NonEmpty(u.Name, u.DisplayName),
			GivenName:  u.GivenName,
			FamilyName: u.FamilyName,
		}
	}
	return res
}

// GroupToSCIM projects a domain Group into the SCIM wire format.
func GroupToSCIM(g models.Group, members []models.ULID, baseURL string) GroupResource {
	res := GroupResource{
		Schemas:     []string{GroupSchema},
		ID:          g.ID.String(),
		ExternalID:  g.ExternalID,
		DisplayName: g.DisplayName,
		Meta: Meta{
			ResourceType: "Group",
			Created:      g.CreatedAt,
			LastModified: g.UpdatedAt,
			Location:     baseURL + "/scim/v2/Groups/" + g.ID.String(),
		},
	}
	for _, m := range members {
		res.Members = append(res.Members, GroupRef{
			Value: m.String(),
			Ref:   baseURL + "/scim/v2/Users/" + m.String(),
			Type:  "User",
		})
	}
	return res
}

// PatchOp is one entry in a PATCH Operations array (RFC 7644 §3.5.2).
type PatchOp struct {
	Op    string          `json:"op"`
	Path  string          `json:"path,omitempty"`
	Value json.RawMessage `json:"value,omitempty"`
}

// PatchRequest is the top-level PATCH body shape.
type PatchRequest struct {
	Schemas    []string  `json:"schemas"`
	Operations []PatchOp `json:"Operations"`
}

// itoa converts an int status code to its string form without bringing
// in strconv for a couple of call sites.
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		buf[i] = '-'
	}
	return string(buf[i:])
}

// NonEmpty returns a when non-empty, otherwise b.
func NonEmpty(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

// ParsePrimaryEmail extracts the primary email (or the first one when
// none is flagged primary) from a SCIM emails array, lowercased.
func ParsePrimaryEmail(emails []UserEmail) string {
	for _, e := range emails {
		if e.Primary {
			return strings.ToLower(e.Value)
		}
	}
	if len(emails) > 0 {
		return strings.ToLower(emails[0].Value)
	}
	return ""
}

// ---------- ServiceProviderConfig, ResourceTypes, Schemas (RFC 7644 §5/§6) ----------

// ServiceProviderConfig returns the SCIM 2.0 ServiceProviderConfig
// document body.
func ServiceProviderConfig(maxResults int) map[string]interface{} {
	return map[string]interface{}{
		"schemas":          []string{SPConfigSchema},
		"documentationUri": "https://github.com/glincker/theauth-go/blob/main/docs/SCIM.md",
		"patch":            map[string]interface{}{"supported": true},
		"bulk":             map[string]interface{}{"supported": false, "maxOperations": 0, "maxPayloadSize": 0},
		"filter":           map[string]interface{}{"supported": true, "maxResults": maxResults},
		"changePassword":   map[string]interface{}{"supported": false},
		"sort":             map[string]interface{}{"supported": false},
		"etag":             map[string]interface{}{"supported": false},
		"authenticationSchemes": []map[string]interface{}{
			{
				"type":        "oauthbearertoken",
				"name":        "OAuth Bearer Token",
				"description": "Authentication scheme using the OAuth Bearer Token Standard",
				"specUri":     "https://www.rfc-editor.org/info/rfc6750",
				"primary":     true,
			},
		},
	}
}

// ResourceTypes returns the SCIM 2.0 ResourceTypes list.
func ResourceTypes(baseURL string) []map[string]interface{} {
	return []map[string]interface{}{
		ResourceTypeUser(baseURL),
		ResourceTypeGroup(baseURL),
	}
}

// ResourceTypeUser returns the SCIM 2.0 User resource type document.
func ResourceTypeUser(baseURL string) map[string]interface{} {
	return map[string]interface{}{
		"schemas":     []string{ResTypeSchema},
		"id":          "User",
		"name":        "User",
		"endpoint":    "/Users",
		"description": "User account",
		"schema":      UserSchema,
		"meta": map[string]interface{}{
			"resourceType": "ResourceType",
			"location":     baseURL + "/scim/v2/ResourceTypes/User",
		},
	}
}

// ResourceTypeGroup returns the SCIM 2.0 Group resource type document.
func ResourceTypeGroup(baseURL string) map[string]interface{} {
	return map[string]interface{}{
		"schemas":     []string{ResTypeSchema},
		"id":          "Group",
		"name":        "Group",
		"endpoint":    "/Groups",
		"description": "Group of users",
		"schema":      GroupSchema,
		"meta": map[string]interface{}{
			"resourceType": "ResourceType",
			"location":     baseURL + "/scim/v2/ResourceTypes/Group",
		},
	}
}

// Schemas returns the User + Group schema documents.
func Schemas(baseURL string) []map[string]interface{} {
	return []map[string]interface{}{
		SchemaUser(baseURL),
		SchemaGroup(baseURL),
	}
}

// SchemaUser returns the SCIM 2.0 User schema document.
func SchemaUser(baseURL string) map[string]interface{} {
	return map[string]interface{}{
		"id":          UserSchema,
		"name":        "User",
		"description": "User Account",
		"attributes": []map[string]interface{}{
			{"name": "userName", "type": "string", "required": true, "uniqueness": "server"},
			{"name": "displayName", "type": "string"},
			{"name": "active", "type": "boolean"},
			{"name": "externalId", "type": "string"},
			{"name": "emails", "type": "complex", "multiValued": true, "subAttributes": []map[string]interface{}{
				{"name": "value", "type": "string"},
				{"name": "type", "type": "string"},
				{"name": "primary", "type": "boolean"},
			}},
			{"name": "name", "type": "complex", "subAttributes": []map[string]interface{}{
				{"name": "formatted", "type": "string"},
				{"name": "givenName", "type": "string"},
				{"name": "familyName", "type": "string"},
			}},
		},
		"meta": map[string]interface{}{
			"resourceType": "Schema",
			"location":     baseURL + "/scim/v2/Schemas/" + UserSchema,
		},
	}
}

// SchemaGroup returns the SCIM 2.0 Group schema document.
func SchemaGroup(baseURL string) map[string]interface{} {
	return map[string]interface{}{
		"id":          GroupSchema,
		"name":        "Group",
		"description": "Group of users",
		"attributes": []map[string]interface{}{
			{"name": "displayName", "type": "string", "required": true},
			{"name": "externalId", "type": "string"},
			{"name": "members", "type": "complex", "multiValued": true, "subAttributes": []map[string]interface{}{
				{"name": "value", "type": "string"},
				{"name": "type", "type": "string"},
				{"name": "$ref", "type": "string"},
			}},
		},
		"meta": map[string]interface{}{
			"resourceType": "Schema",
			"location":     baseURL + "/scim/v2/Schemas/" + GroupSchema,
		},
	}
}

// ParseUserFilter accepts the equality-only filter subset documented in
// v0.7 section 6.4 and returns a models.SCIMUserFilter. Any other shape
// returns ErrUnsupportedFilter.
func ParseUserFilter(s string) (models.SCIMUserFilter, error) {
	var out models.SCIMUserFilter
	field, value, err := ParseEqFilter(s)
	if err != nil {
		return out, err
	}
	if field == "" {
		return out, nil
	}
	switch field {
	case "userName":
		out.UserName = value
	case "externalId":
		out.ExternalID = value
	case "emails.value":
		out.Email = value
	default:
		return out, ErrUnsupportedFilter
	}
	return out, nil
}

// ParseGroupFilter accepts the equality-only filter subset for groups.
func ParseGroupFilter(s string) (models.SCIMGroupFilter, error) {
	var out models.SCIMGroupFilter
	field, value, err := ParseEqFilter(s)
	if err != nil {
		return out, err
	}
	if field == "" {
		return out, nil
	}
	switch field {
	case "displayName":
		out.DisplayName = value
	case "externalId":
		out.ExternalID = value
	default:
		return out, ErrUnsupportedFilter
	}
	return out, nil
}

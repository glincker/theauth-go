package theauth

import (
	"encoding/json"
	"strings"
	"time"
)

// SCIM 2.0 wire formats and resource mapping. RFC 7643 (Core Schema) and
// RFC 7644 (Protocol). Resources are emitted with the "schemas" array
// containing the core User or Group URN exactly; we do not advertise the
// Enterprise User extension because v0.7 does not store its attributes.

const (
	scimContentType    = "application/scim+json"
	scimErrorSchema    = "urn:ietf:params:scim:api:messages:2.0:Error"
	scimListSchema     = "urn:ietf:params:scim:api:messages:2.0:ListResponse"
	scimPatchSchema    = "urn:ietf:params:scim:api:messages:2.0:PatchOp"
	scimUserSchema     = "urn:ietf:params:scim:schemas:core:2.0:User"
	scimGroupSchema    = "urn:ietf:params:scim:schemas:core:2.0:Group"
	scimSPConfigSchema = "urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig"
	scimResTypeSchema  = "urn:ietf:params:scim:schemas:core:2.0:ResourceType"
	scimSchemaSchema   = "urn:ietf:params:scim:schemas:core:2.0:Schema"
)

// scimError is the wire format for SCIM 2.0 error responses (RFC 7644 §3.12).
type scimError struct {
	Schemas  []string `json:"schemas"`
	Status   string   `json:"status"`
	ScimType string   `json:"scimType,omitempty"`
	Detail   string   `json:"detail,omitempty"`
}

func newSCIMError(status int, scimType, detail string) scimError {
	return scimError{
		Schemas:  []string{scimErrorSchema},
		Status:   itoa(status),
		ScimType: scimType,
		Detail:   detail,
	}
}

// scimUserResource is the wire format for a SCIM User. We only emit a
// subset of RFC 7643 §4.1; see v0.7 spec §6.1 for the deviations.
type scimUserResource struct {
	Schemas     []string        `json:"schemas"`
	ID          string          `json:"id"`
	ExternalID  string          `json:"externalId,omitempty"`
	UserName    string          `json:"userName"`
	Name        *scimUserName   `json:"name,omitempty"`
	DisplayName string          `json:"displayName,omitempty"`
	Emails      []scimUserEmail `json:"emails,omitempty"`
	Active      bool            `json:"active"`
	Meta        scimMeta        `json:"meta"`
	Groups      []scimGroupRef  `json:"groups,omitempty"`
}

type scimUserName struct {
	Formatted  string `json:"formatted,omitempty"`
	GivenName  string `json:"givenName,omitempty"`
	FamilyName string `json:"familyName,omitempty"`
}

type scimUserEmail struct {
	Value   string `json:"value"`
	Type    string `json:"type,omitempty"`
	Primary bool   `json:"primary,omitempty"`
}

type scimGroupRef struct {
	Value   string `json:"value"`
	Ref     string `json:"$ref,omitempty"`
	Display string `json:"display,omitempty"`
	Type    string `json:"type,omitempty"`
}

type scimMeta struct {
	ResourceType string    `json:"resourceType"`
	Created      time.Time `json:"created,omitempty"`
	LastModified time.Time `json:"lastModified,omitempty"`
	Location     string    `json:"location,omitempty"`
	Version      string    `json:"version,omitempty"`
}

// scimGroupResource is the wire format for a SCIM Group (RFC 7643 §4.2).
type scimGroupResource struct {
	Schemas     []string       `json:"schemas"`
	ID          string         `json:"id"`
	ExternalID  string         `json:"externalId,omitempty"`
	DisplayName string         `json:"displayName"`
	Members     []scimGroupRef `json:"members,omitempty"`
	Meta        scimMeta       `json:"meta"`
}

// scimListResponse wraps a list endpoint payload.
type scimListResponse struct {
	Schemas      []string          `json:"schemas"`
	TotalResults int               `json:"totalResults"`
	StartIndex   int               `json:"startIndex"`
	ItemsPerPage int               `json:"itemsPerPage"`
	Resources    []json.RawMessage `json:"Resources"`
}

// userToSCIM projects a domain User into the SCIM wire format. baseURL is
// the absolute origin used to build meta.location; resourceID is the
// already-formatted ULID string.
func userToSCIM(u User, baseURL string) scimUserResource {
	res := scimUserResource{
		Schemas:    []string{scimUserSchema},
		ID:         u.ID.String(),
		ExternalID: u.ExternalID,
		UserName:   u.Email,
		Active:     true,
		Emails: []scimUserEmail{
			{Value: u.Email, Type: "work", Primary: true},
		},
		DisplayName: nonEmpty(u.DisplayName, u.Name),
		Meta: scimMeta{
			ResourceType: "User",
			Created:      u.CreatedAt,
			LastModified: u.UpdatedAt,
			Location:     baseURL + "/scim/v2/Users/" + u.ID.String(),
		},
	}
	if u.GivenName != "" || u.FamilyName != "" || u.Name != "" {
		res.Name = &scimUserName{
			Formatted:  nonEmpty(u.Name, u.DisplayName),
			GivenName:  u.GivenName,
			FamilyName: u.FamilyName,
		}
	}
	return res
}

// groupToSCIM projects a domain Group into the SCIM wire format.
func groupToSCIM(g Group, members []ULID, baseURL string) scimGroupResource {
	res := scimGroupResource{
		Schemas:     []string{scimGroupSchema},
		ID:          g.ID.String(),
		ExternalID:  g.ExternalID,
		DisplayName: g.DisplayName,
		Meta: scimMeta{
			ResourceType: "Group",
			Created:      g.CreatedAt,
			LastModified: g.UpdatedAt,
			Location:     baseURL + "/scim/v2/Groups/" + g.ID.String(),
		},
	}
	for _, m := range members {
		res.Members = append(res.Members, scimGroupRef{
			Value: m.String(),
			Ref:   baseURL + "/scim/v2/Users/" + m.String(),
			Type:  "User",
		})
	}
	return res
}

// scimPatchOp is one entry in a PATCH Operations array (RFC 7644 §3.5.2).
type scimPatchOp struct {
	Op    string          `json:"op"`
	Path  string          `json:"path,omitempty"`
	Value json.RawMessage `json:"value,omitempty"`
}

type scimPatchRequest struct {
	Schemas    []string      `json:"schemas"`
	Operations []scimPatchOp `json:"Operations"`
}

// itoa converts an int status code to its string form without bringing in
// strconv for a couple of call sites.
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

func nonEmpty(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

// ---------- ServiceProviderConfig, ResourceTypes, Schemas (RFC 7644 §5/§6) ----------

func scimServiceProviderConfig(maxResults int) map[string]interface{} {
	return map[string]interface{}{
		"schemas":          []string{scimSPConfigSchema},
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

func scimResourceTypes(baseURL string) []map[string]interface{} {
	return []map[string]interface{}{
		scimResourceTypeUser(baseURL),
		scimResourceTypeGroup(baseURL),
	}
}

func scimResourceTypeUser(baseURL string) map[string]interface{} {
	return map[string]interface{}{
		"schemas":     []string{scimResTypeSchema},
		"id":          "User",
		"name":        "User",
		"endpoint":    "/Users",
		"description": "User account",
		"schema":      scimUserSchema,
		"meta": map[string]interface{}{
			"resourceType": "ResourceType",
			"location":     baseURL + "/scim/v2/ResourceTypes/User",
		},
	}
}

func scimResourceTypeGroup(baseURL string) map[string]interface{} {
	return map[string]interface{}{
		"schemas":     []string{scimResTypeSchema},
		"id":          "Group",
		"name":        "Group",
		"endpoint":    "/Groups",
		"description": "Group of users",
		"schema":      scimGroupSchema,
		"meta": map[string]interface{}{
			"resourceType": "ResourceType",
			"location":     baseURL + "/scim/v2/ResourceTypes/Group",
		},
	}
}

func scimSchemas(baseURL string) []map[string]interface{} {
	return []map[string]interface{}{
		scimSchemaUser(baseURL),
		scimSchemaGroup(baseURL),
	}
}

func scimSchemaUser(baseURL string) map[string]interface{} {
	return map[string]interface{}{
		"id":          scimUserSchema,
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
			"location":     baseURL + "/scim/v2/Schemas/" + scimUserSchema,
		},
	}
}

func scimSchemaGroup(baseURL string) map[string]interface{} {
	return map[string]interface{}{
		"id":          scimGroupSchema,
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
			"location":     baseURL + "/scim/v2/Schemas/" + scimGroupSchema,
		},
	}
}

// parsePrimaryEmail picks the entry marked primary, or the first entry, or
// the empty string when no emails are supplied.
func parsePrimaryEmail(emails []scimUserEmail) string {
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

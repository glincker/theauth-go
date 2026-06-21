package scim

import (
	"encoding/json"
	"errors"
	"strings"

	"github.com/glincker/theauth-go/internal/models"
	"github.com/oklog/ulid/v2"
)

// ApplyUserPatch applies a sequence of PATCH operations to a User.
// Supported ops: replace and add against the attribute paths active,
// userName, displayName, externalId, name.givenName, name.familyName,
// name.formatted, name, emails. remove against active flips the user
// to inactive (the handler maps this to membership removal).
//
// On an unsupported path or op we return ErrUnsupportedFilter (reused
// here as a generic "this PATCH is outside our subset" signal); the
// handler maps it to 400 invalidValue.
func ApplyUserPatch(u *models.User, ops []PatchOp, activeOut *bool) error {
	for _, op := range ops {
		opName := strings.ToLower(op.Op)
		path := op.Path
		switch opName {
		case "replace", "add":
			if err := applyUserSet(u, activeOut, path, op.Value); err != nil {
				return err
			}
		case "remove":
			if err := applyUserRemove(u, activeOut, path); err != nil {
				return err
			}
		default:
			return ErrUnsupportedFilter
		}
	}
	return nil
}

func applyUserSet(u *models.User, activeOut *bool, path string, value json.RawMessage) error {
	if path == "" {
		var obj map[string]json.RawMessage
		if err := json.Unmarshal(value, &obj); err != nil {
			return err
		}
		for k, raw := range obj {
			if err := applyUserSet(u, activeOut, k, raw); err != nil {
				return err
			}
		}
		return nil
	}
	switch path {
	case "active":
		var b bool
		if err := json.Unmarshal(value, &b); err != nil {
			return err
		}
		*activeOut = b
	case "userName":
		var s string
		if err := json.Unmarshal(value, &s); err != nil {
			return err
		}
		u.Email = strings.ToLower(s)
	case "displayName":
		var s string
		if err := json.Unmarshal(value, &s); err != nil {
			return err
		}
		u.DisplayName = s
		if u.Name == "" {
			u.Name = s
		}
	case "externalId":
		var s string
		if err := json.Unmarshal(value, &s); err != nil {
			return err
		}
		u.ExternalID = s
	case "name.givenName":
		var s string
		if err := json.Unmarshal(value, &s); err != nil {
			return err
		}
		u.GivenName = s
	case "name.familyName":
		var s string
		if err := json.Unmarshal(value, &s); err != nil {
			return err
		}
		u.FamilyName = s
	case "name.formatted":
		var s string
		if err := json.Unmarshal(value, &s); err != nil {
			return err
		}
		u.Name = s
	case "name":
		var n UserName
		if err := json.Unmarshal(value, &n); err != nil {
			return err
		}
		if n.GivenName != "" {
			u.GivenName = n.GivenName
		}
		if n.FamilyName != "" {
			u.FamilyName = n.FamilyName
		}
		if n.Formatted != "" {
			u.Name = n.Formatted
		}
	case "emails":
		var emails []UserEmail
		if err := json.Unmarshal(value, &emails); err != nil {
			return err
		}
		if e := ParsePrimaryEmail(emails); e != "" {
			u.Email = e
		}
	default:
		return ErrUnsupportedFilter
	}
	return nil
}

func applyUserRemove(u *models.User, activeOut *bool, path string) error {
	switch path {
	case "active":
		*activeOut = false
	case "externalId":
		u.ExternalID = ""
	case "displayName":
		u.DisplayName = ""
	default:
		return ErrUnsupportedFilter
	}
	_ = u
	return nil
}

// ApplyGroupPatch returns the lists of members to add or remove for a
// PATCH against a Group's members attribute. Other paths are not
// implemented; v0.7 only needs displayName replace and members
// add/remove for the Okta / Azure AD provisioning cycle.
func ApplyGroupPatch(g *models.Group, ops []PatchOp) (addUsers []models.ULID, removeUsers []models.ULID, err error) {
	for _, op := range ops {
		opName := strings.ToLower(op.Op)
		path := op.Path
		switch {
		case path == "displayName" && (opName == "replace" || opName == "add"):
			var s string
			if uerr := json.Unmarshal(op.Value, &s); uerr != nil {
				return nil, nil, uerr
			}
			g.DisplayName = s
		case path == "externalId" && (opName == "replace" || opName == "add"):
			var s string
			if uerr := json.Unmarshal(op.Value, &s); uerr != nil {
				return nil, nil, uerr
			}
			g.ExternalID = s
		case path == "members" && opName == "add":
			ids, terr := parseGroupMemberRefs(op.Value)
			if terr != nil {
				return nil, nil, terr
			}
			addUsers = append(addUsers, ids...)
		case path == "members" && opName == "remove":
			ids, terr := parseGroupMemberRefs(op.Value)
			if terr != nil {
				return nil, nil, terr
			}
			removeUsers = append(removeUsers, ids...)
		case path == "members" && opName == "replace":
			ids, terr := parseGroupMemberRefs(op.Value)
			if terr != nil {
				return nil, nil, terr
			}
			removeUsers = append(removeUsers, SentinelClearAll)
			addUsers = append(addUsers, ids...)
		default:
			return nil, nil, ErrUnsupportedFilter
		}
	}
	return addUsers, removeUsers, nil
}

// SentinelClearAll is a placeholder ULID used to signal "wipe the
// member set before applying the add list". The handler treats the
// presence of this ULID in the remove list as "call SetGroupMembers
// with addUsers".
var SentinelClearAll = models.ULID{}

// parseGroupMemberRefs reads a SCIM PATCH members value (either a
// single object or an array of objects) and returns the contained
// ULIDs. Rejects nested groups (type=="Group") per v0.7 §6.2
// deviation.
func parseGroupMemberRefs(raw json.RawMessage) ([]models.ULID, error) {
	if len(raw) == 0 {
		return nil, errors.New("empty members value")
	}
	var arr []GroupRef
	if err := json.Unmarshal(raw, &arr); err == nil {
		return resolveRefs(arr)
	}
	var one GroupRef
	if err := json.Unmarshal(raw, &one); err != nil {
		return nil, err
	}
	return resolveRefs([]GroupRef{one})
}

func resolveRefs(refs []GroupRef) ([]models.ULID, error) {
	out := make([]models.ULID, 0, len(refs))
	for _, r := range refs {
		if strings.EqualFold(r.Type, "Group") {
			return nil, ErrUnsupportedFilter
		}
		id, err := ulid.Parse(r.Value)
		if err != nil {
			return nil, err
		}
		out = append(out, id)
	}
	return out, nil
}

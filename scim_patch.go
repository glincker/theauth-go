package theauth

import (
	"encoding/json"
	"errors"
	"strings"
)

// applySCIMUserPatch applies a sequence of PATCH operations to a User.
// Supported ops: replace and add against the attribute paths active,
// userName, displayName, externalId, name.givenName, name.familyName,
// name.formatted, emails. remove against active flips the user to
// inactive (which the handler maps to membership removal).
//
// On an unsupported path or op we return ErrUnsupportedFilter (reused
// here as a generic "this PATCH is outside our subset" signal); the
// handler maps it to 400 invalidValue.
func applySCIMUserPatch(u *User, ops []scimPatchOp, activeOut *bool) error {
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

func applyUserSet(u *User, activeOut *bool, path string, value json.RawMessage) error {
	// PATCH ops without a path put the full object literal in Value (and
	// the SCIM spec defines that as a merge against the top-level
	// resource). We handle the common Okta / Azure AD shape of "replace
	// the active flag at the root via a value object".
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
		var n scimUserName
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
		var emails []scimUserEmail
		if err := json.Unmarshal(value, &emails); err != nil {
			return err
		}
		if e := parsePrimaryEmail(emails); e != "" {
			u.Email = e
		}
	default:
		return ErrUnsupportedFilter
	}
	return nil
}

func applyUserRemove(u *User, activeOut *bool, path string) error {
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

// applySCIMGroupPatch returns the lists of members to add or remove for a
// PATCH against a Group's members attribute. Other paths are not
// implemented; v0.7 only needs displayName replace and members add/remove
// for the Okta / Azure AD provisioning cycle.
func applySCIMGroupPatch(g *Group, ops []scimPatchOp) (addUsers []ULID, removeUsers []ULID, err error) {
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
			// Replace is "swap to this exact set"; we model that by
			// signalling the entire desired set as adds + a sentinel.
			// The handler interprets a replace by calling SetGroupMembers
			// directly; here we just return the new set as the "add" list
			// and an explicit empty remove. The handler must distinguish
			// replace from add. To keep the shape simple, we forbid
			// replace at the path level by returning errors.New so callers
			// that intentionally PUT-via-PATCH (Azure AD does this) can
			// fall back to a separate code path. For v0.7 we accept it as
			// "remove all, then add these".
			removeUsers = append(removeUsers, sentinelClearAll)
			addUsers = append(addUsers, ids...)
		default:
			return nil, nil, ErrUnsupportedFilter
		}
	}
	return addUsers, removeUsers, nil
}

// sentinelClearAll is a placeholder ULID used to signal "wipe the member
// set before applying the add list". The handler treats the presence of
// this ULID in the remove list as "call SetGroupMembers with addUsers".
var sentinelClearAll = ULID{}

// parseGroupMemberRefs reads a SCIM PATCH members value (either a
// single object or an array of objects) and returns the contained ULIDs.
// Rejects nested groups (type=="Group") per v0.7 §6.2 deviation.
func parseGroupMemberRefs(raw json.RawMessage) ([]ULID, error) {
	if len(raw) == 0 {
		return nil, errors.New("empty members value")
	}
	// Try array first; SCIM PATCH on multi-valued attributes is canonical
	// in the array form.
	var arr []scimGroupRef
	if err := json.Unmarshal(raw, &arr); err == nil {
		return resolveRefs(arr)
	}
	var one scimGroupRef
	if err := json.Unmarshal(raw, &one); err != nil {
		return nil, err
	}
	return resolveRefs([]scimGroupRef{one})
}

func resolveRefs(refs []scimGroupRef) ([]ULID, error) {
	out := make([]ULID, 0, len(refs))
	for _, r := range refs {
		if strings.EqualFold(r.Type, "Group") {
			return nil, ErrUnsupportedFilter
		}
		id, err := ulidParse(r.Value)
		if err != nil {
			return nil, err
		}
		out = append(out, id)
	}
	return out, nil
}

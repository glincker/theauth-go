package signals

import (
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
)

// Subject identifier formats (RFC 9493).
const (
	FormatIssSub      = "iss_sub"
	FormatEmail       = "email"
	FormatOpaque      = "opaque"
	FormatPhoneNumber = "phone_number"
	FormatAccount     = "account"
	FormatDID         = "did"
	FormatURI         = "uri"
)

// Subject is a Subject Identifier (RFC 9493) or a Complex Subject (SSF
// section 3.2). A simple subject sets Format and the fields that format
// uses; a complex subject sets Complex only.
type Subject struct {
	Format      string
	Iss         string // iss_sub
	Sub         string // iss_sub
	Email       string // email
	ID          string // opaque
	PhoneNumber string // phone_number
	URI         string // account, uri
	URL         string // did
	// Complex maps member names (user, device, session, application,
	// tenant, org_unit, group) to simple subjects.
	Complex map[string]Subject
}

// IssSub builds an iss_sub subject.
func IssSub(iss, sub string) Subject { return Subject{Format: FormatIssSub, Iss: iss, Sub: sub} }

// EmailSubject builds an email subject.
func EmailSubject(email string) Subject { return Subject{Format: FormatEmail, Email: email} }

// Opaque builds an opaque subject.
func Opaque(id string) Subject { return Subject{Format: FormatOpaque, ID: id} }

// ComplexSubject builds a complex subject from named members.
func ComplexSubject(members map[string]Subject) Subject { return Subject{Complex: members} }

// IsZero reports whether s carries no identifier.
func (s Subject) IsZero() bool { return s.Format == "" && len(s.Complex) == 0 }

// Validate checks that the format's required members are present.
func (s Subject) Validate() error {
	if len(s.Complex) > 0 {
		if s.Format != "" {
			return errors.New("signals: complex subject must not set format")
		}
		for name, m := range s.Complex {
			if len(m.Complex) > 0 {
				return fmt.Errorf("signals: complex subject member %q must be a simple subject", name)
			}
			if err := m.Validate(); err != nil {
				return fmt.Errorf("member %q: %w", name, err)
			}
		}
		return nil
	}
	switch s.Format {
	case FormatIssSub:
		if s.Iss == "" || s.Sub == "" {
			return errors.New("signals: iss_sub subject requires iss and sub")
		}
	case FormatEmail:
		if s.Email == "" || !strings.Contains(s.Email, "@") {
			return errors.New("signals: email subject requires a valid email")
		}
	case FormatOpaque:
		if s.ID == "" {
			return errors.New("signals: opaque subject requires id")
		}
	case FormatPhoneNumber:
		if s.PhoneNumber == "" {
			return errors.New("signals: phone_number subject requires phone_number")
		}
	case FormatAccount, FormatURI:
		if s.URI == "" {
			return fmt.Errorf("signals: %s subject requires uri", s.Format)
		}
	case FormatDID:
		if s.URL == "" {
			return errors.New("signals: did subject requires url")
		}
	case "":
		return errors.New("signals: subject requires a format")
	default:
		return fmt.Errorf("signals: unsupported subject format %q", s.Format)
	}
	return nil
}

// MarshalJSON implements json.Marshaler.
func (s Subject) MarshalJSON() ([]byte, error) {
	if len(s.Complex) > 0 {
		return json.Marshal(s.Complex)
	}
	m := map[string]string{"format": s.Format}
	set := func(k, v string) {
		if v != "" {
			m[k] = v
		}
	}
	set("iss", s.Iss)
	set("sub", s.Sub)
	set("email", s.Email)
	set("id", s.ID)
	set("phone_number", s.PhoneNumber)
	set("uri", s.URI)
	set("url", s.URL)
	return json.Marshal(m)
}

// UnmarshalJSON implements json.Unmarshaler.
func (s *Subject) UnmarshalJSON(b []byte) error {
	var m map[string]json.RawMessage
	if err := json.Unmarshal(b, &m); err != nil {
		return err
	}
	*s = Subject{}
	if _, ok := m["format"]; !ok {
		s.Complex = make(map[string]Subject, len(m))
		for k, v := range m {
			var sub Subject
			if err := json.Unmarshal(v, &sub); err != nil {
				return fmt.Errorf("complex member %q: %w", k, err)
			}
			s.Complex[k] = sub
		}
		return nil
	}
	var flat map[string]string
	if err := json.Unmarshal(b, &flat); err != nil {
		return err
	}
	s.Format = flat["format"]
	s.Iss, s.Sub, s.Email, s.ID = flat["iss"], flat["sub"], flat["email"], flat["id"]
	s.PhoneNumber, s.URI, s.URL = flat["phone_number"], flat["uri"], flat["url"]
	return nil
}

// Key returns a canonical string for matching subjects. Email matching is
// case-insensitive.
func (s Subject) Key() string {
	if len(s.Complex) > 0 {
		names := make([]string, 0, len(s.Complex))
		for n := range s.Complex {
			names = append(names, n)
		}
		sort.Strings(names)
		parts := make([]string, 0, len(names))
		for _, n := range names {
			parts = append(parts, n+"="+s.Complex[n].Key())
		}
		return "complex:" + strings.Join(parts, "&")
	}
	switch s.Format {
	case FormatIssSub:
		return "iss_sub:" + s.Iss + "|" + s.Sub
	case FormatEmail:
		return "email:" + strings.ToLower(s.Email)
	case FormatOpaque:
		return "opaque:" + s.ID
	case FormatPhoneNumber:
		return "phone_number:" + s.PhoneNumber
	case FormatAccount, FormatURI:
		return s.Format + ":" + s.URI
	case FormatDID:
		return "did:" + s.URL
	}
	return s.Format + ":"
}

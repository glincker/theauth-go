package signals

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"strings"
)

func splitJWS(tok string) []string {
	p := strings.Split(tok, ".")
	if len(p) != 3 {
		return nil
	}
	return p
}

func b64(s string) ([]byte, error) { return base64.RawURLEncoding.DecodeString(s) }

// newID returns a random 128 bit hex identifier.
func newID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic("signals: entropy source failed: " + err.Error())
	}
	return hex.EncodeToString(b[:])
}

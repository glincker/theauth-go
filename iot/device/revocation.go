package device

import (
	"bytes"
	"crypto/sha256"
	"slices"
	"time"
)

// RevocationTyp is the `typ` header of a signed revocation snapshot.
const RevocationTyp = "device-revocations+jwt"

// RevocationDigest is the only list format so far: SHA-256 of the UTF-8 device id, first 8 bytes.
const RevocationDigest = "sha256-64"

const digestBytes = 8

// RevocationSnapshot is a verified list of the revoked and suspended device ids of one owner.
type RevocationSnapshot struct {
	Issuer, Owner string
	IssuedAt, Exp int64
	JTI           string
	// Seq is the issue time in milliseconds. Keep the highest one you accepted and pass it
	// as RevocationOptions.LastSeq, or an attacker can replay a shorter, older list.
	Seq int64
	// Count is the number of entries.
	Count int
	ids   []byte
}

// Contains reports whether the device id is on the list. The list holds 64 bit digests, so a
// healthy device is listed by mistake with probability about 2^-64 per entry.
func (s *RevocationSnapshot) Contains(deviceID string) bool {
	sum := sha256.Sum256([]byte(deviceID))
	target := sum[:digestBytes]
	lo, hi := 0, s.Count
	for lo < hi {
		mid := int(uint(lo+hi) >> 1)
		if bytes.Compare(s.ids[mid*digestBytes:(mid+1)*digestBytes], target) < 0 {
			lo = mid + 1
		} else {
			hi = mid
		}
	}
	return lo < s.Count && bytes.Equal(s.ids[lo*digestBytes:(lo+1)*digestBytes], target)
}

// RevocationOptions configures VerifyRevocations and opts VerifyBundle in to offline revocation.
type RevocationOptions struct {
	// Token is the snapshot delivered next to the bundle. An empty token fails closed.
	Token string
	// MaxAge fails closed when the snapshot was issued longer ago than this, even if it has
	// not expired yet. Set it to the longest stale window the device accepts. Required.
	MaxAge time.Duration
	// Owner, when set, must equal the snapshot's owner. VerifyBundle sets it from the bundle.
	Owner string
	// LastSeq is the highest snapshot seq accepted before, 0 for none.
	LastSeq int64
}

// VerifyRevocations checks signature, typ, iss, nbf and exp (30 s skew), age against MaxAge,
// owner, a sorted list whose length matches its count, and that seq did not go backwards.
// It matches TS verifyRevocationSnapshot. The error is a *VerifyError.
func VerifyRevocations(o RevocationOptions, keys *KeySet, issuer string, now time.Time) (*RevocationSnapshot, error) {
	invalid := func(msg string) error { return &VerifyError{ReasonInvalid, msg} }
	if o.Token == "" {
		return nil, &VerifyError{ReasonStaleRevocations, "no revocation snapshot supplied"}
	}
	t, err := parseJWS(o.Token)
	if err != nil {
		return nil, invalid("malformed snapshot")
	}
	alg, _ := t.header["alg"].(string)
	kid, _ := t.header["kid"].(string)
	key, found := keys.Lookup(kid)
	if !typMatches(t.header["typ"], RevocationTyp) || (alg != string(AlgES256) && alg != string(AlgEdDSA)) ||
		!found || alg != string(key.Alg) || !key.verifySig(t.input, t.sig) {
		return nil, invalid("snapshot signature, issuer or lifetime is invalid")
	}
	pv, err := parseJSON(t.payload)
	obj, isObj := pv.(map[string]any)
	if err != nil || !isObj {
		return nil, invalid("snapshot payload is not a JSON object")
	}
	if issuer == "" {
		issuer = DefaultIssuer
	}
	nowSec := now.Unix()
	exp, hasExp := obj["exp"].(float64)
	nbf, hasNbf := obj["nbf"].(float64)
	if obj["iss"] != issuer || !hasExp || (hasNbf && int64(nbf) > nowSec+skewSeconds) || (obj["nbf"] != nil && !hasNbf) {
		return nil, invalid("snapshot signature, issuer or lifetime is invalid")
	}
	if int64(exp) <= nowSec-skewSeconds {
		return nil, &VerifyError{ReasonStaleRevocations, "snapshot has expired"}
	}
	owner, okOwner := obj["sub"].(string)
	iat, okIat := obj["iat"].(float64)
	seq, okSeq := obj["seq"].(float64)
	n, okN := obj["n"].(float64)
	ids, okIDs := obj["ids"].(string)
	if !okOwner || !okIat || !okSeq || !okN || !okIDs || obj["h"] != RevocationDigest {
		return nil, invalid("snapshot is missing fields")
	}
	if o.Owner != "" && owner != o.Owner {
		return nil, invalid("snapshot is for another owner")
	}
	if float64(nowSec)-iat > o.MaxAge.Seconds() {
		return nil, &VerifyError{ReasonStaleRevocations, "snapshot is older than allowed"}
	}
	if o.LastSeq != 0 && int64(seq) < o.LastSeq {
		return nil, &VerifyError{ReasonRollback, "snapshot is older than the last accepted"}
	}
	list, err := b64.DecodeString(ids)
	if err != nil || len(list)%digestBytes != 0 || float64(len(list)/digestBytes) != n {
		return nil, invalid("revocation list is malformed or does not match its count")
	}
	count := len(list) / digestBytes
	for i := 1; i < count; i++ {
		if bytes.Compare(list[(i-1)*digestBytes:i*digestBytes], list[i*digestBytes:(i+1)*digestBytes]) >= 0 {
			return nil, invalid("revocation list is not sorted")
		}
	}
	jti, _ := obj["jti"].(string)
	return &RevocationSnapshot{
		Issuer: issuer, Owner: owner, IssuedAt: int64(iat), Exp: int64(exp), JTI: jti,
		Seq: int64(seq), Count: count, ids: list,
	}, nil
}

// SignRevocations signs a snapshot of the blocked device ids of one owner. The server (TS
// core) is the real issuer; this exists for Go gateways that act as a local issuer, and for tests.
func (s *Signer) SignRevocations(kid, issuer, owner string, deviceIDs []string, iat time.Time, ttl time.Duration) (string, error) {
	if s.pub.Alg == AlgES384 {
		return "", errBundleAlg
	}
	if kid == "" {
		return "", errKidRequired
	}
	seen := map[string]bool{}
	digests := make([][]byte, 0, len(deviceIDs))
	for _, id := range deviceIDs {
		if seen[id] {
			continue
		}
		seen[id] = true
		sum := sha256.Sum256([]byte(id))
		digests = append(digests, sum[:digestBytes])
	}
	slices.SortFunc(digests, bytes.Compare)
	joined := bytes.Join(digests, nil)
	sec := iat.Unix()
	payload := map[string]any{
		"iss": issuer, "sub": owner, "iat": sec, "nbf": sec, "exp": sec + int64(ttl.Seconds()),
		"jti": "go-" + b64.EncodeToString(joined[:min(len(joined), 6)]), "seq": iat.UnixMilli(),
		"n": len(digests), "h": RevocationDigest, "ids": b64.EncodeToString(joined),
	}
	return signJWS(s, map[string]any{"alg": string(s.pub.Alg), "typ": RevocationTyp, "kid": kid}, payload)
}

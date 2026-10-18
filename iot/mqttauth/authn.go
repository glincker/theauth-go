package mqttauth

import (
	"context"
	"crypto/subtle"
	"errors"
	"net/http"
	"strings"
	"time"
)

type principal struct {
	dev    *Device
	method string
	exp    time.Time // zero when the credential has no expiry of its own
}

// authenticate resolves the device behind a CONNECT. The reason is for audit only. The order is
// fixed and there is no fallback between credential kinds: a broker verified client certificate
// wins, then a JWT password when the password has the JWT shape, then username plus opaque token.
func (h *Handler) authenticate(ctx context.Context, r *http.Request, req brokerRequest) (*principal, string) {
	now := h.now()
	fp, reason := h.certFingerprint(r, req)
	switch {
	case reason != "":
		return nil, reason
	case fp != "":
		d, err := h.cfg.Store.DeviceByCertFingerprint(ctx, fp)
		if err != nil {
			return nil, h.lookupReason(err, "unknown certificate")
		}
		return h.finish(d, "cert", time.Time{}, req, now)
	case h.cfg.JWT != nil && looksLikeJWT(req.Password):
		sub, exp, err := h.cfg.JWT.verify(req.Password, h.now)
		if err != nil {
			return nil, "invalid jwt"
		}
		d, err := h.deviceBySubject(ctx, sub)
		if err != nil {
			return nil, h.lookupReason(err, "unknown subject")
		}
		return h.finish(d, "jwt", exp, req, now)
	case req.Username != "" && req.Password != "":
		d, err := h.cfg.Store.DeviceByID(ctx, req.Username)
		if err != nil && !errors.Is(err, ErrDeviceNotFound) {
			return nil, "store error"
		}
		if !tokenMatches(d, req.Password) {
			return nil, "bad token"
		}
		return h.finish(d, "token", time.Time{}, req, now)
	}
	return nil, "no credential"
}

// tokenMatches compares the password hash with every stored hash in constant time. A missing
// device still costs one hash and compare.
func tokenMatches(d *Device, password string) bool {
	got := []byte(HashToken(password))
	ok := 0
	var hashes []string
	if d != nil {
		hashes = d.TokenHashes
	}
	for _, h := range hashes {
		ok |= subtle.ConstantTimeCompare(got, []byte(h))
	}
	return ok == 1 && d != nil
}

func (h *Handler) lookupReason(err error, notFound string) string {
	if errors.Is(err, ErrDeviceNotFound) {
		return notFound
	}
	h.metrics.inc("theauth_mqtt_errors_total", "store")
	return "store error"
}

func (h *Handler) finish(d *Device, method string, exp time.Time, req brokerRequest, now time.Time) (*principal, string) {
	if !d.Active(now) {
		return nil, "device not active"
	}
	if !h.cfg.AllowAnyClientID && !clientIDBound(req.ClientID, d.ID) {
		return nil, "client id not bound to device"
	}
	return &principal{dev: d, method: method, exp: exp}, ""
}

// clientIDBound reports whether the MQTT client ID is the device ID or the ID plus "-suffix".
func clientIDBound(clientID, deviceID string) bool {
	if clientID == deviceID {
		return true
	}
	rest, ok := strings.CutPrefix(clientID, deviceID+"-")
	return ok && rest != ""
}

// certFingerprint reads the broker supplied fingerprint from the header and the body field. A
// disagreement, or a value that is not a SHA-256 digest, is a failure rather than a fallback to
// another credential.
func (h *Handler) certFingerprint(r *http.Request, req brokerRequest) (fp, reason string) {
	vals := []string{r.Header.Get(h.cfg.CertFingerprintHeader), req.CertFingerprint}
	for _, v := range vals {
		if strings.TrimSpace(v) == "" {
			continue
		}
		n, ok := NormalizeFingerprint(v)
		if !ok {
			return "", "malformed certificate fingerprint"
		}
		if fp != "" && fp != n {
			return "", "conflicting certificate fingerprints"
		}
		fp = n
	}
	return fp, ""
}

func (h *Handler) serveAuthn(w http.ResponseWriter, r *http.Request) {
	if !h.fromBroker(r) {
		h.log.Warn("mqttauth: caller is not the broker", "path", r.URL.Path)
		h.record(r.Context(), AuditEvent{Kind: "authn", Reason: "caller not authorized"})
		emqxDeny(w)
		return
	}
	req, ok := readRequest(w, r)
	if !ok {
		h.record(r.Context(), AuditEvent{Kind: "authn", Reason: "malformed request"})
		emqxDeny(w)
		return
	}
	p, reason := h.authenticate(r.Context(), r, req)
	ev := AuditEvent{Kind: "authn", ClientID: req.ClientID, RemoteAddr: req.PeerHost, Reason: reason}
	if p == nil {
		h.record(r.Context(), ev)
		emqxDeny(w)
		return
	}
	ev.Allowed, ev.Method, ev.DeviceID, ev.OrgID, ev.Reason = true, p.method, p.dev.ID, p.dev.OrgID, "ok"
	h.record(r.Context(), ev)
	h.cache.putDevice(p.dev)
	resp := map[string]any{
		"result":       "allow",
		"is_superuser": false,
		"client_attrs": map[string]string{"device_id": p.dev.ID, "org_id": p.dev.OrgID, "method": p.method},
	}
	if exp := earliest(p.exp, p.dev.ExpiresAt); !exp.IsZero() {
		resp["expire_at"] = exp.Unix()
	}
	writeJSON(w, http.StatusOK, resp)
}

func earliest(a, b time.Time) time.Time {
	switch {
	case a.IsZero():
		return b
	case b.IsZero() || a.Before(b):
		return a
	}
	return b
}

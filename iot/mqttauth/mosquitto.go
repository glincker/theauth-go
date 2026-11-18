package mqttauth

import (
	"bytes"
	"crypto/sha256"
	"crypto/subtle"
	"net/http"
	"strconv"
)

// The mosquitto-go-auth HTTP backend sends username, password, clientid, topic and acc. acc is
// 1 read, 2 write, 3 readwrite, 4 subscribe. The plugin treats any non 2xx status as a denial in
// its default "status" response mode and reads {"Ok": bool} in "json" mode, so a deny is a 403
// with Ok false, which satisfies both. Username is the device ID.

// fromMosquitto authorizes the caller of a mosquitto-go-auth route. The plugin has no option to
// send request headers (its HTTP backend options are the host, port, URIs, method, params mode,
// response mode, timeout, user agent and TLS flag), so besides the bearer header the broker secret
// is accepted as the "secret" query parameter of the configured URIs. Keep the plugin to this
// service on a private network or over TLS, since a URI can end up in access logs.
func (h *Handler) fromMosquitto(r *http.Request) bool {
	if h.fromBroker(r) {
		return true
	}
	if h.cfg.BrokerSecret == "" {
		return false
	}
	g := sha256.Sum256([]byte(r.URL.Query().Get("secret")))
	return subtle.ConstantTimeCompare(g[:], h.secret[:]) == 1
}

func mosquittoDeny(w http.ResponseWriter) {
	writeJSON(w, http.StatusForbidden, map[string]any{"Ok": false, "Error": "denied"})
}

func mosquittoAllow(w http.ResponseWriter) { writeJSON(w, http.StatusOK, map[string]any{"Ok": true}) }

func (h *Handler) mosquittoUser(w http.ResponseWriter, r *http.Request) {
	req, ok := readRequest(w, r)
	if !ok || !h.fromMosquitto(r) {
		mosquittoDeny(w)
		return
	}
	if req.Username == "" || req.Password == "" {
		h.record(r.Context(), AuditEvent{Kind: "authn", ClientID: req.ClientID, Reason: "no credential"})
		mosquittoDeny(w)
		return
	}
	snap := h.cache.snapshot()
	p, reason := h.authenticate(r.Context(), r, brokerRequest{
		Username: req.Username, Password: req.Password, ClientID: req.ClientID,
	})
	ev := AuditEvent{Kind: "authn", ClientID: req.ClientID, Reason: reason, Code: authnCode(reason)}
	if p == nil {
		h.record(r.Context(), ev)
		mosquittoDeny(w)
		return
	}
	ev.Allowed, ev.Method, ev.DeviceID, ev.OrgID, ev.Reason, ev.Code = true, p.method, p.dev.ID, p.dev.OrgID, "ok", CodeAllowed
	h.record(r.Context(), ev)
	h.cache.putDevice(p.dev, h.cache.tokenFrom(snap, p.dev.ID))
	mosquittoAllow(w)
}

// mosquittoSuperuser always answers no: there are no superusers.
func (h *Handler) mosquittoSuperuser(w http.ResponseWriter, _ *http.Request) { mosquittoDeny(w) }

func (h *Handler) mosquittoACL(w http.ResponseWriter, r *http.Request) {
	req, ok := readRequest(w, r)
	if !ok || !h.fromMosquitto(r) {
		mosquittoDeny(w)
		return
	}
	acc, err := strconv.Atoi(string(bytes.Trim(req.Acc, `" `)))
	var action Action
	switch {
	case err != nil:
	case acc == 2:
		action = ActionPublish
	case acc == 1 || acc == 4:
		// A read check names a concrete topic, which a subscribe grant covers the same way.
		action = ActionSubscribe
	}
	req.DeviceID = "" // never trust a client supplied attribute on this contract
	dec, d, cached := h.authorize(r.Context(), req, action, req.Topic)
	h.recordAuthz(r, req, string(action), dec, d, cached)
	if !dec.Allowed {
		mosquittoDeny(w)
		return
	}
	mosquittoAllow(w)
}

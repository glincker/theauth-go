package mqttauth

import (
	"context"
	"errors"
	"net/http"
	"strings"
)

// authorize runs one publish or subscribe check for the device named by the request.
func (h *Handler) authorize(ctx context.Context, req brokerRequest, action Action, rawTopic string) (Decision, *Device, bool) {
	topic, why := h.checkTopic(action, rawTopic)
	if why != "" {
		return Decision{Reason: why}, nil, false
	}
	id := req.DeviceID
	bound := id != "" // the broker relays client_attrs.device_id that authn set
	if id == "" {
		id = req.Username
	}
	if id == "" {
		return Decision{Reason: "no device identity"}, nil, false
	}
	if !bound && !h.cfg.AllowAnyClientID && !clientIDBound(req.ClientID, id) {
		return Decision{Reason: "client id not bound to device"}, nil, false
	}
	d, err := h.loadDevice(ctx, id)
	if err != nil {
		if errors.Is(err, ErrDeviceNotFound) {
			return Decision{Reason: "unknown device"}, nil, false
		}
		h.metrics.inc("theauth_mqtt_errors_total", "store")
		return Decision{Reason: "store error"}, nil, false
	}
	if !d.Active(h.now()) {
		h.cache.purge(d.ID)
		return Decision{Reason: "device not active"}, d, false
	}
	key := string(action) + "\x00" + topic
	if dec, ok := h.cache.decision(d.ID, key); ok {
		h.metrics.inc("theauth_mqtt_cache_hits_total", "decision")
		return dec, d, true
	}
	dec := h.cfg.Authorizer.Authorize(ctx, d, action, topic)
	h.cache.putDecision(d.ID, key, dec)
	return dec, d, false
}

func (h *Handler) loadDevice(ctx context.Context, id string) (*Device, error) {
	if d, ok := h.cache.device(id); ok {
		h.metrics.inc("theauth_mqtt_cache_hits_total", "device")
		return d, nil
	}
	d, err := h.cfg.Store.DeviceByID(ctx, id)
	if err != nil {
		return nil, err
	}
	h.cache.putDevice(d)
	return d, nil
}

// checkTopic validates the topic for the action. Publishing to $SYS or to a $share name is never
// allowed, brokers own those. For a subscribe the $share prefix is removed.
func (h *Handler) checkTopic(action Action, raw string) (string, string) {
	switch action {
	case ActionPublish:
		if err := ValidateTopicName(raw); err != nil {
			return "", "invalid topic"
		}
		if strings.HasPrefix(raw, "$SYS/") || raw == "$SYS" || strings.HasPrefix(raw, "$share/") {
			return "", "reserved topic"
		}
		return raw, ""
	case ActionSubscribe:
		s, err := ParseSubscription(raw)
		if err != nil {
			return "", "invalid topic filter"
		}
		return s.Filter, ""
	}
	return "", "unknown action"
}

func (h *Handler) serveAuthz(w http.ResponseWriter, r *http.Request) {
	if !h.fromBroker(r) {
		h.record(r.Context(), AuditEvent{Kind: "authz", Reason: "caller not authorized"})
		emqxDeny(w)
		return
	}
	req, ok := readRequest(w, r)
	if !ok {
		h.record(r.Context(), AuditEvent{Kind: "authz", Reason: "malformed request"})
		emqxDeny(w)
		return
	}
	dec, d, cached := h.authorize(r.Context(), req, Action(req.Action), req.Topic)
	h.recordAuthz(r, req, req.Action, dec, d, cached)
	if !dec.Allowed {
		emqxDeny(w)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"result": "allow"})
}

func (h *Handler) recordAuthz(r *http.Request, req brokerRequest, action string, dec Decision, d *Device, cached bool) {
	ev := AuditEvent{Kind: "authz", Allowed: dec.Allowed, ClientID: req.ClientID, Action: action, Topic: req.Topic,
		Reason: dec.Reason, RemoteAddr: req.PeerHost, Cached: cached}
	if d != nil {
		ev.DeviceID, ev.OrgID = d.ID, d.OrgID
	}
	h.record(r.Context(), ev)
}

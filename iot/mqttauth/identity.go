package mqttauth

import (
	"context"
	"errors"
	"log/slog"
	"strings"
	"sync/atomic"

	theauth "github.com/glincker/theauth-go/v2"
)

// ScopePrefix starts a device scope that grants MQTT access. The full form is
// "mqtt:<action>:<level>:<level>...", for example "mqtt:publish:sensors:temp:*" or
// "mqtt:subscribe:devices:{device_id}:cmd:*". The action is publish, subscribe or "*" (both). The
// levels are the colon segments of decision D8 in the device identity design: a final "*" means
// the rest of the topic, so the examples are the MQTT filters "sensors/temp/#" and
// "devices/{device_id}/cmd/#". "{device_id}" and "{org_id}" are replaced when the rule is applied.
const ScopePrefix = "mqtt:"

// subjectPrefix is the access token subject prefix of a device without a SPIFFE ID (the core
// Device.Subject method).
const subjectPrefix = "device:"

// ScopeRules turns device scopes into allow rules. Scopes that do not start with ScopePrefix are
// ignored (they belong to other resources). A scope that starts with it but is malformed grants
// nothing, which fails closed. There are no deny rules: a device holds only what it was enrolled
// with.
func ScopeRules(scopes []string) []Rule {
	var rules []Rule
	for _, sc := range scopes {
		rest, ok := strings.CutPrefix(sc, ScopePrefix)
		if !ok {
			continue
		}
		act, path, ok := strings.Cut(rest, ":")
		if !ok || path == "" {
			continue
		}
		var action Action
		switch act {
		case "publish":
			action = ActionPublish
		case "subscribe":
			action = ActionSubscribe
		case "*":
			action = ActionAll
		default:
			continue
		}
		filter, valid := scopeFilter(strings.Split(path, ":"))
		if !valid {
			continue
		}
		r := Rule{Effect: Allow, Action: action, Filter: filter}
		if r.validate() == nil {
			rules = append(rules, r)
		}
	}
	return rules
}

// scopeFilter joins D8 levels into an MQTT filter. A "*" level ends the filter as "#".
func scopeFilter(levels []string) (string, bool) {
	out := make([]string, 0, len(levels))
	for _, l := range levels {
		switch {
		case l == "*":
			return strings.Join(append(out, "#"), "/"), true
		case l == "" || strings.ContainsAny(l, "/+#*"):
			return "", false
		}
		out = append(out, l)
	}
	return strings.Join(out, "/"), true
}

// IdentityStore serves the MQTT broker from the device registry of the authorization server
// (Config.AuthorizationServer.DeviceTokens, storage implementing theauth.DeviceIdentityStorage).
// It is read only: enrollment, revocation and scopes stay with theAuth.
//
// Mapping: the device ID is the ULID string, OrgID the organization ULID, Subject the access token
// subject (the SPIFFE ID when set, else "device:<id>"), and a suspended device is reported suspended and any other
// device that is not active revoked. The ACL comes from the device's enrolled scopes through Rules (default ScopeRules), not
// from the scope claim of any one access token. The device holds an asymmetric key and no
// certificate or opaque token, so the credential on the MQTT side is the access token the device
// obtained with its assertion, sent as the password and verified through Config.JWT.
// DeviceByCertFingerprint therefore never finds anything.
type IdentityStore struct {
	Storage theauth.DeviceIdentityStorage
	// Rules maps a device to its ACL rules. Nil means ScopeRules(d.Scopes).
	Rules func(d theauth.Device) []Rule
}

var _ DeviceStore = (*IdentityStore)(nil)

// NewIdentityStore returns an IdentityStore over s.
func NewIdentityStore(s theauth.DeviceIdentityStorage) *IdentityStore {
	return &IdentityStore{Storage: s}
}

func (s *IdentityStore) toDevice(d theauth.Device) *Device {
	out := &Device{ID: d.ID.String(), Name: d.Name, Subject: d.Subject(), Status: StatusRevoked}
	if d.OrganizationID != nil {
		out.OrgID = d.OrganizationID.String()
	}
	switch {
	case d.Active():
		out.Status = StatusActive
	case d.Status == theauth.DeviceStatusSuspended && d.RevokedAt == nil:
		out.Status = StatusSuspended
	}
	if s.Rules != nil {
		out.Rules = s.Rules(d)
	} else {
		out.Rules = ScopeRules(d.Scopes)
	}
	return out
}

// DeviceByID implements DeviceStore. An ID that is not a ULID is not found.
func (s *IdentityStore) DeviceByID(ctx context.Context, id string) (*Device, error) {
	var uid theauth.ULID
	if err := uid.UnmarshalText([]byte(id)); err != nil || uid.String() != id {
		return nil, ErrDeviceNotFound
	}
	d, err := s.Storage.DeviceByID(ctx, uid)
	if err != nil {
		if errors.Is(err, theauth.ErrStorageNotFound) {
			return nil, ErrDeviceNotFound
		}
		return nil, err
	}
	return s.toDevice(*d), nil
}

// DeviceBySubject implements DeviceStore. "device:<id>" is a direct lookup by ID, any other
// subject is a SPIFFE ID and goes through the indexed Storage.DeviceBySPIFFEID.
func (s *IdentityStore) DeviceBySubject(ctx context.Context, subject string) (*Device, error) {
	if subject == "" {
		return nil, ErrDeviceNotFound
	}
	if id, ok := strings.CutPrefix(subject, subjectPrefix); ok {
		d, err := s.DeviceByID(ctx, id)
		if err != nil {
			return nil, err
		}
		if d.Subject != subject {
			return nil, ErrDeviceNotFound // the device has a SPIFFE ID, which is its subject instead
		}
		return d, nil
	}
	d, err := s.Storage.DeviceBySPIFFEID(ctx, subject)
	if err != nil {
		if errors.Is(err, theauth.ErrStorageNotFound) {
			return nil, ErrDeviceNotFound
		}
		return nil, err
	}
	return s.toDevice(*d), nil
}

// DeviceByKeyThumbprint finds the device enrolled with the key whose RFC 7638 thumbprint is
// given (the newest one when several share a key). It is an indexed lookup, for brokers that
// authenticate a device by its key instead of an access token.
func (s *IdentityStore) DeviceByKeyThumbprint(ctx context.Context, thumbprint string) (*Device, error) {
	d, err := s.Storage.DeviceByKeyThumbprint(ctx, thumbprint)
	if err != nil {
		if errors.Is(err, theauth.ErrStorageNotFound) {
			return nil, ErrDeviceNotFound
		}
		return nil, err
	}
	return s.toDevice(*d), nil
}

// DeviceByCertFingerprint implements DeviceStore. Registry devices have no certificate
// credential, so nothing matches.
func (s *IdentityStore) DeviceByCertFingerprint(context.Context, string) (*Device, error) {
	return nil, ErrDeviceNotFound
}

// Purger connects the device revoke and status paths to the handler cache. Pass OnRevoke and
// OnStatusChange as DeviceTokensConfig.OnRevoke and OnStatusChange and call Bind once the Handler
// exists (the Handler needs the TheAuth value for TheAuthSink, which needs the config, hence the
// two steps):
//
//	var purge mqttauth.Purger
//	cfg.AuthorizationServer.DeviceTokens = &theauth.DeviceTokensConfig{
//		OnRevoke: purge.OnRevoke, OnStatusChange: purge.OnStatusChange,
//	}
//	// ... theauth.New, mqttauth.New ...
//	purge.Bind(h)
//
// The purge is per process unless a PurgeBroadcaster is set (SetBroadcaster, then Run in a
// goroutine): then every revoke also reaches the other replicas. Without one, call Handler.Purge
// on each replica (see POST /purge) or keep CacheTTL short. A revoke before Bind is not lost: Bind
// drops all cached state.
type Purger struct {
	h  atomic.Pointer[Handler]
	bc atomic.Pointer[PurgeBroadcaster]
}

// Bind sets the handler to purge and clears whatever it cached before.
func (p *Purger) Bind(h *Handler) {
	p.h.Store(h)
	if h != nil {
		h.PurgeAll()
	}
}

// SetBroadcaster makes OnRevoke and OnStatusChange publish to the other replicas as well. Pass
// nil to stop. Run must be running on every replica, including this one, to receive.
func (p *Purger) SetBroadcaster(b PurgeBroadcaster) {
	if b == nil {
		p.bc.Store(nil)
		return
	}
	p.bc.Store(&b)
}

// Run receives purges from the broadcaster and applies them to the bound handler. It blocks until
// ctx ends or the broadcaster fails, so start it in a goroutine. Without a broadcaster it
// returns nil at once.
func (p *Purger) Run(ctx context.Context) error {
	bp := p.bc.Load()
	if bp == nil {
		return nil
	}
	return (*bp).Subscribe(ctx, p.purgeLocal)
}

func (p *Purger) purgeLocal(deviceID string) {
	h := p.h.Load()
	switch {
	case h == nil:
	case deviceID == "":
		h.PurgeAll()
	default:
		h.Purge(deviceID)
	}
}

func (p *Purger) purge(ctx context.Context, deviceID string) {
	p.purgeLocal(deviceID)
	if bp := p.bc.Load(); bp != nil {
		if err := (*bp).Publish(ctx, deviceID); err != nil {
			slog.Warn("mqttauth: purge broadcast failed, other replicas keep the cache until CacheTTL", "device", deviceID, "err", err.Error())
		}
	}
}

// OnRevoke has the signature of DeviceTokensConfig.OnRevoke.
func (p *Purger) OnRevoke(ctx context.Context, deviceID string) { p.purge(ctx, deviceID) }

// OnStatusChange has the signature of DeviceTokensConfig.OnStatusChange. A suspend or resume
// changes what the broker may serve, so it purges like a revoke.
func (p *Purger) OnStatusChange(ctx context.Context, deviceID, _ string) { p.purge(ctx, deviceID) }

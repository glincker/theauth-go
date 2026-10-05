package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/glincker/theauth-go"
	sqlitestore "github.com/glincker/theauth-go/storage/sqlite"
	_ "modernc.org/sqlite"
)

const abilityRead = "read"

type options struct {
	baseURL        string
	dbPath         string
	setupToken     string
	pollInterval   time.Duration
	rateLimitPerIP int
}

type app struct {
	auth    *theauth.TheAuth
	db      *sql.DB
	handler http.Handler
}

func (a *app) close() {
	a.auth.Close()
	_ = a.db.Close()
}

func newApp(ctx context.Context, o options) (*app, error) {
	dsn := "file:" + o.dbPath + "?_pragma=foreign_keys(1)&_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)&_txlock=immediate"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("open database: %w", err)
	}
	if err := db.PingContext(ctx); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("ping database: %w", err)
	}
	if err := sqlitestore.Migrate(ctx, db); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("migrate: %w", err)
	}
	store, err := sqlitestore.New(db)
	if err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("storage: %w", err)
	}

	a, err := theauth.New(theauth.Config{
		CoreStorage:                   store,
		BaseURL:                       o.baseURL,
		RateLimitPerIP:                o.rateLimitPerIP,
		SecureCookie:                  strings.HasPrefix(o.baseURL, "https://"),
		SuppressSecureCookieWarning:   true,
		SuppressTrustedProxiesWarning: true,
		Bootstrap:                     &theauth.BootstrapConfig{SetupToken: o.setupToken},
		APITokens: &theauth.APITokensConfig{
			Abilities: []string{abilityRead},
			UserAbilities: func(context.Context, *theauth.User) ([]string, error) {
				return []string{abilityRead}, nil
			},
			Device: &theauth.DeviceConfig{
				VerificationURI:  strings.TrimRight(o.baseURL, "/") + "/device",
				DefaultAbilities: []string{abilityRead},
				Interval:         o.pollInterval,
			},
		},
	})
	if err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("theauth: %w", err)
	}

	mux := http.NewServeMux()
	mux.Handle("/auth/", a.Handler())
	mux.HandleFunc("GET /device", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write([]byte(devicePage))
	})
	mux.Handle("GET /api/whoami", a.RequireAbility(abilityRead)(http.HandlerFunc(whoami)))

	return &app{auth: a, db: db, handler: mux}, nil
}

func whoami(w http.ResponseWriter, r *http.Request) {
	p, ok := theauth.PrincipalFromContext(r.Context())
	if !ok {
		http.Error(w, "no principal", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"userId":    p.UserID.String(),
		"kind":      p.Kind,
		"abilities": p.Abilities,
	})
}

const devicePage = `<!doctype html>
<meta charset="utf-8"><title>Approve a device</title>
<body style="font-family:sans-serif;max-width:28rem;margin:3rem auto">
<h1>Approve a device</h1>
<form id="login" hidden>
  <p>Sign in first.</p>
  <input name="email" type="email" placeholder="email" required>
  <input name="password" type="password" placeholder="password" required>
  <button>Sign in</button>
</form>
<form id="approve" hidden>
  <input name="user_code" placeholder="ABCD-EFGH" required>
  <button name="action" value="approve">Approve</button>
  <button name="action" value="deny" type="button" id="deny">Deny</button>
</form>
<p id="msg"></p>
<script>
const msg = document.getElementById("msg");
const post = (url, body) => fetch(url, {method: "POST", headers: {"Content-Type": "application/json"}, body: JSON.stringify(body)});
async function refresh() {
  const me = await fetch("/auth/me");
  document.getElementById("login").hidden = me.ok;
  document.getElementById("approve").hidden = !me.ok;
}
async function decide(action) {
  const code = document.querySelector("#approve [name=user_code]").value;
  const r = await post("/auth/device/approve", {user_code: code, action});
  msg.textContent = r.status === 204 ? "Done. Return to your terminal." : "Failed: " + r.status;
}
document.getElementById("login").onsubmit = async (e) => {
  e.preventDefault();
  const f = new FormData(e.target);
  const r = await post("/auth/email-password/signin", {email: f.get("email"), password: f.get("password")});
  msg.textContent = r.ok ? "" : "Sign in failed: " + r.status;
  refresh();
};
document.getElementById("approve").onsubmit = (e) => { e.preventDefault(); decide("approve"); };
document.getElementById("deny").onclick = () => decide("deny");
const q = new URLSearchParams(location.search).get("user_code");
if (q) document.querySelector("#approve [name=user_code]").value = q;
refresh();
</script>
`

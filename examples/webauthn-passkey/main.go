// webauthn-passkey is a runnable demo of v0.5 passkey registration + login.
//
// What it does:
//   - Mounts the full /auth/* route set with WebAuthn enabled
//   - Serves a single page that registers a passkey and then signs in with it
//
// What it expects:
//   - Run on https://localhost or any origin that the browser permits for
//     WebAuthn. For a quick local run, use mkcert + a local TLS reverse
//     proxy, or set HOST=localhost and POINT_BROWSER to an https origin.
//
// What it does NOT do:
//   - Cookies, CSRF, CORS for cross-origin SPA setups: this is a single-page
//     example and skips that to keep the file readable.
package main

import (
	"log"
	"log/slog"
	"net/http"
	"os"

	"github.com/glincker/theauth-go"
	"github.com/glincker/theauth-go/storage/memory"
	"github.com/go-chi/chi/v5"
)

func main() {
	rpid := envOr("RPID", "localhost")
	origin := envOr("ORIGIN", "http://localhost:8080")

	a, err := theauth.New(theauth.Config{
		Storage:      memory.New(),
		BaseURL:      origin,
		SecureCookie: false,
		WebAuthn: &theauth.WebAuthnConfig{
			RPID:          rpid,
			RPDisplayName: "TheAuth Passkey Demo",
			RPOrigins:     []string{origin},
		},
	})
	if err != nil {
		log.Fatal(err)
	}
	defer a.Close()

	r := chi.NewRouter()
	a.Mount(r)
	r.Get("/", indexHandler)

	slog.Info("listening", "addr", ":8080", "origin", origin, "rpid", rpid)
	if err := http.ListenAndServe(":8080", r); err != nil {
		log.Fatal(err)
	}
}

func envOr(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

func indexHandler(w http.ResponseWriter, _ *http.Request) {
	_, _ = w.Write([]byte(`<!doctype html>
<html><body>
<h1>TheAuth passkey demo</h1>
<p>Open the browser console; the buttons call the v0.5 endpoints in order.</p>
<button id="register">Register passkey</button>
<button id="login">Login with passkey</button>
<pre id="out"></pre>
<script type="module">
function b64uToBuf(s){const p='='.repeat((4-s.length%4)%4);const b=atob((s+p).replace(/-/g,'+').replace(/_/g,'/'));const a=new Uint8Array(b.length);for(let i=0;i<b.length;i++)a[i]=b.charCodeAt(i);return a.buffer}
function bufToB64u(b){const a=new Uint8Array(b);let s='';for(const x of a)s+=String.fromCharCode(x);return btoa(s).replace(/\+/g,'-').replace(/\//g,'_').replace(/=+$/,'')}
const out = document.getElementById('out');
document.getElementById('register').onclick = async () => {
  // The demo assumes the user is already signed in via the email-password
  // route group. In a real app you would prompt for signin first.
  const opt = await (await fetch('/auth/webauthn/register/begin', {method:'POST'})).json();
  opt.publicKey.challenge = b64uToBuf(opt.publicKey.challenge);
  opt.publicKey.user.id   = b64uToBuf(opt.publicKey.user.id);
  if (opt.publicKey.excludeCredentials) opt.publicKey.excludeCredentials.forEach(c=>c.id=b64uToBuf(c.id));
  const cred = await navigator.credentials.create({publicKey: opt.publicKey});
  const body = {
    id: cred.id, rawId: bufToB64u(cred.rawId), type: cred.type,
    response: {
      attestationObject: bufToB64u(cred.response.attestationObject),
      clientDataJSON: bufToB64u(cred.response.clientDataJSON),
    },
  };
  const res = await fetch('/auth/webauthn/register/finish?name=primary', {
    method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify(body),
  });
  out.textContent = 'register: ' + res.status + ' ' + await res.text();
};
document.getElementById('login').onclick = async () => {
  const opt = await (await fetch('/auth/webauthn/login/begin', {method:'POST'})).json();
  opt.publicKey.challenge = b64uToBuf(opt.publicKey.challenge);
  if (opt.publicKey.allowCredentials) opt.publicKey.allowCredentials.forEach(c=>c.id=b64uToBuf(c.id));
  const cred = await navigator.credentials.get({publicKey: opt.publicKey});
  const body = {
    id: cred.id, rawId: bufToB64u(cred.rawId), type: cred.type,
    response: {
      authenticatorData: bufToB64u(cred.response.authenticatorData),
      clientDataJSON: bufToB64u(cred.response.clientDataJSON),
      signature: bufToB64u(cred.response.signature),
      userHandle: cred.response.userHandle ? bufToB64u(cred.response.userHandle) : null,
    },
  };
  const res = await fetch('/auth/webauthn/login/finish', {
    method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify(body),
  });
  out.textContent = 'login: ' + res.status + ' ' + await res.text();
};
</script>
</body></html>`))
}

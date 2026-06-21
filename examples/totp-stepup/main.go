// totp-stepup is a runnable demo of the v0.5 password + TOTP step-up flow.
//
// What it does:
//   - Mounts the full /auth/* route set with TOTP enabled
//   - Serves a single page that signs up, enrolls TOTP, signs out, signs
//     back in (gets a pending_2fa cookie), and posts the current 6-digit
//     code to /auth/totp/verify to upgrade the session
//
// What it does NOT do:
//   - Render a QR. The example surfaces the otpauth:// URI and the raw
//     base32 secret in the page so a user can hand-enter it into Google
//     Authenticator / 1Password / Authy or paste the URI into any QR
//     renderer. Consumers wanting an inline QR can plug in any QR library;
//     the spec deliberately keeps QR generation out of the library scope.
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
	baseURL := envOr("BASE_URL", "http://localhost:8080")
	key := []byte(envOr("ENCRYPTION_KEY", "0123456789abcdef0123456789abcdef")) // 32 bytes; rotate via your secrets manager in prod

	a, err := theauth.New(theauth.Config{
		Storage:       memory.New(),
		BaseURL:       baseURL,
		SecureCookie:  false,
		EncryptionKey: key,
		TOTP:          &theauth.TOTPConfig{Issuer: "TheAuth TOTP Demo"},
	})
	if err != nil {
		log.Fatal(err)
	}
	defer a.Close()

	r := chi.NewRouter()
	a.Mount(r)
	r.Get("/", indexHandler)

	slog.Info("listening", "addr", ":8080", "baseURL", baseURL)
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
<h1>TheAuth password + TOTP demo</h1>
<p>Flow: Signup, then Enroll TOTP, then Signout, then Signin (you get pending), then Verify.</p>
<input id="email" value="demo@example.com" /> <input id="pw" type="password" value="twelve-chars-min" />
<button id="signup">Signup</button>
<button id="signin">Signin</button>
<button id="signout">Signout</button>
<hr/>
<button id="enroll-begin">Enroll Begin</button>
<input id="enroll-id" placeholder="enrollmentId"/>
<input id="enroll-code" placeholder="6-digit code"/>
<button id="enroll-finish">Enroll Finish</button>
<hr/>
<input id="verify-code" placeholder="6-digit code"/>
<button id="verify">Verify</button>
<button id="me">/auth/me</button>
<pre id="out"></pre>
<script>
const out = document.getElementById('out');
const POST = (p, b) => fetch(p, {method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify(b||{})});
const DEL  = (p) => fetch(p, {method:'DELETE'});
async function show(r){ out.textContent = r.status + ' ' + await r.text(); }
document.getElementById('signup').onclick = async () => show(await POST('/auth/email-password/signup', {email: email.value, password: pw.value}));
document.getElementById('signin').onclick = async () => show(await POST('/auth/email-password/signin', {email: email.value, password: pw.value}));
document.getElementById('signout').onclick = async () => show(await DEL('/auth/sessions/current'));
document.getElementById('enroll-begin').onclick = async () => {
  const r = await POST('/auth/totp/enroll/begin');
  const j = await r.json();
  out.textContent = JSON.stringify(j, null, 2);
  document.getElementById('enroll-id').value = j.enrollmentId;
};
document.getElementById('enroll-finish').onclick = async () => show(await POST('/auth/totp/enroll/finish', {
  enrollmentId: document.getElementById('enroll-id').value,
  code: document.getElementById('enroll-code').value,
}));
document.getElementById('verify').onclick = async () => show(await POST('/auth/totp/verify', {code: document.getElementById('verify-code').value}));
document.getElementById('me').onclick = async () => show(await fetch('/auth/me'));
</script>
</body></html>`))
}

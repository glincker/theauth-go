package saml_test

import (
	"context"
	"testing"

	theauth "github.com/glincker/theauth-go/v2"
	"github.com/glincker/theauth-go/v2/internal/samltest"
	"github.com/glincker/theauth-go/v2/storage/memory"
)

// TestSAMLLoginFiresSigninHook proves OnSignin fires on every successful
// SAML login (new and returning users) and OnSignup only on the first.
func TestSAMLLoginFiresSigninHook(t *testing.T) {
	tests := []struct {
		name       string
		logins     int
		wantSignup int
		wantSignin int
	}{
		{"first login signs up and signs in", 1, 1, 1},
		{"returning login only signs in", 2, 1, 2},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			store := memory.New()
			certPEM, keyPEM, err := samltest.GenerateSPKeypair()
			if err != nil {
				t.Fatal(err)
			}
			var signups, signins int
			a, err := theauth.New(theauth.Config{
				Storage:       store,
				BaseURL:       "https://sp.example.test",
				Organizations: &theauth.OrganizationsConfig{},
				SAML:          &theauth.SAMLConfig{SPCertificatePEM: certPEM, SPPrivateKeyPEM: keyPEM},
				LifecycleHooks: &theauth.LifecycleHooks{
					OnSignup: func(context.Context, *theauth.User, theauth.SignupMethod) error { signups++; return nil },
					OnSignin: func(_ context.Context, u *theauth.User, s *theauth.Session) error {
						if u.ID != s.UserID {
							t.Errorf("hook user %v does not match session user %v", u.ID, s.UserID)
						}
						signins++
						return nil
					},
				},
			})
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(a.Close)
			_, conn := seedSAMLConnection(t, a, store)
			for i := 0; i < tc.logins; i++ {
				as := samltest.Default(conn.SPEntityID, conn.SPACSURL)
				as.Email = "hook-user@samltest.local"
				as.NameID = "saml-hook-user"
				resp, err := as.SignAndEncode()
				if err != nil {
					t.Fatal(err)
				}
				if _, _, err := a.FinishSAMLLogin(context.Background(), conn.ID, resp, "ua", "1.2.3.4"); err != nil {
					t.Fatalf("login %d: %v", i, err)
				}
			}
			if signups != tc.wantSignup || signins != tc.wantSignin {
				t.Fatalf("want signup=%d signin=%d; got signup=%d signin=%d", tc.wantSignup, tc.wantSignin, signups, signins)
			}
		})
	}
}

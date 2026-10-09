package crypto

import (
	"crypto/pbkdf2"
	"crypto/sha256"
	"crypto/sha512"
	"errors"
	"testing"
)

func TestVerifyLegacyPBKDF2(t *testing.T) {
	salt := []byte("0123456789abcdef")
	k256, err := pbkdf2.Key(sha256.New, "hunter2", salt, 27500, 64)
	if err != nil {
		t.Fatal(err)
	}
	k512, err := pbkdf2.Key(sha512.New, "hunter2", salt, 210000, 64)
	if err != nil {
		t.Fatal(err)
	}
	h256 := FormatPBKDF2Hash("pbkdf2-sha256", 27500, salt, k256)
	h512 := FormatPBKDF2Hash("pbkdf2-sha512", 210000, salt, k512)

	tests := []struct {
		name    string
		plain   string
		stored  string
		want    bool
		wantErr bool
	}{
		{"sha256 match", "hunter2", h256, true, false},
		{"sha256 mismatch", "hunter3", h256, false, false},
		{"sha512 match", "hunter2", h512, true, false},
		{"unknown algo", "x", "$pbkdf2-md5$1$AA==$AA==", false, true},
		{"iteration bomb", "x", "$pbkdf2-sha256$999999999$AA==$AA==", false, true},
		{"truncated", "x", "$pbkdf2-sha256$27500$AA==", false, true},
		{"bad base64", "x", "$pbkdf2-sha256$27500$!!$AA==", false, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := VerifyLegacyPBKDF2(tc.plain, tc.stored)
			if (err != nil) != tc.wantErr || got != tc.want {
				t.Fatalf("got (%v, %v), want (%v, err=%v)", got, err, tc.want, tc.wantErr)
			}
			if tc.wantErr && !errors.Is(err, ErrInvalidPasswordHash) {
				t.Fatalf("err = %v, want ErrInvalidPasswordHash", err)
			}
		})
	}
}

func TestLegacyFallbackAcceptsPBKDF2AndRehashes(t *testing.T) {
	salt := []byte("0123456789abcdef")
	key, _ := pbkdf2.Key(sha256.New, "hunter2", salt, 1000, 32)
	stored := FormatPBKDF2Hash("pbkdf2-sha256", 1000, salt, key)

	if _, _, err := VerifyPasswordWithLegacyFallback("hunter2", stored, false); !errors.Is(err, ErrInvalidPasswordHash) {
		t.Fatalf("legacy off: err = %v, want ErrInvalidPasswordHash", err)
	}
	ok, newHash, err := VerifyPasswordWithLegacyFallback("hunter2", stored, true)
	if err != nil || !ok || newHash == "" {
		t.Fatalf("legacy on: ok=%v newHash=%q err=%v", ok, newHash, err)
	}
	if again, err := VerifyPassword("hunter2", newHash); err != nil || !again {
		t.Fatalf("upgraded hash does not verify: %v %v", again, err)
	}
}

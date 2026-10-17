package models_test

import (
	"context"
	"reflect"
	"testing"
	"time"

	"github.com/glincker/theauth-go/v2/internal/models"
)

func TestMergeAuthMethods(t *testing.T) {
	got := models.MergeAuthMethods([]string{"pwd", "otp"}, "OTP", " mfa ", "", "pwd", "hwk")
	if want := []string{"pwd", "otp", "mfa", "hwk"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("merge = %v, want %v", got, want)
	}
	if got := models.MergeAuthMethods(nil); len(got) != 0 {
		t.Fatalf("merge of nothing = %v", got)
	}
	in := []string{"pwd"}
	_ = models.MergeAuthMethods(in, "otp")
	if len(in) != 1 {
		t.Fatal("merge mutated its input")
	}
}

func TestSessionMethodHelpers(t *testing.T) {
	s := models.Session{AuthMethods: []string{"pwd", "otp", "mfa"}}
	for _, tc := range []struct {
		name string
		got  bool
		want bool
	}{
		{"has pwd", s.HasMethod("pwd"), true},
		{"case and space", s.HasMethod(" OTP "), true},
		{"missing", s.HasMethod("hwk"), false},
		{"any hit", s.HasAnyMethod("hwk", "otp"), true},
		{"any miss", s.HasAnyMethod("hwk", "swk"), false},
		{"all hit", s.HasAllMethods("pwd", "mfa"), true},
		{"all miss", s.HasAllMethods("pwd", "hwk"), false},
		{"empty session", models.Session{}.HasMethod("pwd"), false},
	} {
		if tc.got != tc.want {
			t.Errorf("%s = %v, want %v", tc.name, tc.got, tc.want)
		}
	}
}

func TestAuthRecordContext(t *testing.T) {
	if rec := models.AuthRecordFrom(context.Background()); len(rec.Methods) != 0 {
		t.Fatalf("empty context carries %v", rec)
	}
	at := time.Unix(1700000000, 0)
	rec := models.AuthRecordFrom(models.WithAuthRecord(context.Background(), at, "pwd", "PWD", "otp"))
	if !reflect.DeepEqual(rec.Methods, []string{"pwd", "otp"}) || !rec.At.Equal(at) {
		t.Fatalf("record = %+v", rec)
	}
}

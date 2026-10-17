package main

import (
	"bytes"
	"context"
	"strings"
	"testing"

	theauth "github.com/glincker/theauth-go/v2"
)

func TestParseOptions(t *testing.T) {
	tests := []struct {
		name    string
		args    []string
		env     map[string]string
		want    options
		wantErr bool
	}{
		{name: "defaults", want: options{port: 3100}},
		{name: "env port", env: map[string]string{"THEAUTH_DEV_PORT": "4000"}, want: options{port: 4000}},
		{name: "flag beats env", args: []string{"--port", "5000"}, env: map[string]string{"THEAUTH_DEV_PORT": "4000"}, want: options{port: 5000}},
		{name: "equals form and smoke", args: []string{"--port=6000", "--smoke"}, want: options{port: 6000, smoke: true}},
		{name: "bad port", args: []string{"--port", "abc"}, wantErr: true},
		{name: "port out of range", args: []string{"--port=70000"}, wantErr: true},
		{name: "missing value", args: []string{"--port"}, wantErr: true},
		{name: "bad env", env: map[string]string{"THEAUTH_DEV_PORT": "x"}, wantErr: true},
		{name: "unknown flag", args: []string{"--nope"}, wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseOptions(tt.args, func(k string) string { return tt.env[k] })
			if (err != nil) != tt.wantErr {
				t.Fatalf("err = %v, wantErr %t", err, tt.wantErr)
			}
			if err == nil && got != tt.want {
				t.Fatalf("got %+v, want %+v", got, tt.want)
			}
		})
	}
}

func TestSmokeWalkthrough(t *testing.T) {
	tests := []struct {
		name string
		want []string
	}{
		{name: "smoke output", want: []string{
			"dev@example.com", "support-agent", "delegation",
			"ALLOWED search_tickets", "DENIED  delete_records",
			"hash chain verified", "smoke: ok",
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var out bytes.Buffer
			err := run(context.Background(), []string{"--smoke"}, func(string) string { return "" }, &out)
			if err != nil {
				t.Fatalf("run: %v", err)
			}
			for _, w := range tt.want {
				if !strings.Contains(out.String(), w) {
					t.Errorf("output missing %q:\n%s", w, out.String())
				}
			}
		})
	}
}

func TestCheckChain(t *testing.T) {
	mk := func(action string) theauth.AuditEvent {
		return theauth.AuditEvent{Action: action, Metadata: map[string]any{"k": action}}
	}
	tests := []struct {
		name    string
		tamper  func([]theauth.AuditEvent)
		wantErr bool
	}{
		{name: "intact", tamper: func([]theauth.AuditEvent) {}},
		{name: "edited event", tamper: func(e []theauth.AuditEvent) { e[1].Action = "evil" }, wantErr: true},
		{name: "reordered", tamper: func(e []theauth.AuditEvent) { e[0], e[2] = e[2], e[0] }, wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			events := []theauth.AuditEvent{mk("a"), mk("b"), mk("c")}
			links, err := buildChain(events)
			if err != nil {
				t.Fatal(err)
			}
			tt.tamper(events)
			if err := checkChain(events, links); (err != nil) != tt.wantErr {
				t.Fatalf("err = %v, wantErr %t", err, tt.wantErr)
			}
		})
	}
}

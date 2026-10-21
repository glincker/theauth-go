// Command mqtt-auth serves the broker authentication and authorization endpoints for EMQX (and,
// with MQTT_AUTH_MOSQUITTO=1, mosquitto-go-auth) on top of a SQLite device table.
//
// Environment:
//
//	MQTT_AUTH_ADDR           listen address, default 127.0.0.1:8090
//	MQTT_AUTH_DB             SQLite file, default mqtt-auth.db
//	MQTT_AUTH_BROKER_SECRET  bearer token the broker sends (required)
//	MQTT_AUTH_PURGE_SECRET   enables POST /purge when set
//	MQTT_AUTH_CACHE_TTL      cache TTL as a Go duration, default 5s
//	MQTT_AUTH_MOSQUITTO      set to 1 to mount the mosquitto-go-auth routes
//	MQTT_AUTH_SEED_TOKEN     when set, seeds device "demo-sensor" with this token
package main

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"time"

	"github.com/glincker/theauth-go/v2/iot/mqttauth"
	_ "modernc.org/sqlite"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "mqtt-auth:", err)
		os.Exit(1)
	}
}

func env(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func run() error {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	db, err := sql.Open("sqlite", env("MQTT_AUTH_DB", "mqtt-auth.db")+"?_pragma=foreign_keys(1)&_pragma=busy_timeout(5000)")
	if err != nil {
		return err
	}
	defer db.Close()
	store := &mqttauth.SQLStore{DB: db}
	if err := store.EnsureSchema(ctx); err != nil {
		return err
	}
	if tok := os.Getenv("MQTT_AUTH_SEED_TOKEN"); tok != "" {
		if err := seed(ctx, store, tok); err != nil {
			return err
		}
	}
	ttl, err := time.ParseDuration(env("MQTT_AUTH_CACHE_TTL", "5s"))
	if err != nil {
		return fmt.Errorf("MQTT_AUTH_CACHE_TTL: %w", err)
	}
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	h, err := mqttauth.New(mqttauth.Config{
		Store:        store,
		BrokerSecret: os.Getenv("MQTT_AUTH_BROKER_SECRET"),
		PurgeSecret:  os.Getenv("MQTT_AUTH_PURGE_SECRET"),
		CacheTTL:     ttl,
		Mosquitto:    os.Getenv("MQTT_AUTH_MOSQUITTO") == "1",
		Audit:        mqttauth.SlogSink(logger),
		Logger:       logger,
	})
	if err != nil {
		return err
	}
	mux := http.NewServeMux()
	mux.Handle("/mqtt/", http.StripPrefix("/mqtt", h))
	mux.Handle("GET /metrics", h.MetricsHandler())
	srv := &http.Server{Addr: env("MQTT_AUTH_ADDR", "127.0.0.1:8090"), Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	go func() {
		<-ctx.Done()
		sctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(sctx)
	}()
	logger.Info("listening", "addr", srv.Addr)
	if err := srv.ListenAndServe(); !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

// seed registers one device that may publish its own telemetry and read its commands.
func seed(ctx context.Context, store mqttauth.DeviceWriter, token string) error {
	return store.PutDevice(ctx, mqttauth.Device{
		ID: "demo-sensor", Status: mqttauth.StatusActive, TokenHashes: []string{mqttauth.HashToken(token)},
		Rules: []mqttauth.Rule{
			{Effect: mqttauth.Allow, Action: mqttauth.ActionPublish, Filter: "devices/{device_id}/telemetry/#"},
			{Effect: mqttauth.Allow, Action: mqttauth.ActionSubscribe, Filter: "devices/{device_id}/cmd/+"},
		},
	})
}

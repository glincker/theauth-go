// Package redispurge is a mqttauth.PurgeBroadcaster over Redis PUBLISH and SUBSCRIBE, for
// deployments of the MQTT broker auth service that already run Redis. It speaks RESP2 over the
// standard library (no Redis client dependency), supports AUTH (password, or ACL user and
// password) and TLS, and uses only PUBLISH, SUBSCRIBE, PING and AUTH.
//
// Redis pub/sub is fire and forget: a message sent while a replica is disconnected is lost.
// Subscribe therefore reports an empty device ID (purge everything) after every reconnect, the
// same rule the Postgres and MySQL broadcasters follow.
package redispurge

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"time"
)

// DefaultChannel is the pub/sub channel used when Config.Channel is empty.
const DefaultChannel = "theauth_device_purge"

const (
	reconnectDelay = time.Second
	pingEvery      = 20 * time.Second
	readTimeout    = 3 * pingEvery
)

// Config builds a Broadcaster.
type Config struct {
	// Addr is host:port of the Redis server. Required.
	Addr string
	// Username and Password are sent with AUTH when Password is set. Username is for Redis 6 ACLs.
	Username string
	Password string
	// TLS, when non-nil, wraps the connection.
	TLS *tls.Config
	// Channel is the pub/sub channel. Empty means DefaultChannel. Use one channel per deployment.
	Channel string
	// DialTimeout bounds connecting and the AUTH round trip. Zero means 5 seconds.
	DialTimeout time.Duration
}

// Broadcaster implements mqttauth.PurgeBroadcaster.
type Broadcaster struct {
	cfg Config
}

// New validates cfg and returns a Broadcaster. It does not connect.
func New(cfg Config) (*Broadcaster, error) {
	if cfg.Addr == "" {
		return nil, errors.New("redispurge: Addr is required")
	}
	if cfg.Channel == "" {
		cfg.Channel = DefaultChannel
	}
	if cfg.DialTimeout <= 0 {
		cfg.DialTimeout = 5 * time.Second
	}
	return &Broadcaster{cfg: cfg}, nil
}

func (b *Broadcaster) dial(ctx context.Context) (net.Conn, *bufio.Reader, error) {
	d := &net.Dialer{Timeout: b.cfg.DialTimeout, KeepAlive: 15 * time.Second}
	var conn net.Conn
	var err error
	if b.cfg.TLS != nil {
		conn, err = (&tls.Dialer{NetDialer: d, Config: b.cfg.TLS}).DialContext(ctx, "tcp", b.cfg.Addr)
	} else {
		conn, err = d.DialContext(ctx, "tcp", b.cfg.Addr)
	}
	if err != nil {
		return nil, nil, err
	}
	r := bufio.NewReader(conn)
	if b.cfg.Password != "" {
		_ = conn.SetDeadline(time.Now().Add(b.cfg.DialTimeout))
		args := []string{"AUTH"}
		if b.cfg.Username != "" {
			args = append(args, b.cfg.Username)
		}
		args = append(args, b.cfg.Password)
		if err := writeCommand(conn, args...); err != nil {
			_ = conn.Close()
			return nil, nil, err
		}
		rep, err := readReply(r)
		if err != nil || rep.kind == '-' {
			_ = conn.Close()
			if err == nil {
				err = fmt.Errorf("redispurge: AUTH refused: %s", rep.str)
			}
			return nil, nil, err
		}
		_ = conn.SetDeadline(time.Time{})
	}
	return conn, r, nil
}

// Publish sends a purge for deviceID, or for everything when deviceID is empty. It uses a short
// lived connection: revokes are rare, and it keeps Publish safe to call from any goroutine.
func (b *Broadcaster) Publish(ctx context.Context, deviceID string) error {
	conn, r, err := b.dial(ctx)
	if err != nil {
		return fmt.Errorf("redispurge: publish: %w", err)
	}
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(b.cfg.DialTimeout))
	if err := writeCommand(conn, "PUBLISH", b.cfg.Channel, deviceID); err != nil {
		return fmt.Errorf("redispurge: publish: %w", err)
	}
	rep, err := readReply(r)
	if err != nil {
		return fmt.Errorf("redispurge: publish: %w", err)
	}
	if rep.kind == '-' {
		return fmt.Errorf("redispurge: publish refused: %s", rep.str)
	}
	return nil
}

// Subscribe listens until ctx ends and returns nil then. A lost connection is retried forever
// after a short pause, and fn("") runs after each reconnect.
func (b *Broadcaster) Subscribe(ctx context.Context, fn func(deviceID string)) error {
	first := true
	for ctx.Err() == nil {
		err := b.listen(ctx, fn, !first)
		first = false
		if ctx.Err() != nil {
			return nil
		}
		slog.Warn("redispurge: subscriber lost, reconnecting", "channel", b.cfg.Channel, "err", fmt.Sprint(err))
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(reconnectDelay):
		}
	}
	return nil
}

func (b *Broadcaster) listen(ctx context.Context, fn func(string), afterGap bool) error {
	conn, r, err := b.dial(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = conn.Close() }()
	if err := writeCommand(conn, "SUBSCRIBE", b.cfg.Channel); err != nil {
		return err
	}
	_ = conn.SetReadDeadline(time.Now().Add(b.cfg.DialTimeout))
	ack, err := readReply(r)
	if err != nil {
		return err
	}
	if ack.kind == '-' {
		return fmt.Errorf("redispurge: SUBSCRIBE refused: %s", ack.str)
	}
	if afterGap {
		fn("")
	}
	// Close the connection when ctx ends so the blocking read returns.
	stop := make(chan struct{})
	defer close(stop)
	go func() {
		pt := time.NewTicker(pingEvery)
		defer pt.Stop()
		for {
			select {
			case <-ctx.Done():
				_ = conn.Close()
				return
			case <-stop:
				return
			case <-pt.C:
				if writeCommand(conn, "PING") != nil {
					return
				}
			}
		}
	}()
	for {
		_ = conn.SetReadDeadline(time.Now().Add(readTimeout))
		rep, err := readReply(r)
		if err != nil {
			return err
		}
		if rep.kind != '*' || len(rep.items) < 3 {
			continue // pong, or something we do not act on
		}
		if rep.items[0].str == "message" && rep.items[1].str == b.cfg.Channel {
			fn(rep.items[2].str)
		}
	}
}

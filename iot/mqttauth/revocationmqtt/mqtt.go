package revocationmqtt

// mqtt.go is the small slice of MQTT 3.1.1 (OASIS, 2014) this package needs: CONNECT, PUBLISH with
// the retain flag at QoS 0 or 1, SUBSCRIBE at QoS 1, PINGREQ and DISCONNECT. It is standard library
// only, like the rest of iot. MQTT 3.1.1 is spoken by Mosquitto, EMQX and HiveMQ alike. Anything a
// real client library does beyond this (QoS 2, sessions, auto reconnect of publishes) is not here.

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"time"
)

// ConnectOptions says how to reach and log in to the broker.
type ConnectOptions struct {
	// Addr is host:port. Port 1883 is plain TCP, 8883 is TLS (set TLS).
	Addr string
	// TLS, when non-nil, wraps the connection in TLS. Use it: the snapshot is signed, but the
	// password is not.
	TLS *tls.Config
	// ClientID defaults to "theauth-revocations". A broker drops an older session with the same id.
	ClientID string
	// Username and Password are sent when Username is not empty.
	Username string
	Password string
	// KeepAlive defaults to 30s.
	KeepAlive time.Duration
	// Timeout bounds dialing, CONNACK and each PUBACK or SUBACK wait. Default 10s.
	Timeout time.Duration
	// MaxPacket is the largest packet accepted from the broker, default 1 MiB.
	MaxPacket int
}

func (o ConnectOptions) withDefaults() ConnectOptions {
	if o.ClientID == "" {
		o.ClientID = "theauth-revocations"
	}
	if o.KeepAlive <= 0 {
		o.KeepAlive = 30 * time.Second
	}
	if o.Timeout <= 0 {
		o.Timeout = 10 * time.Second
	}
	if o.MaxPacket <= 0 {
		o.MaxPacket = 1 << 20
	}
	return o
}

// Packet types (first byte, high nibble).
const (
	typeConnect   = 1
	typeConnack   = 2
	typePublish   = 3
	typePuback    = 4
	typeSubscribe = 8
	typeSuback    = 9
	typePingreq   = 12
	typePingresp  = 13
	typeDisconn   = 14
)

// message is a PUBLISH received from the broker.
type message struct {
	Topic   string
	Payload []byte
	Retain  bool
}

type client struct {
	c      net.Conn
	r      *bufio.Reader
	opts   ConnectOptions
	wmu    sync.Mutex
	nextID uint16
}

// dial opens the connection and completes the CONNECT handshake.
func dial(ctx context.Context, o ConnectOptions) (*client, error) {
	o = o.withDefaults()
	if o.Addr == "" {
		return nil, errors.New("revocationmqtt: Addr is required")
	}
	d := net.Dialer{Timeout: o.Timeout}
	var nc net.Conn
	var err error
	if o.TLS != nil {
		nc, err = (&tls.Dialer{NetDialer: &d, Config: o.TLS}).DialContext(ctx, "tcp", o.Addr)
	} else {
		nc, err = d.DialContext(ctx, "tcp", o.Addr)
	}
	if err != nil {
		return nil, fmt.Errorf("revocationmqtt: dial: %w", err)
	}
	cl := &client{c: nc, r: bufio.NewReader(nc), opts: o}
	if err := cl.handshake(); err != nil {
		_ = nc.Close()
		return nil, err
	}
	return cl, nil
}

func (cl *client) handshake() error {
	o := cl.opts
	flags := byte(0x02) // clean session
	body := appendString(nil, "MQTT")
	body = append(body, 4) // protocol level 4 is MQTT 3.1.1
	if o.Username != "" {
		flags |= 0x80
		if o.Password != "" {
			flags |= 0x40
		}
	}
	body = append(body, flags, byte(int(o.KeepAlive.Seconds())>>8), byte(int(o.KeepAlive.Seconds())))
	body = appendString(body, o.ClientID)
	if o.Username != "" {
		body = appendString(body, o.Username)
		if o.Password != "" {
			body = appendString(body, o.Password)
		}
	}
	_ = cl.c.SetDeadline(time.Now().Add(o.Timeout))
	if err := cl.write(typeConnect<<4, body); err != nil {
		return err
	}
	typ, _, p, err := cl.read()
	if err != nil {
		return err
	}
	if typ != typeConnack || len(p) != 2 {
		return errors.New("revocationmqtt: broker did not answer CONNECT with CONNACK")
	}
	if p[1] != 0 {
		return fmt.Errorf("revocationmqtt: broker refused the connection (CONNACK code %d)", p[1])
	}
	_ = cl.c.SetDeadline(time.Time{})
	return nil
}

func (cl *client) close() {
	_ = cl.c.SetWriteDeadline(time.Now().Add(time.Second))
	_ = cl.write(typeDisconn<<4, nil)
	_ = cl.c.Close()
}

func (cl *client) id() uint16 {
	cl.nextID++
	if cl.nextID == 0 {
		cl.nextID = 1
	}
	return cl.nextID
}

// publish sends one PUBLISH. At QoS 1 it waits for the matching PUBACK.
func (cl *client) publish(topic string, payload []byte, retain bool, qos byte) error {
	flags := byte(typePublish<<4) | qos<<1
	if retain {
		flags |= 1
	}
	body := appendString(nil, topic)
	var id uint16
	if qos > 0 {
		id = cl.id()
		body = append(body, byte(id>>8), byte(id))
	}
	body = append(body, payload...)
	_ = cl.c.SetDeadline(time.Now().Add(cl.opts.Timeout))
	defer func() { _ = cl.c.SetDeadline(time.Time{}) }()
	if err := cl.write(flags, body); err != nil {
		return err
	}
	if qos == 0 {
		return nil
	}
	for {
		typ, _, p, err := cl.read()
		if err != nil {
			return err
		}
		if typ == typePuback && len(p) == 2 && uint16(p[0])<<8|uint16(p[1]) == id {
			return nil
		}
	}
}

// subscribe asks for one filter at QoS 1 and waits for the SUBACK. A PUBLISH that arrives first
// (a retained message can overtake nothing, but a broker may interleave) is returned in early.
func (cl *client) subscribe(filter string) (early []message, err error) {
	id := cl.id()
	body := append([]byte{byte(id >> 8), byte(id)}, appendString(nil, filter)...)
	body = append(body, 1)
	_ = cl.c.SetDeadline(time.Now().Add(cl.opts.Timeout))
	defer func() { _ = cl.c.SetDeadline(time.Time{}) }()
	if err := cl.write(typeSubscribe<<4|2, body); err != nil {
		return nil, err
	}
	for {
		typ, flags, p, err := cl.read()
		if err != nil {
			return nil, err
		}
		switch typ {
		case typeSuback:
			if len(p) < 3 || uint16(p[0])<<8|uint16(p[1]) != id {
				return nil, errors.New("revocationmqtt: unexpected SUBACK")
			}
			if p[2] == 0x80 {
				return early, errors.New("revocationmqtt: broker refused the subscription (check the topic ACL)")
			}
			return early, nil
		case typePublish:
			m, err := cl.parsePublish(flags, p)
			if err != nil {
				return nil, err
			}
			early = append(early, m)
		}
	}
}

// next blocks for the next PUBLISH. It sends PINGREQ at half the keep alive interval and fails if the
// broker is silent for one and a half intervals (MQTT 3.1.1 section 3.1.2.10).
func (cl *client) next(ctx context.Context) (message, error) {
	stop := make(chan struct{})
	defer close(stop)
	go func() {
		t := time.NewTicker(cl.opts.KeepAlive / 2)
		defer t.Stop()
		for {
			select {
			case <-t.C:
				_ = cl.write(typePingreq<<4, nil)
			case <-ctx.Done():
				_ = cl.c.SetReadDeadline(time.Now())
				return
			case <-stop:
				return
			}
		}
	}()
	for {
		_ = cl.c.SetReadDeadline(time.Now().Add(cl.opts.KeepAlive * 3 / 2))
		typ, flags, p, err := cl.read()
		if err != nil {
			if ctx.Err() != nil {
				return message{}, ctx.Err()
			}
			return message{}, err
		}
		if typ == typePublish {
			return cl.parsePublish(flags, p)
		}
	}
}

// parsePublish decodes an incoming PUBLISH and acknowledges QoS 1.
func (cl *client) parsePublish(flags byte, p []byte) (message, error) {
	qos := flags >> 1 & 3
	if qos == 3 || qos == 2 {
		return message{}, errors.New("revocationmqtt: broker sent a QoS 2 message that was not requested")
	}
	if len(p) < 2 {
		return message{}, errors.New("revocationmqtt: short PUBLISH")
	}
	n := int(p[0])<<8 | int(p[1])
	if len(p) < 2+n {
		return message{}, errors.New("revocationmqtt: short PUBLISH topic")
	}
	m := message{Topic: string(p[2 : 2+n]), Retain: flags&1 == 1}
	rest := p[2+n:]
	if qos == 1 {
		if len(rest) < 2 {
			return message{}, errors.New("revocationmqtt: PUBLISH without packet id")
		}
		if err := cl.write(typePuback<<4, rest[:2]); err != nil {
			return message{}, err
		}
		rest = rest[2:]
	}
	m.Payload = append([]byte(nil), rest...)
	return m, nil
}

func (cl *client) write(first byte, body []byte) error {
	buf := []byte{first}
	for n := len(body); ; {
		b := byte(n % 128)
		n /= 128
		if n > 0 {
			b |= 0x80
		}
		buf = append(buf, b)
		if n == 0 {
			break
		}
	}
	buf = append(buf, body...)
	cl.wmu.Lock()
	defer cl.wmu.Unlock()
	_, err := cl.c.Write(buf)
	return err
}

func (cl *client) read() (typ, flags byte, body []byte, err error) {
	first, err := cl.r.ReadByte()
	if err != nil {
		return 0, 0, nil, err
	}
	n, mult := 0, 1
	for i := 0; ; i++ {
		if i == 4 {
			return 0, 0, nil, errors.New("revocationmqtt: bad remaining length")
		}
		b, err := cl.r.ReadByte()
		if err != nil {
			return 0, 0, nil, err
		}
		n += int(b&0x7f) * mult
		mult *= 128
		if b&0x80 == 0 {
			break
		}
	}
	if n > cl.opts.MaxPacket {
		return 0, 0, nil, fmt.Errorf("revocationmqtt: packet of %d bytes exceeds MaxPacket", n)
	}
	body = make([]byte, n)
	if _, err := io.ReadFull(cl.r, body); err != nil {
		return 0, 0, nil, err
	}
	return first >> 4, first & 0x0f, body, nil
}

func appendString(b []byte, s string) []byte {
	return append(append(b, byte(len(s)>>8), byte(len(s))), s...)
}

// validTopicName reports whether s may be published to: not empty, at most 65535 bytes, no NUL and no
// wildcard (MQTT 3.1.1 sections 4.7.1 and 4.7.3).
func validTopicName(s string) bool {
	return s != "" && len(s) <= 65535 && !strings.ContainsAny(s, "+#\x00")
}

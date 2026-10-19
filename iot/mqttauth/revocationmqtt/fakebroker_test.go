package revocationmqtt

import (
	"bufio"
	"io"
	"net"
	"strings"
	"sync"
	"testing"
)

// fakeBroker is just enough of an MQTT 3.1.1 broker to test the client: CONNECT with an optional
// username check, retained PUBLISH (an empty payload clears), SUBSCRIBE with an optional deny list,
// delivery to subscribers, and PINGREQ.
type fakeBroker struct {
	t        *testing.T
	ln       net.Listener
	user     string // when set, CONNECT must carry this username
	denySub  bool
	mu       sync.Mutex
	retained map[string]fakeMsg
	subs     map[*fakeConn][]string
	conns    []net.Conn
	wg       sync.WaitGroup
	// PublishCount counts PUBLISH packets received from clients.
	published []fakeMsg
}

type fakeMsg struct {
	Topic   string
	Payload []byte
	Retain  bool
	QoS     byte
}

type fakeConn struct {
	c  net.Conn
	mu sync.Mutex
}

func newFakeBroker(t *testing.T) *fakeBroker {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	b := &fakeBroker{t: t, ln: ln, retained: map[string]fakeMsg{}, subs: map[*fakeConn][]string{}}
	b.wg.Add(1)
	go b.accept()
	t.Cleanup(func() {
		_ = ln.Close()
		b.mu.Lock()
		for _, c := range b.conns {
			_ = c.Close()
		}
		b.mu.Unlock()
		b.wg.Wait()
	})
	return b
}

func (b *fakeBroker) addr() string { return b.ln.Addr().String() }

func (b *fakeBroker) accept() {
	defer b.wg.Done()
	for {
		c, err := b.ln.Accept()
		if err != nil {
			return
		}
		b.mu.Lock()
		b.conns = append(b.conns, c)
		b.mu.Unlock()
		b.wg.Add(1)
		go b.serve(&fakeConn{c: c})
	}
}

func (fc *fakeConn) send(first byte, body []byte) {
	buf := []byte{first}
	for n := len(body); ; {
		d := byte(n % 128)
		n /= 128
		if n > 0 {
			d |= 0x80
		}
		buf = append(buf, d)
		if n == 0 {
			break
		}
	}
	fc.mu.Lock()
	defer fc.mu.Unlock()
	_, _ = fc.c.Write(append(buf, body...))
}

func readFake(r *bufio.Reader) (first byte, body []byte, err error) {
	first, err = r.ReadByte()
	if err != nil {
		return
	}
	n, mult := 0, 1
	for {
		var d byte
		if d, err = r.ReadByte(); err != nil {
			return
		}
		n += int(d&0x7f) * mult
		mult *= 128
		if d&0x80 == 0 {
			break
		}
	}
	body = make([]byte, n)
	_, err = io.ReadFull(r, body)
	return
}

func publishBody(m fakeMsg, id uint16) (byte, []byte) {
	first := byte(3<<4) | m.QoS<<1
	if m.Retain {
		first |= 1
	}
	body := appendString(nil, m.Topic)
	if m.QoS > 0 {
		body = append(body, byte(id>>8), byte(id))
	}
	return first, append(body, m.Payload...)
}

func (b *fakeBroker) serve(fc *fakeConn) {
	defer b.wg.Done()
	defer func() {
		b.mu.Lock()
		delete(b.subs, fc)
		b.mu.Unlock()
		_ = fc.c.Close()
	}()
	r := bufio.NewReader(fc.c)
	for {
		first, body, err := readFake(r)
		if err != nil {
			return
		}
		switch first >> 4 {
		case 1: // CONNECT
			code := byte(0)
			if b.user != "" && !strings.Contains(string(body), b.user) {
				code = 5
			}
			fc.send(2<<4, []byte{0, code})
			if code != 0 {
				return
			}
		case 3: // PUBLISH
			qos := first >> 1 & 3
			n := int(body[0])<<8 | int(body[1])
			m := fakeMsg{Topic: string(body[2 : 2+n]), Retain: first&1 == 1, QoS: qos}
			rest := body[2+n:]
			if qos > 0 {
				fc.send(4<<4, rest[:2])
				rest = rest[2:]
			}
			m.Payload = append([]byte(nil), rest...)
			b.deliver(m)
		case 8: // SUBSCRIBE
			id := body[:2]
			n := int(body[2])<<8 | int(body[3])
			filter := string(body[4 : 4+n])
			if b.denySub {
				fc.send(9<<4, append(append([]byte(nil), id...), 0x80))
				continue
			}
			fc.send(9<<4, append(append([]byte(nil), id...), 1))
			b.mu.Lock()
			b.subs[fc] = append(b.subs[fc], filter)
			ret, ok := b.retained[filter]
			b.mu.Unlock()
			if ok {
				ret.QoS = 0
				ret.Retain = true
				f, bd := publishBody(ret, 0)
				fc.send(f, bd)
			}
		case 12: // PINGREQ
			fc.send(13<<4, nil)
		case 14: // DISCONNECT
			return
		}
	}
}

func (b *fakeBroker) deliver(m fakeMsg) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.published = append(b.published, m)
	if m.Retain {
		if len(m.Payload) == 0 {
			delete(b.retained, m.Topic)
		} else {
			b.retained[m.Topic] = m
		}
	}
	for fc, filters := range b.subs {
		for _, f := range filters {
			if f == m.Topic {
				out := m
				out.QoS, out.Retain = 0, false // live delivery clears the retain flag
				first, body := publishBody(out, 0)
				go fc.send(first, body)
			}
		}
	}
}

func (b *fakeBroker) retainedFor(topic string) (fakeMsg, bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	m, ok := b.retained[topic]
	return m, ok
}

func (b *fakeBroker) publishedMsgs() []fakeMsg {
	b.mu.Lock()
	defer b.mu.Unlock()
	return append([]fakeMsg(nil), b.published...)
}

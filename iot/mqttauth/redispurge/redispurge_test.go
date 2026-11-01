package redispurge

import (
	"bufio"
	"context"
	"net"
	"os/exec"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/glincker/theauth-go/v2/iot/mqttauth"
)

var _ mqttauth.PurgeBroadcaster = (*Broadcaster)(nil)

type sink struct {
	mu  sync.Mutex
	ids []string
}

func (s *sink) add(id string) {
	s.mu.Lock()
	s.ids = append(s.ids, id)
	s.mu.Unlock()
}

func (s *sink) wait(t *testing.T, want []string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		s.mu.Lock()
		got := append([]string(nil), s.ids...)
		s.mu.Unlock()
		if strings.Join(got, "|") == strings.Join(want, "|") {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("purges = %q, want %q", got, want)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestNewRequiresAddr(t *testing.T) {
	if _, err := New(Config{}); err == nil {
		t.Fatal("expected an error without Addr")
	}
}

func TestRESPRoundTrip(t *testing.T) {
	var sb strings.Builder
	if err := writeCommand(&sb, "PUBLISH", "c", ""); err != nil {
		t.Fatal(err)
	}
	if sb.String() != "*3\r\n$7\r\nPUBLISH\r\n$1\r\nc\r\n$0\r\n\r\n" {
		t.Fatalf("encoding: %q", sb.String())
	}
	rep, err := readReply(bufio.NewReader(strings.NewReader("*3\r\n$7\r\nmessage\r\n$1\r\nc\r\n$0\r\n\r\n")))
	if err != nil || len(rep.items) != 3 || rep.items[0].str != "message" || rep.items[2].str != "" {
		t.Fatalf("decode: %+v %v", rep, err)
	}
	for _, bad := range []string{"$99999999\r\n", "*99\r\n", "?x\r\n", "$3\r\nab\r\n", "+ok\n"} {
		if _, err := readReply(bufio.NewReader(strings.NewReader(bad))); err == nil {
			t.Fatalf("expected an error for %q", bad)
		}
	}
}

// startRedis runs a throwaway redis-server on a free port. Skips when the binary is missing.
func startRedis(t *testing.T) (addr string, stop func()) {
	t.Helper()
	bin, err := exec.LookPath("redis-server")
	if err != nil {
		t.Skip("redis-server not installed")
	}
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr = l.Addr().String()
	_ = l.Close()
	port := addr[strings.LastIndex(addr, ":")+1:]
	cmd := exec.Command(bin, "--port", port, "--bind", "127.0.0.1", "--save", "", "--appendonly", "no", "--dir", t.TempDir())
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	stop = func() { _ = cmd.Process.Kill(); _, _ = cmd.Process.Wait() }
	deadline := time.Now().Add(5 * time.Second)
	for {
		c, err := net.Dial("tcp", addr)
		if err == nil {
			_ = c.Close()
			return addr, stop
		}
		if time.Now().After(deadline) {
			stop()
			t.Fatal("redis-server did not start")
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func TestBroadcastAgainstRedis(t *testing.T) {
	addr, stop := startRedis(t)
	defer stop()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	b, err := New(Config{Addr: addr, Channel: "purge_test"})
	if err != nil {
		t.Fatal(err)
	}
	var a, c sink
	done := make(chan error, 2)
	go func() { done <- b.Subscribe(ctx, a.add) }()
	go func() { done <- b.Subscribe(ctx, c.add) }()
	// Wait until redis reports two subscribers.
	deadline := time.Now().Add(5 * time.Second)
	for {
		conn, r, err := b.dial(ctx)
		if err != nil {
			t.Fatal(err)
		}
		_ = writeCommand(conn, "PUBSUB", "NUMSUB", "purge_test")
		rep, _ := readReply(r)
		_ = conn.Close()
		if len(rep.items) == 2 && rep.items[1].str == "2" {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("subscribers not up")
		}
		time.Sleep(20 * time.Millisecond)
	}
	want := []string{"01J00000000000000000000001", ""}
	for _, id := range want {
		if err := b.Publish(ctx, id); err != nil {
			t.Fatal(err)
		}
	}
	a.wait(t, want)
	c.wait(t, want)

	other, _ := New(Config{Addr: addr, Channel: "purge_other"})
	if err := other.Publish(ctx, "elsewhere"); err != nil {
		t.Fatal(err)
	}
	time.Sleep(100 * time.Millisecond)
	a.wait(t, want)

	cancel()
	for i := 0; i < 2; i++ {
		select {
		case err := <-done:
			if err != nil {
				t.Fatalf("Subscribe returned %v on cancel", err)
			}
		case <-time.After(5 * time.Second):
			t.Fatal("Subscribe did not return after cancel")
		}
	}
}

func TestReconnectPurgesAll(t *testing.T) {
	addr, stop := startRedis(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	b, _ := New(Config{Addr: addr, Channel: "purge_gap"})
	var s sink
	done := make(chan error, 1)
	go func() { done <- b.Subscribe(ctx, s.add) }()
	time.Sleep(300 * time.Millisecond)
	stop() // the server dies, the subscriber loses its connection
	// A new server on the same port: subscriber reconnects and must report a gap.
	bin, _ := exec.LookPath("redis-server")
	port := addr[strings.LastIndex(addr, ":")+1:]
	cmd := exec.Command(bin, "--port", port, "--bind", "127.0.0.1", "--save", "", "--appendonly", "no", "--dir", t.TempDir())
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = cmd.Process.Kill(); _, _ = cmd.Process.Wait() }()
	s.wait(t, []string{""})
	cancel()
	<-done
}

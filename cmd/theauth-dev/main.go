// Command theauth-dev starts a local in-memory TheAuth server and walks the agent flow end to end:
// a seeded user and agent, a delegation, allowed and denied guarded tool calls, and a verified
// audit chain. Nothing is persisted or leaves 127.0.0.1.
package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"
)

const defaultPort = 3100

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := run(ctx, os.Args[1:], os.Getenv, os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, "theauth-dev:", err)
		os.Exit(1)
	}
}

type options struct {
	port  int
	smoke bool
}

// parseOptions reads --port and --smoke. The port defaults to
// THEAUTH_DEV_PORT, then 3100.
func parseOptions(args []string, getenv func(string) string) (options, error) {
	opts := options{port: defaultPort}
	if v := getenv("THEAUTH_DEV_PORT"); v != "" {
		p, err := parsePort(v)
		if err != nil {
			return opts, fmt.Errorf("THEAUTH_DEV_PORT: %w", err)
		}
		opts.port = p
	}
	for i := 0; i < len(args); i++ {
		switch a := args[i]; {
		case a == "--smoke" || a == "-smoke":
			opts.smoke = true
		case a == "--port" || a == "-port":
			if i+1 >= len(args) {
				return opts, errors.New("--port needs a value")
			}
			i++
			p, err := parsePort(args[i])
			if err != nil {
				return opts, fmt.Errorf("--port: %w", err)
			}
			opts.port = p
		case len(a) > 7 && a[:7] == "--port=":
			p, err := parsePort(a[7:])
			if err != nil {
				return opts, fmt.Errorf("--port: %w", err)
			}
			opts.port = p
		default:
			return opts, fmt.Errorf("unknown argument %q (flags: --port, --smoke)", a)
		}
	}
	return opts, nil
}

func parsePort(s string) (int, error) {
	p, err := strconv.Atoi(s)
	if err != nil || p < 0 || p > 65535 {
		return 0, fmt.Errorf("%q is not a valid port", s)
	}
	return p, nil
}

func run(ctx context.Context, args []string, getenv func(string) string, out io.Writer) error {
	opts, err := parseOptions(args, getenv)
	if err != nil {
		return err
	}
	env, err := newEnv(ctx)
	if err != nil {
		return err
	}
	defer env.close()

	if err := walkthrough(ctx, env, out); err != nil {
		return err
	}
	if opts.smoke {
		say(out, "smoke: ok")
		return nil
	}
	return serve(ctx, env, opts.port, out)
}

// serve exposes the library handler on loopback until ctx is cancelled.
func serve(ctx context.Context, env *devEnv, port int, out io.Writer) error {
	ln, err := net.Listen("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)))
	if err != nil {
		return fmt.Errorf("listen: %w", err)
	}
	srv := &http.Server{Handler: env.auth.Handler(), ReadHeaderTimeout: 10 * time.Second}
	sayf(out, "\nServing on http://%s (Ctrl+C to stop)\n", ln.Addr())
	errc := make(chan error, 1)
	go func() { errc <- srv.Serve(ln) }()
	select {
	case <-ctx.Done():
		shutdown, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		return srv.Shutdown(shutdown)
	case err := <-errc:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	}
}

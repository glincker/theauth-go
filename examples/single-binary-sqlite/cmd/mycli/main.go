// Command mycli signs in to the server with the device grant and calls its API.
package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/signal"

	"github.com/glincker/theauth-go/clientauth"
)

const app = "mycli"

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	if err := run(ctx, os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func run(ctx context.Context, args []string) error {
	server := os.Getenv("MYCLI_SERVER")
	if len(args) == 0 || server == "" {
		return errors.New("usage: MYCLI_SERVER=http://localhost:8080 mycli login|whoami|logout|get <path>")
	}
	store, err := clientauth.NewFileStore(app)
	if err != nil {
		return err
	}
	client, err := clientauth.NewClient(server, store)
	if err != nil {
		return err
	}
	switch args[0] {
	case "login":
		cred, err := clientauth.DeviceLogin(ctx, clientauth.DeviceOptions{ServerURL: server, ClientName: app, Store: store})
		if err != nil {
			return err
		}
		fmt.Println("logged in, token expires", cred.ExpiresAt.Format("2006-01-02"))
	case "whoami":
		id, err := client.Whoami(ctx)
		if err != nil {
			return reloginHint(err)
		}
		fmt.Println(id.Name, id.Abilities)
	case "logout":
		return client.Logout(ctx)
	case "get":
		if len(args) < 2 {
			return errors.New("get needs a path")
		}
		req, err := client.NewRequest(ctx, http.MethodGet, args[1], nil)
		if err != nil {
			return err
		}
		resp, err := client.Do(req)
		if err != nil {
			return reloginHint(err)
		}
		defer func() { _ = resp.Body.Close() }()
		_, err = io.Copy(os.Stdout, resp.Body)
		return err
	default:
		return fmt.Errorf("unknown command %q", args[0])
	}
	return nil
}

func reloginHint(err error) error {
	if errors.Is(err, clientauth.ErrReloginRequired) || errors.Is(err, clientauth.ErrNotLoggedIn) {
		return fmt.Errorf("%w (run: %s login)", err, app)
	}
	return err
}

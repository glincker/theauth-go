package otp

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/glincker/theauth-go/v2/email"
)

// EmailSender adapts an email.Sender. Subject and Body may be nil, in which
// case plain defaults are used.
type EmailSender struct {
	Mailer  email.Sender
	Subject func(Message) string
	Body    func(Message) string
}

// Send implements Sender.
func (e EmailSender) Send(ctx context.Context, m Message) error {
	if e.Mailer == nil {
		return errors.New("otp: EmailSender.Mailer is nil")
	}
	subject := "Your verification code"
	if e.Subject != nil {
		subject = e.Subject(m)
	}
	body := fmt.Sprintf("Your verification code is %s. It expires in %d minutes.", m.Code, int(m.ExpiresIn.Minutes()))
	if e.Body != nil {
		body = e.Body(m)
	}
	return e.Mailer.Send(ctx, m.To, subject, body)
}

// TwilioSender delivers codes through Twilio's Messages API.
type TwilioSender struct {
	AccountSID string
	AuthToken  string
	// From is the sending number or messaging service identifier.
	From string
	// Template renders the SMS text. Defaults to a short code message.
	Template func(Message) string
	// BaseURL overrides https://api.twilio.com for tests.
	BaseURL    string
	HTTPClient *http.Client
}

// Send implements Sender.
func (t TwilioSender) Send(ctx context.Context, m Message) error {
	if t.AccountSID == "" || t.AuthToken == "" || t.From == "" {
		return errors.New("otp: TwilioSender needs AccountSID, AuthToken and From")
	}
	base := t.BaseURL
	if base == "" {
		base = "https://api.twilio.com"
	}
	text := fmt.Sprintf("Your verification code is %s", m.Code)
	if t.Template != nil {
		text = t.Template(m)
	}
	form := url.Values{"To": {m.To}, "From": {t.From}, "Body": {text}}
	endpoint := base + "/2010-04-01/Accounts/" + url.PathEscape(t.AccountSID) + "/Messages.json"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return err
	}
	req.SetBasicAuth(t.AccountSID, t.AuthToken)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	client := t.HTTPClient
	if client == nil {
		client = &http.Client{Timeout: 10 * time.Second}
	}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<14))
	if resp.StatusCode/100 != 2 {
		var e struct {
			Message string `json:"message"`
		}
		_ = json.Unmarshal(body, &e)
		return fmt.Errorf("twilio: status %d: %s", resp.StatusCode, e.Message)
	}
	return nil
}

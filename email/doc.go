// Package email defines the Sender interface theauth-go uses to deliver
// magic-link and password-reset messages, plus a Noop implementation
// suitable for local development and tests.
//
// Production deployments are expected to provide their own Sender
// implementation that talks to an SMTP relay, SES, Postmark, or similar.
package email

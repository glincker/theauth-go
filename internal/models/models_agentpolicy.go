package models

import (
	"errors"
	"fmt"
	"time"
)

// models_agentpolicy.go: shared types for per agent IAM policy enforcement and
// rate limits at token mint time. They live here so internal/as (which mints)
// and internal/agent (which decides) agree without importing each other.

// Mint grants named in AgentMintRequest.Grant.
const (
	AgentMintClientCredentials = "client_credentials"
	AgentMintTokenExchange     = "token_exchange"
	AgentMintJWTBearer         = "jwt_bearer"
)

// AgentMintRequest asks the agent gate to vet one token mint.
type AgentMintRequest struct {
	// Grant is one of the AgentMint* constants.
	Grant string
	// Resource is the audience the token is minted for.
	Resource string
	// Scopes are the scopes the mint is about to grant, already narrowed by
	// the registered scope set, resource catalog and delegation.
	Scopes []string
	// Explicit is true when the caller asked for these scopes by name. An
	// explicit scope that policy denies fails the mint. A defaulted scope that
	// policy denies is dropped instead.
	Explicit bool
	// Ceiling, when non-nil, is the most the credential may ever carry (the
	// agent's registered scopes). The gate never lets policy widen past it:
	// explicit scopes outside it are invalid_scope, defaulted ones are cut.
	// Set only where the grant has no ceiling of its own (jwt-bearer).
	Ceiling []string
}

// AgentMintResult is the gate's verdict: the scopes that survive and the
// identifiers of the policies that were consulted.
type AgentMintResult struct {
	Scopes []string
	// Dropped lists defaulted scopes that policy removed.
	Dropped []string
	// PolicyIDs lists the ids of the attached policies, sorted. Empty when no
	// policy applied.
	PolicyIDs []string
	// PolicyHash is a hex SHA-256 over the canonical policy documents, so a
	// decision can be tied to the exact text in force. Empty when no policy
	// applied.
	PolicyHash string
}

// ErrAgentPolicyDenied is wrapped by every mint refusal caused by agent policy
// (an explicit deny, a scope no allow statement covers, or an escalation).
// It maps to the OAuth error access_denied. The wrapping message names the
// action but never the policy text.
var ErrAgentPolicyDenied = errors.New("theauth: access_denied")

// AgentPolicyDeniedError carries the denied action for audit. Its Error text
// is safe for a client: it names the action, not the policy.
type AgentPolicyDeniedError struct {
	Action   string
	Resource string
	// PolicyID and StatementID identify the matching deny for audit only.
	PolicyID    string
	StatementID string
	Reason      string
}

func (e *AgentPolicyDeniedError) Error() string {
	return fmt.Sprintf("%v: agent policy does not permit action %q", ErrAgentPolicyDenied, e.Action)
}

// Is makes errors.Is(err, ErrAgentPolicyDenied) true.
func (e *AgentPolicyDeniedError) Is(target error) bool { return target == ErrAgentPolicyDenied }

// AgentRateLimitedError is returned when an agent has used up its mint budget.
type AgentRateLimitedError struct {
	RetryAfter time.Duration
}

func (e *AgentRateLimitedError) Error() string { return "theauth: agent rate limit exceeded" }

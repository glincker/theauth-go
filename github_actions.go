package theauth

import (
	"errors"
	"fmt"
	"strings"
)

const (
	// GitHubActionsIssuerURL is the iss value of GitHub Actions OIDC tokens.
	GitHubActionsIssuerURL = "https://token.actions.githubusercontent.com"
	// GitHubActionsJWKSURL is the jwks_uri from GitHub's OIDC discovery
	// document at GitHubActionsIssuerURL/.well-known/openid-configuration.
	GitHubActionsJWKSURL = GitHubActionsIssuerURL + "/.well-known/jwks"
)

// ErrGitHubActionsUnrestricted is returned by GitHubActionsIssuer when
// neither Repository nor RepositoryOwner is set.
var ErrGitHubActionsUnrestricted = errors.New("theauth: GitHubActionsIssuer needs Repository or RepositoryOwner: an unrestricted GitHub issuer lets any GitHub repository mint tokens")

// GitHubActionsOptions configures GitHubActionsIssuer.
type GitHubActionsOptions struct {
	// Repository is the exact "owner/name" the workflow must run in (the
	// repository claim). Matching is case sensitive.
	Repository string
	// RepositoryOwner is the exact organization or user (the
	// repository_owner claim).
	RepositoryOwner string
	// Refs restricts the ref claim. A single entry may contain "*"
	// (for example "refs/heads/release/*"); several entries must all be
	// exact. Empty means any ref.
	Refs []string
	// Environment restricts the environment claim to this exact name.
	// Empty means any (or no) environment.
	Environment string
	// Audience is the aud the workflow must request (the audience query
	// parameter of the token request). Empty means the authorization server
	// issuer URL.
	Audience string
	// SubjectMapper resolves the verified claims to a local user. GitHub's
	// sub is not a ULID, so supply a mapper that looks the workflow up, for
	// example by repository. Required to complete an exchange.
	SubjectMapper SubjectMapper
}

// GitHubActionsIssuer returns a TrustedJWTIssuer for GitHub Actions OIDC
// tokens (RS256, issuer and JWKS URL as published by GitHub) with required
// claim matchers built from opts. It returns ErrGitHubActionsUnrestricted
// unless Repository or RepositoryOwner is set: GitHub signs tokens for every
// repository on github.com with the same key, so an issuer without such a
// matcher accepts a token from any public repository.
//
// Append further matchers (job_workflow_ref, repository_id, ...) to the
// result's RequiredClaims.
func GitHubActionsIssuer(opts GitHubActionsOptions) (TrustedJWTIssuer, error) {
	if opts.Repository == "" && opts.RepositoryOwner == "" {
		return TrustedJWTIssuer{}, ErrGitHubActionsUnrestricted
	}
	var req []ClaimMatcher
	if opts.RepositoryOwner != "" {
		if strings.ContainsAny(opts.RepositoryOwner, "*/") {
			return TrustedJWTIssuer{}, fmt.Errorf("theauth: GitHubActionsOptions.RepositoryOwner %q must be a bare owner name: %w", opts.RepositoryOwner, ErrInvalidClaimMatcher)
		}
		req = append(req, ClaimMatcher{Claim: "repository_owner", Equals: opts.RepositoryOwner})
	}
	if opts.Repository != "" {
		owner, name, ok := strings.Cut(opts.Repository, "/")
		if !ok || owner == "" || name == "" || strings.ContainsAny(opts.Repository, "*") || strings.Contains(name, "/") {
			return TrustedJWTIssuer{}, fmt.Errorf("theauth: GitHubActionsOptions.Repository %q must be exactly owner/name: %w", opts.Repository, ErrInvalidClaimMatcher)
		}
		req = append(req, ClaimMatcher{Claim: "repository", Equals: opts.Repository})
	}
	switch len(opts.Refs) {
	case 0:
	case 1:
		if strings.Contains(opts.Refs[0], "*") {
			req = append(req, ClaimMatcher{Claim: "ref", Pattern: opts.Refs[0]})
		} else {
			req = append(req, ClaimMatcher{Claim: "ref", Equals: opts.Refs[0]})
		}
	default:
		for _, r := range opts.Refs {
			if strings.Contains(r, "*") {
				return TrustedJWTIssuer{}, fmt.Errorf("theauth: GitHubActionsOptions.Refs mixes %d entries with a glob; use one glob or exact refs: %w", len(opts.Refs), ErrInvalidClaimMatcher)
			}
		}
		req = append(req, ClaimMatcher{Claim: "ref", OneOf: append([]string(nil), opts.Refs...)})
	}
	if opts.Environment != "" {
		req = append(req, ClaimMatcher{Claim: "environment", Equals: opts.Environment})
	}
	for _, m := range req {
		if err := m.Validate(); err != nil {
			return TrustedJWTIssuer{}, err
		}
	}
	return TrustedJWTIssuer{
		Issuer:            GitHubActionsIssuerURL,
		JWKSURL:           GitHubActionsJWKSURL,
		AllowedAlgorithms: []string{"RS256"},
		SubjectMapper:     opts.SubjectMapper,
		RequiredClaims:    req,
		Audience:          opts.Audience,
	}, nil
}

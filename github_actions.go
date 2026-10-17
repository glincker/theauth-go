package theauth

import (
	"errors"
	"fmt"
	"strings"
)

const (
	// GitHubActionsIssuerURL is the iss value of GitHub Actions OIDC tokens.
	GitHubActionsIssuerURL = "https://token.actions.githubusercontent.com"
	// GitHubActionsJWKSURL is the jwks_uri from GitHub's OIDC discovery document.
	GitHubActionsJWKSURL = GitHubActionsIssuerURL + "/.well-known/jwks"
)

// ErrGitHubActionsUnrestricted is returned by GitHubActionsIssuer when neither Repository nor
// RepositoryOwner is set.
var ErrGitHubActionsUnrestricted = errors.New("theauth: GitHubActionsIssuer needs Repository or RepositoryOwner: an unrestricted GitHub issuer lets any GitHub repository mint tokens")

// GitHubActionsOptions configures GitHubActionsIssuer.
type GitHubActionsOptions struct {
	Repository      string
	RepositoryOwner string
	Refs            []string
	Environment     string
	Audience        string
	SubjectMapper   SubjectMapper
}

// GitHubActionsIssuer returns a TrustedJWTIssuer for GitHub Actions OIDC tokens, with claim
// matchers built from opts. It returns ErrGitHubActionsUnrestricted unless Repository or
// RepositoryOwner is set, because GitHub signs tokens for every repository with one key. Append
// further matchers such as job_workflow_ref to RequiredClaims.
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

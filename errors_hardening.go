package theauth

import "github.com/glincker/theauth-go/v2/internal/models"

// Error codes added with the auth hardening work.
const (
	CodeAccountLocked     = models.CodeAccountLocked
	CodeSignupClosed      = models.CodeSignupClosed
	CodeSetupTokenInvalid = models.CodeSetupTokenInvalid
	CodeBadRequest        = models.CodeBadRequest
	CodeUnauthorized      = models.CodeUnauthorized
	CodeForbidden         = models.CodeForbidden
	CodeNotFound          = models.CodeNotFound
	CodeConflict          = models.CodeConflict
	CodeInternal          = models.CodeInternal
)

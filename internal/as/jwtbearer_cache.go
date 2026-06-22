package as

// ResetJWKSCache clears the in-process JWKS URL cache. Exported for tests
// only; production code should not call this.
func ResetJWKSCache() {
	jwksURLCache.Range(func(k, _ any) bool {
		jwksURLCache.Delete(k)
		return true
	})
}

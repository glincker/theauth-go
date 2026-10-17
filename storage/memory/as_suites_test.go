package memory

import (
	"testing"

	"github.com/glincker/theauth-go/v2/storagetest"
)

// The authorization server core suite and the pushed request suite are shared
// with the SQLite adapter; running them here keeps the two backends honest.
func TestOAuthServerCoreContract(t *testing.T) { storagetest.RunOAuthServerCore(t, New()) }
func TestPushedRequestContract(t *testing.T)   { storagetest.RunPushedRequests(t, New()) }

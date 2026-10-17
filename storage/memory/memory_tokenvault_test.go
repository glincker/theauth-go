package memory

import (
	"testing"

	"github.com/glincker/theauth-go/v2/storagetest"
)

func TestTokenVaultContract(t *testing.T) { storagetest.RunTokenVault(t, New()) }

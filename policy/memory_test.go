package policy_test

import (
	"testing"

	"github.com/glincker/theauth-go/v2/policy"
	"github.com/glincker/theauth-go/v2/storagetest"
)

func TestMemoryContract(t *testing.T) { storagetest.RunPolicy(t, policy.NewMemory()) }

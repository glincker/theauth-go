package policy_test

import (
	"testing"

	"github.com/glincker/theauth-go/policy"
	"github.com/glincker/theauth-go/storagetest"
)

func TestMemoryContract(t *testing.T) { storagetest.RunPolicy(t, policy.NewMemory()) }

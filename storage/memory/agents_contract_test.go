package memory_test

import (
	"testing"

	"github.com/glincker/theauth-go/v2/storage/memory"
	"github.com/glincker/theauth-go/v2/storagetest"
)

func TestAgentSuites(t *testing.T) {
	t.Parallel()
	t.Run("Agents", func(t *testing.T) { storagetest.RunAgents(t, memory.New()) })
	t.Run("Delegations", func(t *testing.T) { storagetest.RunDelegations(t, memory.New()) })
	t.Run("JWTBearer", func(t *testing.T) { storagetest.RunJWTBearer(t, memory.New()) })
}

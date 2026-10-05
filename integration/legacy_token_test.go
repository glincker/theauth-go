package integration

import (
	"testing"

	"github.com/glincker/theauth-go/v2/storage/memory"
	"github.com/glincker/theauth-go/v2/storagetest"
)

func TestLegacyTokenImportMemory(t *testing.T) {
	storagetest.RunLegacyTokenImport(t, memory.New())
}

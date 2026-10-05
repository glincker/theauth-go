package theauth_test

import (
	"testing"

	"github.com/glincker/theauth-go/storage/memory"
	"github.com/glincker/theauth-go/storagetest"
)

func TestLegacyTokenImportMemory(t *testing.T) {
	storagetest.RunLegacyTokenImport(t, memory.New())
}

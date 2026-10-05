package memory

import (
	"testing"

	"github.com/glincker/theauth-go/v2/storagetest"
)

func TestAPITokenContract(t *testing.T) { storagetest.RunAPITokens(t, New()) }

func TestDeviceCodeContract(t *testing.T) { storagetest.RunDeviceCodes(t, New()) }

package memory

import (
	"testing"

	"github.com/glincker/theauth-go/v2"
	"github.com/glincker/theauth-go/v2/storagetest"
)

var (
	_ theauth.DeviceAuthorizationStorage = (*Store)(nil)
	_ theauth.RegistrationTokenStorage   = (*Store)(nil)
	_ theauth.OpaqueTokenStorage         = (*Store)(nil)
)

func TestDeviceAuthorizationContract(t *testing.T) { storagetest.RunDeviceAuthorizations(t, New()) }
func TestRegistrationTokenContract(t *testing.T)   { storagetest.RunRegistrationTokens(t, New()) }
func TestOpaqueTokenContract(t *testing.T)         { storagetest.RunOpaqueTokens(t, New()) }

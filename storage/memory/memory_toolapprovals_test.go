package memory

import (
	"testing"

	"github.com/glincker/theauth-go/v2/storagetest"
)

func TestToolApprovalContract(t *testing.T) { storagetest.RunToolApprovals(t, New()) }

func TestToolApprovalAdminContract(t *testing.T) { storagetest.RunToolApprovalAdmin(t, New()) }

func TestApprovalFlowContract(t *testing.T) { storagetest.RunApprovalFlow(t, New()) }

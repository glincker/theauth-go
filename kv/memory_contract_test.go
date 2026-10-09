package kv_test

import (
	"testing"

	"github.com/glincker/theauth-go/v2/kv"
	"github.com/glincker/theauth-go/v2/kv/kvtest"
)

func TestMemoryContract(t *testing.T) {
	kvtest.Run(t, func(_ *testing.T, clk *kvtest.Clock) kv.Cache { return kv.NewMemory(kv.WithClock(clk.Now)) })
}

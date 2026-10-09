package as_test

import "github.com/glincker/theauth-go/v2/kv"

func newSharedStores() kv.Stores { return kv.NewMemory().Stores() }

// Command fleetbench runs the device conformance kit at scale and prints latency percentiles and memory.
//
//	go run ./iot/fleet/cmd/fleetbench [devices]
//
// One process, in memory storage, one machine, loopback HTTP. The numbers describe the library under a
// virtual clock, not a deployed service: there is no real network and no database round trip.
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"runtime"
	"sort"
	"strconv"
	"time"

	"github.com/glincker/theauth-go/v2/iot/fleet"
)

func main() {
	size := 1000
	if len(os.Args) > 1 {
		n, err := strconv.Atoi(os.Args[1])
		if err != nil || n < 2 {
			fmt.Fprintln(os.Stderr, "usage: fleetbench [devices >= 2]")
			os.Exit(2)
		}
		size = n
	}
	ctx := context.Background()
	before := fleet.SampleMemory()
	started := time.Now()
	f, err := fleet.New(ctx, fleet.Options{Size: size})
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	defer f.Close()
	setup := time.Since(started)
	report := f.Run(ctx)
	total := time.Since(started)
	after := fleet.SampleMemory()

	type row struct {
		Operation string  `json:"operation"`
		Calls     int     `json:"calls"`
		P50Ms     float64 `json:"p50_ms"`
		P99Ms     float64 `json:"p99_ms"`
		MaxMs     float64 `json:"max_ms"`
	}
	ms := func(d time.Duration) float64 { return float64(d.Microseconds()) / 1000 }
	var rows []row
	for name, s := range f.Latency.Report() {
		rows = append(rows, row{name, s.Count, ms(s.P50), ms(s.P99), ms(s.Max)})
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i].Operation < rows[j].Operation })
	type scenario struct {
		Name     string `json:"name"`
		Checks   int    `json:"checks"`
		Failures int    `json:"failures"`
	}
	var scenarios []scenario
	checks := 0
	for _, s := range report.Scenarios {
		scenarios = append(scenarios, scenario{s.Name, s.Checks, len(s.Failures)})
		checks += s.Checks
	}
	out := map[string]any{
		"devices": size, "go": runtime.Version(), "platform": runtime.GOOS + " " + runtime.GOARCH, "cpus": runtime.NumCPU(),
		"passed": report.Passed, "checks": checks, "scenarios": scenarios,
		"setupSeconds": round1(setup.Seconds()), "totalSeconds": round1(total.Seconds()),
		"memoryMb": map[string]any{
			"heapInuseBefore": mb(before.HeapInuse), "heapInuseAfter": mb(after.HeapInuse),
			"sysBefore": mb(before.Sys), "sysAfter": mb(after.Sys),
		},
		"latency": rows,
	}
	b, _ := json.MarshalIndent(out, "", "  ")
	fmt.Println(string(b))
	if !report.Passed {
		for _, s := range report.Scenarios {
			for _, f := range s.Failures {
				fmt.Fprintf(os.Stderr, "%s: %s\n", s.Name, f)
			}
		}
		os.Exit(1)
	}
}

func round1(v float64) float64 { return float64(int(v*10+0.5)) / 10 }
func mb(b uint64) float64      { return round1(float64(b) / (1 << 20)) }

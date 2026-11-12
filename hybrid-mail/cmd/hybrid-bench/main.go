// Measure sequential API operations, without disk I/O or process startup.
package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"runtime"
	"sort"
	"time"

	mail "latpre.example/hybridmail"
)

type Timing struct {
	MedianMS, P05MS, P95MS float64
	SamplesNS              []int64
}
type Payload struct {
	PlaintextBytes, SourceBytes, ForwardedBytes, ClassicalCapsuleBytes, SourceLatPREBytes, ForwardedLatPREBytes int
	Operations                                                                                                  map[string]Timing
}
type Result struct {
	Suite    string
	Setup    map[string]Timing
	Sizes    map[string]int
	Payloads []Payload
}

func must(err error) {
	if err != nil {
		panic(err)
	}
}
func stats(samples []int64) Timing {
	sorted := append([]int64(nil), samples...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i] < sorted[j] })
	n := len(sorted)
	median := float64(sorted[n/2])
	if n%2 == 0 {
		median = (median + float64(sorted[n/2-1])) / 2
	}
	return Timing{median / 1e6, float64(sorted[(n-1)*5/100]) / 1e6, float64(sorted[(n-1)*95/100]) / 1e6, samples}
}
func measure(n, warm int, fn func()) Timing {
	var samples []int64
	for i := 0; i < n+warm; i++ {
		t := time.Now()
		fn()
		elapsed := time.Since(t).Nanoseconds()
		if i >= warm {
			samples = append(samples, elapsed)
		}
	}
	return stats(samples)
}
func jsonSize(x any) int { b, e := json.Marshal(x); must(e); return len(b) }
func bench(mode byte, n, warm int) Result {
	name := "classical"
	if mode == mail.HybridLight {
		name = "hybrid-light"
	}
	fmt.Fprintln(os.Stderr, "Benchmarking", name)
	result := Result{Suite: name, Setup: make(map[string]Timing), Sizes: make(map[string]int)}
	result.Setup["source_setup_keygen"] = measure(n, warm, func() { _, e := mail.NewSource(mode); must(e) })
	s, e := mail.NewSource(mode)
	must(e)
	result.Setup["authorize_including_target_keygen"] = measure(n, warm, func() { _, _, e := mail.Authorize(s); must(e) })
	a, r, e := mail.Authorize(s)
	must(e)
	result.Setup["proxy_prepare"] = measure(n, warm, func() { f, e := mail.Prepare(*a); must(e); f.Close() })
	result.Sizes["public_package_compact_json"] = jsonSize(s.Public)
	result.Sizes["proxy_package_compact_json"] = jsonSize(a)
	packedAuthorization, e := a.MarshalBinary()
	must(e)
	result.Sizes["proxy_package_binary"] = len(packedAuthorization)
	result.Sizes["receiver_package_compact_json"] = jsonSize(r)
	result.Sizes["source_classical_public_packets"] = len(s.Public.Classical)
	result.Sizes["source_latpre_public"] = len(s.Public.LatPRE)
	result.Sizes["matrix_seed"] = len(s.Public.MatrixSeed)
	result.Sizes["latpre_rekey_including_32B_seed"] = len(a.LatPRERekey)
	var proxy struct{ ProxyParameter []byte }
	must(json.Unmarshal(a.ClassicalProxy, &proxy))
	result.Sizes["classical_proxy_factor"] = len(proxy.ProxyParameter)
	result.Sizes["raw_rekey_and_factor"] = len(a.LatPRERekey) + len(proxy.ProxyParameter)
	f, e := mail.Prepare(*a)
	must(e)
	defer f.Close()
	for _, size := range []int{10 << 10, 100 << 10, 1 << 20} {
		fmt.Fprintln(os.Stderr, " ", size, "bytes")
		message := bytes.Repeat([]byte{0x42}, size)
		samples := map[string][]int64{"seal": {}, "open_source": {}, "forward_prepared": {}, "open_receiver": {}}
		record := func(i int, name string, start time.Time) {
			elapsed := time.Since(start).Nanoseconds()
			if i >= warm {
				samples[name] = append(samples[name], elapsed)
			}
		}
		var env, out *mail.Envelope
		for i := 0; i < n+warm; i++ {
			t := time.Now()
			env, e = mail.Seal(s.Public, message)
			record(i, "seal", t)
			must(e)
			t = time.Now()
			plain, e := mail.OpenSource(s, env)
			record(i, "open_source", t)
			must(e)
			if !bytes.Equal(plain, message) {
				panic("Bob mismatch")
			}
			t = time.Now()
			out, e = f.Transform(env)
			record(i, "forward_prepared", t)
			must(e)
			t = time.Now()
			plain, e = mail.OpenReceiver(r, out)
			record(i, "open_receiver", t)
			must(e)
			if !bytes.Equal(plain, message) {
				panic("Carol mismatch")
			}
			if !bytes.Equal(env.Body, out.Body) {
				panic("body changed")
			}
		}
		source, e := env.MarshalBinary()
		must(e)
		target, e := out.MarshalBinary()
		must(e)
		p := Payload{PlaintextBytes: size, SourceBytes: len(source), ForwardedBytes: len(target), ClassicalCapsuleBytes: len(env.Classical), SourceLatPREBytes: len(env.LatPRE), ForwardedLatPREBytes: len(out.LatPRE), Operations: make(map[string]Timing)}
		for name, samples := range samples {
			p.Operations[name] = stats(samples)
		}
		result.Payloads = append(result.Payloads, p)
	}
	return result
}
func main() {
	n := flag.Int("n", 1000, "measurements after warmup")
	warm := flag.Int("warmup", 10, "warmup operations")
	out := flag.String("out", "", "new JSON output path")
	flag.Parse()
	if *n < 1 || *warm < 0 || *n+*warm+1 > 1024 || *out == "" {
		fmt.Fprintln(os.Stderr, "require output path and 1 <= n+warmup+1 <= M=1024")
		os.Exit(2)
	}
	runtime.GOMAXPROCS(1)
	results := []Result{bench(mail.Classical, *n, *warm), bench(mail.HybridLight, *n, *warm)}
	report := map[string]any{"go": runtime.Version(), "os": runtime.GOOS, "arch": runtime.GOARCH, "gomaxprocs": 1, "measurements": *n, "warmup": *warm, "created_utc": time.Now().UTC().Format(time.RFC3339), "results": results, "timing_scope": "Sequential public API calls; key parsing, C context construction, C RNG seeding, and allocation included where performed. Proxy preparation measured separately. Forwarding includes payload copy, no body encryption. Disk I/O, envelope serialization, MIME construction, and process startup excluded. Distinct source ciphertext per iteration; equality checks outside timing. New prototypes are single-threaded; Go runtime/GC still present."}
	b, e := json.MarshalIndent(report, "", "  ")
	must(e)
	f, e := os.OpenFile(*out, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0644)
	must(e)
	_, e = f.Write(append(b, '\n'))
	must(e)
	must(f.Close())
	fmt.Fprintln(os.Stderr, "Saved", *out)
}

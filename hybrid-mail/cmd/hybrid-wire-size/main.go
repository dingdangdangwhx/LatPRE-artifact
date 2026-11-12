// Report provisioning sizes for the same authorization in both formats.
// Only lengths are retained; keys and authorization bytes are never exported.
package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"runtime"
	"time"

	mail "latpre.example/hybridmail"
)

type Result struct {
	Suite                  string         `json:"suite"`
	Sizes                  map[string]int `json:"sizes_bytes"`
	AuthorizationRoundTrip bool           `json:"authorization_round_trip"`
	ForwardingRoundTrip    bool           `json:"forwarding_round_trip"`
}

func must(err error) {
	if err != nil {
		panic(err)
	}
}

func measure(mode byte, name string) Result {
	s, err := mail.NewSource(mode)
	must(err)
	a, recipient, err := mail.Authorize(s)
	must(err)
	legacy, err := json.Marshal(a)
	must(err)
	packed, err := a.MarshalBinary()
	must(err)
	parsed, err := mail.ParseAuthorization(packed)
	must(err)
	restored, err := json.Marshal(parsed)
	must(err)
	if !bytes.Equal(legacy, restored) || parsed.Source.ID() != s.Public.ID() {
		panic("authorization or public identity changed")
	}
	public, err := json.Marshal(s.Public)
	must(err)
	secret, err := json.Marshal(recipient)
	must(err)
	var classical struct{ ProxyParameter []byte }
	must(json.Unmarshal(a.ClassicalProxy, &classical))
	message := bytes.Repeat([]byte{0x42}, 1024)
	env, err := mail.Seal(s.Public, message)
	must(err)
	proxy, err := mail.Prepare(*parsed)
	must(err)
	defer proxy.Close()
	forwarded, err := proxy.Transform(env)
	must(err)
	plain, err := mail.OpenReceiver(recipient, forwarded)
	must(err)
	if !bytes.Equal(plain, message) || !bytes.Equal(env.Body, forwarded.Body) {
		panic("forwarded email changed")
	}
	sourceWire, err := env.MarshalBinary()
	must(err)
	forwardedWire, err := forwarded.MarshalBinary()
	must(err)
	return Result{Suite: name, AuthorizationRoundTrip: true, ForwardingRoundTrip: true,
		Sizes: map[string]int{
			"proxy_package_compact_json":      len(legacy),
			"proxy_package_binary":            len(packed),
			"binary_header":                   mail.AuthorizationHeaderSize,
			"public_package_compact_json":     len(public),
			"receiver_package_compact_json":   len(secret),
			"raw_rekey_and_factor":            len(a.LatPRERekey) + len(classical.ProxyParameter),
			"source_latpre_public":            len(a.Source.LatPRE),
			"target_latpre_public":            len(a.TargetLatPRE),
			"source_classical_public":         len(a.Source.Classical),
			"target_classical_public":         len(a.TargetClassical),
			"classical_proxy_adapter":         len(a.ClassicalProxy),
			"matrix_seed":                     len(a.Source.MatrixSeed),
			"latpre_rekey_including_32B_seed": len(a.LatPRERekey),
			"source_email_overhead":           len(sourceWire) - len(message),
			"forwarded_email_overhead":        len(forwardedWire) - len(message),
		}}
}

func main() {
	out := flag.String("out", "", "new report path")
	flag.Parse()
	if *out == "" {
		fmt.Fprintln(os.Stderr, "require -out for a new size report")
		os.Exit(2)
	}
	runtime.GOMAXPROCS(1)
	report := map[string]any{
		"schema":      "hybrid-mail-binary-authorization-v1",
		"created_utc": time.Now().UTC().Format(time.RFC3339),
		"go":          runtime.Version(),
		"scope":       "Same freshly generated keys and authorization in both encodings. No runtime benchmarks or secret material are exported. Source public and recipient secret packages retain their existing JSON format.",
		"results":     []Result{measure(mail.Classical, "classical"), measure(mail.HybridLight, "hybrid-light")},
	}
	b, err := json.MarshalIndent(report, "", "  ")
	must(err)
	f, err := os.OpenFile(*out, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0644)
	must(err)
	_, err = f.Write(append(b, '\n'))
	must(err)
	must(f.Close())
	fmt.Fprintln(os.Stderr, "Saved", *out)
}

# Hybrid encrypted email forwarding

This prototype combines Proton's pinned classical forwarding implementation with
LatPRE Light. It forwards an encrypted MIME message and attachments after the
delegator has authorized a delegatee and gone offline. The proxy transforms the
two key capsules and leaves the authenticated encrypted body unchanged.

Requirements: Go 1.23 or newer, Python 3, and a C compiler. The first build
downloads the versions recorded in `go.mod` and verifies `go.sum`; no local
checkout or globally installed OpenFHE library is needed. Set `GO=/path/to/go`
if Go is not on `PATH`.

From this directory:

```sh
make test
make proton-test
make demo
make bench SAMPLES=1000 OUT=runs/benchmark.json
make wire-sizes
```

`proton-test` executes the upstream, unmodified `TestForwardingFull` from
`github.com/ProtonMail/go-crypto v1.5.2-proton` (commit
`12a205f82df886522b8d1feb076b9562437ac10d`). `demo` checks classical and hybrid
flows in separate processes, removes the delegator's disposable secret before
forwarding, and verifies the recovered MIME bytes and attachment.

The benchmark uses one thread, 1,000 measurements after 10 warmups, and payloads
of 10 KB, 100 KB, and 1 MB. JSON output contains all samples, medians, and packed
communication sizes. Key parsing, C context construction, and allocation are
included where performed by the API. Proxy preparation is measured separately.
File I/O, process startup, serialization, and MIME construction are excluded.
Output paths must not already exist.

Light uses `(Q,M)=(2^20,2^10)` and the C implementation in `../latpre`. The rekey
contains its independent 32-byte seed. Its public key, secret key, source
ciphertext, re-encrypted ciphertext, and rekey occupy respectively 8,960, 7,168,
3,808, 1,824, and 53,792 bytes.

For a payload of `P` bytes, the classical source and forwarded envelopes each
occupy `P+246` bytes. Hybrid source and forwarded envelopes occupy `P+4054` and
`P+2070` bytes. Both modes use the same envelope framing, HKDF-SHA256, and
AES-256-GCM. The hybrid key is derived from two independent 256-bit shares, one
encrypted by each branch.

The envelope is a research format using Proton's forwarding arithmetic; it is
not a deployed Proton Mail service integration or an OpenPGP-compatible hybrid
message. Tests exercise honest source encryption and authorization, not a new
CCA or robust-combiner theorem. The CLI does not provide persistent shared
usage-budget accounting.

Generated secret keys, MIME data, and measurements remain in ignored `runs/`;
builds and dependency caches are ignored as well. See `THIRD_PARTY_NOTICES` for
dependency attribution.

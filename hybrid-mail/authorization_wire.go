package hybridmail

import (
	"encoding/binary"
	"errors"

	"latpre.example/hybridmail/internal/latpre"
)

const (
	authorizationMagic = "LPMAUTH1"
	// Magic/version, suite, authorization ID, and seven byte-string lengths.
	AuthorizationHeaderSize = 8 + 1 + 32 + 7*4
	MaxAuthorizationSize    = 1 << 20
)

func (a Authorization) wireValid() bool {
	if a.Version != 1 || !a.Source.valid() || a.ID == ([32]byte{}) ||
		len(a.TargetClassical) == 0 || len(a.TargetClassical) >= 65536 ||
		len(a.ClassicalProxy) == 0 || len(a.ClassicalProxy) >= 65536 {
		return false
	}
	if a.Source.Mode == HybridLight {
		return len(a.TargetLatPRE) == latpre.PublicKeySize && len(a.LatPRERekey) == latpre.RekeySize
	}
	return len(a.TargetLatPRE) == 0 && len(a.LatPRERekey) == 0
}

// MarshalBinary retains every authorization field, without outer JSON/base64
// encoding. ClassicalProxy remains opaque Proton adapter data. Public.ID keeps
// its existing canonical encoding, so message and authorization bindings do not
// depend on the provisioning format.
func (a Authorization) MarshalBinary() ([]byte, error) {
	if !a.wireValid() {
		return nil, errors.New("invalid authorization")
	}
	fields := [][]byte{a.Source.MatrixSeed, a.Source.Classical, a.Source.LatPRE,
		a.TargetClassical, a.TargetLatPRE, a.ClassicalProxy, a.LatPRERekey}
	size := AuthorizationHeaderSize
	for _, field := range fields {
		if len(field) > MaxAuthorizationSize-size {
			return nil, errors.New("authorization too large")
		}
		size += len(field)
	}
	out := make([]byte, size)
	copy(out[:8], authorizationMagic)
	out[8] = a.Source.Mode
	copy(out[9:41], a.ID[:])
	offset := AuthorizationHeaderSize
	for i, field := range fields {
		binary.BigEndian.PutUint32(out[41+4*i:45+4*i], uint32(len(field)))
		copy(out[offset:], field)
		offset += len(field)
	}
	return out, nil
}

// ParseAuthorization checks the complete framing before allocating an owned
// copy. Truncated inputs, trailing bytes, unknown suites, and malformed lengths
// are rejected.
func ParseAuthorization(data []byte) (*Authorization, error) {
	if len(data) < AuthorizationHeaderSize || len(data) > MaxAuthorizationSize ||
		string(data[:8]) != authorizationMagic {
		return nil, errors.New("bad authorization prefix or size")
	}
	var lengths [7]int
	total := uint64(AuthorizationHeaderSize)
	for i := range lengths {
		n := uint64(binary.BigEndian.Uint32(data[41+4*i : 45+4*i]))
		total += n
		if total > uint64(len(data)) {
			return nil, errors.New("bad authorization lengths")
		}
		lengths[i] = int(n)
	}
	if total != uint64(len(data)) {
		return nil, errors.New("trailing authorization data")
	}
	payload := append([]byte(nil), data[AuthorizationHeaderSize:]...)
	var fields [7][]byte
	offset := 0
	for i, n := range lengths {
		if n > 0 {
			fields[i] = payload[offset : offset+n : offset+n]
		}
		offset += n
	}
	a := &Authorization{Version: 1, Source: Public{Version: 1, Mode: data[8],
		MatrixSeed: fields[0], Classical: fields[1], LatPRE: fields[2]},
		TargetClassical: fields[3], TargetLatPRE: fields[4], ClassicalProxy: fields[5], LatPRERekey: fields[6]}
	copy(a.ID[:], data[9:41])
	if !a.wireValid() {
		return nil, errors.New("invalid authorization fields")
	}
	return a, nil
}

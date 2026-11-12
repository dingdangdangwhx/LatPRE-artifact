package hybridmail

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"testing"
)

func TestAuthorizationBinaryFlow(t *testing.T) {
	for _, mode := range []byte{Classical, HybridLight} {
		s, err := NewSource(mode)
		if err != nil {
			t.Fatal(err)
		}
		a, recipient, err := Authorize(s)
		if err != nil {
			t.Fatal(err)
		}
		wire, err := a.MarshalBinary()
		if err != nil {
			t.Fatal(err)
		}
		got, err := ParseAuthorization(wire)
		if err != nil {
			t.Fatal(err)
		}
		before, err := json.Marshal(a)
		if err != nil {
			t.Fatal(err)
		}
		after, err := json.Marshal(got)
		if err != nil || !bytes.Equal(before, after) || got.Source.ID() != s.Public.ID() {
			t.Fatal("authorization fields or source binding changed")
		}
		if len(wire) >= len(before) {
			t.Fatal("binary authorization did not reduce size")
		}
		wire[len(wire)-1] ^= 1
		again, _ := got.MarshalBinary()
		if bytes.Equal(wire, again) {
			t.Fatal("parsed fields alias the caller's input")
		}
		proxy, err := Prepare(*got)
		if err != nil {
			t.Fatal(err)
		}
		message := []byte("Binary authorization: email body and attachment bytes\x00\xff")
		env, err := Seal(s.Public, message)
		if err != nil {
			t.Fatal(err)
		}
		forwarded, err := proxy.Transform(env)
		if err != nil {
			t.Fatal(err)
		}
		plain, err := OpenReceiver(recipient, forwarded)
		proxy.Close()
		if err != nil || !bytes.Equal(plain, message) {
			t.Fatal("binary authorization forwarding failed")
		}
	}
}

func TestAuthorizationBinaryRejectsMalformed(t *testing.T) {
	s, err := NewSource(HybridLight)
	if err != nil {
		t.Fatal(err)
	}
	a, _, err := Authorize(s)
	if err != nil {
		t.Fatal(err)
	}
	wire, err := a.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < AuthorizationHeaderSize; i++ {
		if _, err := ParseAuthorization(wire[:i]); err == nil {
			t.Fatal("truncated header accepted")
		}
	}
	for _, what := range []string{"prefix", "suite", "id", "length", "truncate", "append"} {
		bad := append([]byte(nil), wire...)
		switch what {
		case "prefix":
			bad[7] ^= 1
		case "suite":
			bad[8] = 255
		case "id":
			clear(bad[9:41])
		case "length":
			binary.BigEndian.PutUint32(bad[41:45], ^uint32(0))
		case "truncate":
			bad = bad[:len(bad)-1]
		case "append":
			bad = append(bad, 0)
		}
		if _, err := ParseAuthorization(bad); err == nil {
			t.Fatalf("accepted malformed authorization: %s", what)
		}
	}
	if _, err := ParseAuthorization(make([]byte, MaxAuthorizationSize+1)); err == nil {
		t.Fatal("oversized authorization accepted")
	}
}

func FuzzParseAuthorization(f *testing.F) {
	f.Add([]byte(authorizationMagic))
	f.Add(make([]byte, AuthorizationHeaderSize))
	s, err := NewSource(HybridLight)
	if err != nil {
		f.Fatal(err)
	}
	a, _, err := Authorize(s)
	if err != nil {
		f.Fatal(err)
	}
	seed, err := a.MarshalBinary()
	if err != nil {
		f.Fatal(err)
	}
	f.Add(seed)
	f.Fuzz(func(t *testing.T, b []byte) {
		a, err := ParseAuthorization(b)
		if err != nil {
			return
		}
		round, err := a.MarshalBinary()
		if err != nil || !bytes.Equal(round, b) {
			t.Fatal("noncanonical authorization round trip")
		}
	})
}

package hybridmail

import (
	"bytes"
	"testing"
)

func TestFullFlow(t *testing.T) {
	for _, mode := range []byte{Classical, HybridLight} {
		s, err := NewSource(mode)
		if err != nil {
			t.Fatal(err)
		}
		a, r, err := Authorize(s)
		if err != nil {
			t.Fatal(err)
		}
		f, err := Prepare(*a)
		if err != nil {
			t.Fatal(err)
		}
		defer f.Close()
		for _, n := range []int{0, 1024, 128 << 10} {
			message := bytes.Repeat([]byte{0, 1, 2, 255}, n/4)
			e, err := Seal(s.Public, message)
			if err != nil {
				t.Fatal(err)
			}
			wire, err := e.MarshalBinary()
			if err != nil {
				t.Fatal(err)
			}
			e, err = ParseEnvelope(wire)
			if err != nil {
				t.Fatal(err)
			}
			bob, err := OpenSource(s, e)
			if err != nil || !bytes.Equal(bob, message) {
				t.Fatalf("Bob: %v", err)
			}
			out, err := f.Transform(e)
			if err != nil {
				t.Fatal(err)
			}
			wire, err = out.MarshalBinary()
			if err != nil {
				t.Fatal(err)
			}
			out, err = ParseEnvelope(wire)
			if err != nil {
				t.Fatal(err)
			}
			carol, err := OpenReceiver(r, out)
			if err != nil || !bytes.Equal(carol, message) {
				t.Fatalf("Carol: %v", err)
			}
			if !bytes.Equal(e.Body, out.Body) || e.Nonce != out.Nonce || e.MessageID != out.MessageID {
				t.Fatal("body changed")
			}
			if _, err = f.Transform(out); err == nil {
				t.Fatal("second hop accepted")
			}
			repeated, err := f.Transform(e)
			if err != nil {
				t.Fatal(err)
			}
			if mode == HybridLight && bytes.Equal(repeated.LatPRE, out.LatPRE) {
				t.Fatal("missing fresh randomness")
			}
			carol, err = OpenReceiver(r, repeated)
			if err != nil || !bytes.Equal(carol, message) {
				t.Fatalf("repeat: %v", err)
			}
		}
	}
}
func TestBindingAndTampering(t *testing.T) {
	s, err := NewSource(HybridLight)
	if err != nil {
		t.Fatal(err)
	}
	a, r, err := Authorize(s)
	if err != nil {
		t.Fatal(err)
	}
	a2, r2, err := Authorize(s)
	if err != nil {
		t.Fatal(err)
	}
	f, err := Prepare(*a)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	f2, err := Prepare(*a2)
	if err != nil {
		t.Fatal(err)
	}
	defer f2.Close()
	e, err := Seal(s.Public, []byte("secret MIME content"))
	if err != nil {
		t.Fatal(err)
	}
	e2, err := Seal(s.Public, []byte("other MIME content"))
	if err != nil {
		t.Fatal(err)
	}
	out, err := f.Transform(e)
	if err != nil {
		t.Fatal(err)
	}
	out2, err := f.Transform(e2)
	if err != nil {
		t.Fatal(err)
	}
	other, err := f2.Transform(e)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = OpenReceiver(r, other); err == nil {
		t.Fatal("wrong authorization accepted")
	}
	if _, err = OpenReceiver(r2, other); err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{"body", "classical", "pq", "message", "source", "nonce", "suite", "authorization", "missing-pq"} {
		wire, _ := out.MarshalBinary()
		bad, err := ParseEnvelope(wire)
		if err != nil {
			t.Fatal(err)
		}
		// Test substitution by another valid capsule. A small coefficient change can
		// leave the decrypted LatPRE share unchanged; this is not a CCA transform.
		switch field {
		case "body":
			bad.Body[0] ^= 1
		case "classical":
			bad.Classical = out2.Classical
		case "pq":
			bad.LatPRE = out2.LatPRE
		case "message":
			bad.MessageID[0] ^= 1
		case "source":
			bad.SourceID[0] ^= 1
		case "nonce":
			bad.Nonce[0] ^= 1
		case "suite":
			bad.Mode = Classical
		case "authorization":
			bad.AuthorizationID[0] ^= 1
		case "missing-pq":
			bad.LatPRE = nil
		}
		if _, err = OpenReceiver(r, bad); err == nil {
			t.Fatalf("accepted tampering: %s", field)
		}
	}
	mixed := *e
	mixed.LatPRE = e2.LatPRE
	mixedOut, err := f.Transform(&mixed)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = OpenReceiver(r, mixedOut); err == nil {
		t.Fatal("accepted mixed shares")
	}
	wire, _ := e.MarshalBinary()
	if _, err = ParseEnvelope(append(wire, 0)); err == nil {
		t.Fatal("trailing data accepted")
	}
	for i := 0; i < HeaderSize; i++ {
		if _, err = ParseEnvelope(wire[:i]); err == nil {
			t.Fatal("truncated prefix accepted")
		}
	}
	f.Close()
	if _, err = f.Transform(e); err == nil {
		t.Fatal("closed forwarder accepted")
	}
}
func FuzzParseEnvelope(f *testing.F) {
	f.Add([]byte("LPMAIL01"))
	f.Add(make([]byte, HeaderSize))
	// Seed a structurally valid frame so fuzzing also reaches capsule/body slicing.
	seed, err := (&Envelope{Mode: HybridLight, Classical: []byte{1}, LatPRE: make([]byte, 3808), Body: make([]byte, 16)}).MarshalBinary()
	if err != nil {
		f.Fatal(err)
	}
	f.Add(seed)
	f.Fuzz(func(t *testing.T, b []byte) {
		e, err := ParseEnvelope(b)
		if err != nil {
			return
		}
		round, err := e.MarshalBinary()
		if err != nil || !bytes.Equal(round, b) {
			t.Fatal("noncanonical round trip")
		}
	})
}

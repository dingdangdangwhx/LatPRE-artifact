package latpre

import (
	"bytes"
	"testing"
)

func TestLight(t *testing.T) {
	c, err := New(make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	pk, sk, err := c.KeyGen()
	if err != nil {
		t.Fatal(err)
	}
	tp, ts, err := c.KeyGen()
	if err != nil {
		t.Fatal(err)
	}
	msg := bytes.Repeat([]byte{17}, 32)
	ct, err := c.Encrypt(pk, msg)
	if err != nil {
		t.Fatal(err)
	}
	got, err := c.DecryptSource(sk, ct)
	if err != nil || !bytes.Equal(got, msg) {
		t.Fatal(err)
	}
	rk, err := c.Rekey(sk, tp)
	if err != nil {
		t.Fatal(err)
	}
	f, err := c.Prepare(rk, pk, tp)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	out, err := f.Transform(ct)
	if err != nil {
		t.Fatal(err)
	}
	got, err = c.DecryptTerminal(ts, out)
	if err != nil || !bytes.Equal(got, msg) {
		t.Fatal(err)
	}
	if _, err = c.Encrypt(nil, msg); err == nil {
		t.Fatal("length check")
	}
	c.Close()
	if _, err = f.Transform(ct); err == nil {
		t.Fatal("closed context accepted")
	}
	f.Close()
	f.Close()
}

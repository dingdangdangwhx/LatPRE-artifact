package classic

import (
	"bytes"
	"testing"
)

func TestForwardShare(t *testing.T) {
	pub, priv, err := Generate()
	if err != nil {
		t.Fatal(err)
	}
	_, target, proxy, err := Authorize(priv)
	if err != nil {
		t.Fatal(err)
	}
	share := bytes.Repeat([]byte{9}, 32)
	ct, err := Seal(pub, share)
	if err != nil {
		t.Fatal(err)
	}
	got, err := Open(priv, ct)
	if err != nil || !bytes.Equal(got, share) {
		t.Fatal(err)
	}
	out, err := Transform(proxy, ct)
	if err != nil {
		t.Fatal(err)
	}
	got, err = Open(target, out)
	if err != nil || !bytes.Equal(got, share) {
		t.Fatal(err)
	}
	if _, err = Open(priv, out); err == nil {
		t.Fatal("wrong private key")
	}
	if _, err = Transform(proxy, append(ct, 0)); err == nil {
		t.Fatal("trailing packet accepted")
	}
	if _, err = Transform(proxy, out); err == nil {
		t.Fatal("wrong source accepted")
	}
}

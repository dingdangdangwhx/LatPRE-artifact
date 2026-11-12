package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	mail "latpre.example/hybridmail"
)

func TestLoadBinaryAndLegacyAuthorizations(t *testing.T) {
	s, err := mail.NewSource(mail.HybridLight)
	if err != nil {
		t.Fatal(err)
	}
	a, _, err := mail.Authorize(s)
	if err != nil {
		t.Fatal(err)
	}
	packed, err := a.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	legacy, err := json.Marshal(a)
	if err != nil {
		t.Fatal(err)
	}
	for _, data := range [][]byte{packed, append([]byte(" \n"), legacy...)} {
		p := filepath.Join(t.TempDir(), "authorization")
		if err := os.WriteFile(p, data, 0600); err != nil {
			t.Fatal(err)
		}
		got, err := loadAuthorization(p)
		if err != nil {
			t.Fatal(err)
		}
		round, err := got.MarshalBinary()
		if err != nil || !bytes.Equal(round, packed) {
			t.Fatal("binary and legacy CLI inputs disagree")
		}
	}
}

// Each invocation performs one role. No sender or proxy operation accepts a
// recipient secret; forwarding accepts only the authorization and source file.
package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"

	mail "latpre.example/hybridmail"
)

func read(path string) ([]byte, error) {
	if path == "" {
		return nil, errors.New("missing input path")
	}
	f, e := os.Open(path)
	if e != nil {
		return nil, e
	}
	defer f.Close()
	b, e := io.ReadAll(io.LimitReader(f, mail.MaxBody+(1<<20)+1))
	if len(b) > mail.MaxBody+(1<<20) {
		return nil, errors.New("file too large")
	}
	return b, e
}
func load(path string, v any) error {
	b, e := read(path)
	if e != nil {
		return e
	}
	return decodeJSON(b, v)
}
func decodeJSON(b []byte, v any) error {
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	if e := d.Decode(v); e != nil {
		return e
	}
	if d.Decode(new(any)) != io.EOF {
		return errors.New("trailing JSON")
	}
	return nil
}
func loadAuthorization(path string) (*mail.Authorization, error) {
	b, e := read(path)
	if e != nil {
		return nil, e
	}
	if bytes.HasPrefix(bytes.TrimSpace(b), []byte("{")) {
		var a mail.Authorization
		if e := decodeJSON(b, &a); e != nil {
			return nil, e
		}
		return &a, nil
	}
	return mail.ParseAuthorization(b)
}
func save(path string, b []byte, mode os.FileMode) error {
	if path == "" {
		return errors.New("missing output path")
	}
	f, e := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if e != nil {
		return e
	}
	_, e = f.Write(b)
	ce := f.Close()
	if e != nil {
		return e
	}
	return ce
}
func saveJSON(path string, v any, mode os.FileMode) error {
	b, e := json.Marshal(v)
	if e != nil {
		return e
	}
	return save(path, append(b, '\n'), mode)
}
func loadEnvelope(path string) (*mail.Envelope, error) {
	b, e := read(path)
	if e != nil {
		return nil, e
	}
	return mail.ParseEnvelope(b)
}
func saveEnvelope(path string, e *mail.Envelope) error {
	b, err := e.MarshalBinary()
	if err != nil {
		return err
	}
	return save(path, b, 0600)
}
func run() error {
	if len(os.Args) < 2 {
		return errors.New("usage: hybrid-mail {init|authorize|send|open-source|forward|open-receiver|inspect} [flags]")
	}
	command := os.Args[1]
	f := flag.NewFlagSet(command, flag.ContinueOnError)
	in := f.String("in", "", "input message/envelope")
	out := f.String("out", "", "new output file or directory")
	key := f.String("key", "", "private key package")
	public := f.String("public", "", "source public package")
	auth := f.String("auth", "", "proxy authorization")
	mode := f.String("mode", "hybrid", "hybrid or classical")
	format := f.String("format", "binary", "authorize output: binary or legacy json")
	if e := f.Parse(os.Args[2:]); e != nil {
		return e
	}
	if f.NArg() != 0 {
		return errors.New("unexpected positional arguments")
	}
	switch command {
	case "init":
		suite := mail.HybridLight
		if *mode == "classical" {
			suite = mail.Classical
		} else if *mode != "hybrid" {
			return errors.New("invalid mode")
		}
		s, e := mail.NewSource(suite)
		if e != nil {
			return e
		}
		if e = os.Mkdir(*out, 0700); e != nil {
			return e
		}
		if e = saveJSON(filepath.Join(*out, "bob-secret.json"), s, 0600); e != nil {
			return e
		}
		return saveJSON(filepath.Join(*out, "bob-public.json"), s.Public, 0644)
	case "authorize":
		if *format != "binary" && *format != "json" {
			return errors.New("authorization format must be binary or json")
		}
		var s mail.SourceSecret
		if e := load(*key, &s); e != nil {
			return e
		}
		a, r, e := mail.Authorize(&s)
		if e != nil {
			return e
		}
		if e = os.Mkdir(*out, 0700); e != nil {
			return e
		}
		if *format == "json" {
			if e = saveJSON(filepath.Join(*out, "proxy.json"), a, 0600); e != nil {
				return e
			}
		} else {
			packed, err := a.MarshalBinary()
			if err != nil {
				return err
			}
			if e = save(filepath.Join(*out, "proxy.bin"), packed, 0600); e != nil {
				return e
			}
		}
		return saveJSON(filepath.Join(*out, "carol-secret.json"), r, 0600)
	case "send":
		var p mail.Public
		if e := load(*public, &p); e != nil {
			return e
		}
		b, e := read(*in)
		if e != nil {
			return e
		}
		c, e := mail.Seal(p, b)
		if e != nil {
			return e
		}
		return saveEnvelope(*out, c)
	case "open-source":
		var s mail.SourceSecret
		if e := load(*key, &s); e != nil {
			return e
		}
		c, e := loadEnvelope(*in)
		if e != nil {
			return e
		}
		b, e := mail.OpenSource(&s, c)
		if e != nil {
			return e
		}
		return save(*out, b, 0600)
	case "forward":
		a, e := loadAuthorization(*auth)
		if e != nil {
			return e
		}
		c, e := loadEnvelope(*in)
		if e != nil {
			return e
		}
		proxy, e := mail.Prepare(*a)
		if e != nil {
			return e
		}
		defer proxy.Close()
		r, e := proxy.Transform(c)
		if e != nil {
			return e
		}
		return saveEnvelope(*out, r)
	case "open-receiver":
		var r mail.ReceiverSecret
		if e := load(*key, &r); e != nil {
			return e
		}
		c, e := loadEnvelope(*in)
		if e != nil {
			return e
		}
		b, e := mail.OpenReceiver(&r, c)
		if e != nil {
			return e
		}
		return save(*out, b, 0600)
	case "inspect":
		e, err := loadEnvelope(*in)
		if err != nil {
			return err
		}
		return json.NewEncoder(os.Stdout).Encode(map[string]any{"mode": e.Mode, "kind": e.Kind, "framing_bytes": mail.HeaderSize, "classical_capsule_bytes": len(e.Classical), "latpre_capsule_bytes": len(e.LatPRE), "encrypted_body_bytes": len(e.Body), "total_bytes": mail.HeaderSize + len(e.Classical) + len(e.LatPRE) + len(e.Body)})
	default:
		return errors.New("unknown command")
	}
}
func main() {
	if e := run(); e != nil {
		fmt.Fprintln(os.Stderr, e)
		os.Exit(1)
	}
}

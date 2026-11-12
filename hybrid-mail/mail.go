// Package hybridmail implements a research forwarding container. Source keys,
// dedicated delegatee keys, and source ciphertexts are honestly generated.
// It does not implement arbitrary-ciphertext security, production key delivery,
// SMTP, or global lifetime Q/M accounting.
package hybridmail

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"golang.org/x/crypto/hkdf"
	"io"
	"latpre.example/hybridmail/internal/classic"
	"latpre.example/hybridmail/internal/latpre"
)

const (
	Classical   byte = 1
	HybridLight byte = 2
	HeaderSize       = 134
	MaxBody          = 32 << 20
)
const magic = "LPMAIL01"

type Public struct {
	Version    int
	Mode       byte
	MatrixSeed []byte
	Classical  []byte
	LatPRE     []byte
}
type SourceSecret struct {
	Public    Public
	Classical []byte
	LatPRE    []byte
}
type ReceiverSecret struct {
	Version         int
	Mode            byte
	SourceID        [32]byte
	AuthorizationID [32]byte
	MatrixSeed      []byte
	Classical       []byte
	LatPRE          []byte
}
type Authorization struct {
	Version         int
	ID              [32]byte
	Source          Public
	TargetClassical []byte
	TargetLatPRE    []byte
	ClassicalProxy  []byte
	LatPRERekey     []byte
}
type Envelope struct {
	Mode, Kind                           byte
	SourceID, MessageID, AuthorizationID [32]byte
	Nonce                                [12]byte
	Classical, LatPRE, Body              []byte
}

func random(n int) ([]byte, error) { b := make([]byte, n); _, e := rand.Read(b); return b, e }
func (p Public) valid() bool {
	return p.Version == 1 && len(p.Classical) > 0 && len(p.Classical) < 65536 && ((p.Mode == HybridLight && len(p.MatrixSeed) == 32 && len(p.LatPRE) == latpre.PublicKeySize) || (p.Mode == Classical && len(p.MatrixSeed) == 0 && len(p.LatPRE) == 0))
}
func (p Public) ID() [32]byte { b, _ := json.Marshal(p); return sha256.Sum256(b) }
func NewSource(mode byte) (*SourceSecret, error) {
	if mode != Classical && mode != HybridLight {
		return nil, errors.New("unsupported suite")
	}
	pub, priv, err := classic.Generate()
	if err != nil {
		return nil, err
	}
	s := &SourceSecret{Public: Public{Version: 1, Mode: mode, Classical: pub}, Classical: priv}
	if mode == HybridLight {
		s.Public.MatrixSeed, err = random(32)
		if err != nil {
			return nil, err
		}
		c, err := latpre.New(s.Public.MatrixSeed)
		if err != nil {
			return nil, err
		}
		defer c.Close()
		s.Public.LatPRE, s.LatPRE, err = c.KeyGen()
		if err != nil {
			return nil, err
		}
	}
	return s, nil
}

// Authorize is run by Bob. Only the receiver package goes to Carol; only the
// authorization goes to the proxy. Key files need authenticated confidential delivery.
func Authorize(s *SourceSecret) (*Authorization, *ReceiverSecret, error) {
	if s == nil || !s.Public.valid() {
		return nil, nil, errors.New("invalid source key")
	}
	a := &Authorization{Version: 1, Source: s.Public}
	if _, e := rand.Read(a.ID[:]); e != nil {
		return nil, nil, e
	}
	r := &ReceiverSecret{Version: 1, Mode: s.Public.Mode, SourceID: s.Public.ID(), AuthorizationID: a.ID, MatrixSeed: append([]byte(nil), s.Public.MatrixSeed...)}
	var err error
	a.TargetClassical, r.Classical, a.ClassicalProxy, err = classic.Authorize(s.Classical)
	if err != nil {
		return nil, nil, err
	}
	if s.Public.Mode == HybridLight {
		c, e := latpre.New(s.Public.MatrixSeed)
		if e != nil {
			return nil, nil, e
		}
		defer c.Close()
		a.TargetLatPRE, r.LatPRE, e = c.KeyGen()
		if e != nil {
			return nil, nil, e
		}
		a.LatPRERekey, e = c.Rekey(s.LatPRE, a.TargetLatPRE)
		if e != nil {
			return nil, nil, e
		}
	}
	return a, r, nil
}
func (e *Envelope) context() []byte {
	b := append([]byte("LatPRE-Proton-hybrid-mail/v1\x00"), e.Mode)
	b = append(b, e.SourceID[:]...)
	b = append(b, e.MessageID[:]...)
	return b
}
func bodyCipher(e *Envelope, x, y []byte) (cipher.AEAD, error) {
	if len(x) != 32 || len(y) != 32 {
		return nil, errors.New("invalid shares")
	}
	var combined, key [32]byte
	for i := range combined {
		combined[i] = x[i] ^ y[i]
	}
	defer clear(combined[:])
	defer clear(key[:])
	kdf := hkdf.New(sha256.New, combined[:], nil, e.context())
	if _, err := io.ReadFull(kdf, key[:]); err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}
func Seal(p Public, mime []byte) (*Envelope, error) {
	if !p.valid() || len(mime) > MaxBody {
		return nil, errors.New("invalid public key or oversized payload")
	}
	e := &Envelope{Mode: p.Mode, SourceID: p.ID()}
	if _, err := rand.Read(e.MessageID[:]); err != nil {
		return nil, err
	}
	if _, err := rand.Read(e.Nonce[:]); err != nil {
		return nil, err
	}
	x, err := random(32)
	if err != nil {
		return nil, err
	}
	defer clear(x)
	y := make([]byte, 32)
	defer clear(y)
	e.Classical, err = classic.Seal(p.Classical, x)
	if err != nil {
		return nil, err
	}
	if p.Mode == HybridLight {
		if _, err = rand.Read(y); err != nil {
			return nil, err
		}
		c, err := latpre.New(p.MatrixSeed)
		if err != nil {
			return nil, err
		}
		defer c.Close()
		e.LatPRE, err = c.Encrypt(p.LatPRE, y)
		if err != nil {
			return nil, err
		}
	}
	aead, err := bodyCipher(e, x, y)
	if err != nil {
		return nil, err
	}
	e.Body = aead.Seal(nil, e.Nonce[:], mime, e.context())
	return e, nil
}

type Forwarder struct {
	authorization Authorization
	ctx           *latpre.Context
	pq            *latpre.Forwarder
	closed        bool
}

func Prepare(a Authorization) (*Forwarder, error) {
	if a.Version != 1 || !a.Source.valid() || a.ID == ([32]byte{}) || len(a.ClassicalProxy) == 0 {
		return nil, errors.New("invalid authorization")
	}
	// Own serialized slices: callers cannot change an authorization after preparation.
	b, _ := json.Marshal(a)
	var own Authorization
	if err := json.Unmarshal(b, &own); err != nil {
		return nil, err
	}
	f := &Forwarder{authorization: own}
	if a.Source.Mode == HybridLight {
		var err error
		f.ctx, err = latpre.New(a.Source.MatrixSeed)
		if err != nil {
			return nil, err
		}
		f.pq, err = f.ctx.Prepare(a.LatPRERekey, a.Source.LatPRE, a.TargetLatPRE)
		if err != nil {
			f.Close()
			return nil, err
		}
	} else if len(a.TargetLatPRE) != 0 || len(a.LatPRERekey) != 0 {
		return nil, errors.New("unexpected PQ material")
	}
	return f, nil
}
func (f *Forwarder) Close() {
	if f == nil {
		return
	}
	f.closed = true
	if f.pq != nil {
		f.pq.Close()
	}
	if f.ctx != nil {
		f.ctx.Close()
	}
}
func (f *Forwarder) Transform(e *Envelope) (*Envelope, error) {
	if f == nil || f.closed || e == nil {
		return nil, errors.New("closed forwarder")
	}
	if err := e.validate(); err != nil {
		return nil, err
	}
	a := &f.authorization
	if e.Kind != 0 || e.Mode != a.Source.Mode || e.SourceID != a.Source.ID() {
		return nil, errors.New("source, suite, or hop mismatch")
	}
	out := *e
	out.Kind = 1
	out.AuthorizationID = a.ID
	var err error
	out.Classical, err = classic.Transform(a.ClassicalProxy, e.Classical)
	if err != nil {
		return nil, err
	}
	if e.Mode == HybridLight {
		out.LatPRE, err = f.pq.Transform(e.LatPRE)
		if err != nil {
			return nil, err
		}
	}
	out.Body = append([]byte(nil), e.Body...)
	return &out, nil
}
func OpenSource(s *SourceSecret, e *Envelope) ([]byte, error) {
	if s == nil || e == nil || !s.Public.valid() || e.Kind != 0 || e.SourceID != s.Public.ID() || e.Mode != s.Public.Mode {
		return nil, errors.New("source key mismatch")
	}
	return open(e, s.Classical, s.LatPRE, s.Public.MatrixSeed, false)
}
func OpenReceiver(r *ReceiverSecret, e *Envelope) ([]byte, error) {
	if r == nil || e == nil || r.Version != 1 || e.Kind != 1 || e.Mode != r.Mode || e.SourceID != r.SourceID || e.AuthorizationID != r.AuthorizationID {
		return nil, errors.New("receiver key mismatch")
	}
	return open(e, r.Classical, r.LatPRE, r.MatrixSeed, true)
}
func open(e *Envelope, priv, sk, seed []byte, terminal bool) ([]byte, error) {
	if err := e.validate(); err != nil {
		return nil, err
	}
	x, err := classic.Open(priv, e.Classical)
	if err != nil {
		return nil, errors.New("cannot recover classical share")
	}
	defer clear(x)
	y := make([]byte, 32)
	defer func() { clear(y) }()
	if e.Mode == HybridLight {
		c, er := latpre.New(seed)
		if er != nil {
			return nil, er
		}
		defer c.Close()
		if terminal {
			y, err = c.DecryptTerminal(sk, e.LatPRE)
		} else {
			y, err = c.DecryptSource(sk, e.LatPRE)
		}
		if err != nil {
			return nil, errors.New("cannot recover LatPRE share")
		}
	}
	aead, err := bodyCipher(e, x, y)
	if err != nil {
		return nil, err
	}
	return aead.Open(nil, e.Nonce[:], e.Body, e.context())
}
func (e *Envelope) validate() error {
	if e == nil || (e.Mode != Classical && e.Mode != HybridLight) || e.Kind > 1 || len(e.Classical) == 0 || len(e.Classical) > 4096 || len(e.Body) < 16 || len(e.Body) > MaxBody+16 {
		return errors.New("invalid envelope")
	}
	if (e.Kind == 0) != (e.AuthorizationID == ([32]byte{})) {
		return errors.New("invalid authorization tag")
	}
	if e.Mode == Classical && len(e.LatPRE) != 0 {
		return errors.New("unexpected PQ capsule")
	}
	if e.Mode == HybridLight {
		n := latpre.SourceSize
		if e.Kind == 1 {
			n = latpre.TerminalSize
		}
		if len(e.LatPRE) != n {
			return errors.New("invalid PQ capsule size")
		}
	}
	return nil
}
func (e *Envelope) MarshalBinary() ([]byte, error) {
	if err := e.validate(); err != nil {
		return nil, err
	}
	var b bytes.Buffer
	b.WriteString(magic)
	b.WriteByte(e.Mode)
	b.WriteByte(e.Kind)
	b.Write(e.SourceID[:])
	b.Write(e.MessageID[:])
	b.Write(e.AuthorizationID[:])
	b.Write(e.Nonce[:])
	binary.Write(&b, binary.BigEndian, uint32(len(e.Classical)))
	binary.Write(&b, binary.BigEndian, uint32(len(e.LatPRE)))
	binary.Write(&b, binary.BigEndian, uint64(len(e.Body)))
	b.Write(e.Classical)
	b.Write(e.LatPRE)
	b.Write(e.Body)
	return b.Bytes(), nil
}
func ParseEnvelope(data []byte) (*Envelope, error) {
	if len(data) < HeaderSize || string(data[:8]) != magic {
		return nil, errors.New("bad envelope prefix")
	}
	e := &Envelope{Mode: data[8], Kind: data[9]}
	copy(e.SourceID[:], data[10:42])
	copy(e.MessageID[:], data[42:74])
	copy(e.AuthorizationID[:], data[74:106])
	copy(e.Nonce[:], data[106:118])
	a, b, c := uint64(binary.BigEndian.Uint32(data[118:122])), uint64(binary.BigEndian.Uint32(data[122:126])), binary.BigEndian.Uint64(data[126:134])
	if a > 4096 || b > latpre.SourceSize || c > MaxBody+16 || a+b+c != uint64(len(data)-HeaderSize) {
		return nil, errors.New("bad envelope lengths")
	}
	e.Classical = append([]byte(nil), data[HeaderSize:HeaderSize+int(a)]...)
	e.LatPRE = append([]byte(nil), data[HeaderSize+int(a):HeaderSize+int(a+b)]...)
	e.Body = append([]byte(nil), data[HeaderSize+int(a+b):]...)
	return e, e.validate()
}

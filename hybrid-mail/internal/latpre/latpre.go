// Package latpre is a single-threaded cgo adapter to the frozen Light build.
// It accepts honestly generated source records; registration is not a proof
// of ciphertext validity or durable global Q/M enforcement.
package latpre

/*
#cgo CFLAGS: -I${SRCDIR}/../../../latpre/include
#cgo LDFLAGS: -L${SRCDIR}/../../../latpre/build -llbpre -lm
#include "lbpre.h"
*/
import "C"
import (
	"crypto/rand"
	"errors"
	"fmt"
	"unsafe"
)

const (
	PublicKeySize = 8960
	SecretKeySize = 7168
	SourceSize    = 3808
	TerminalSize  = 1824
	RekeySize     = 53792
)

type Context struct {
	p        *C.lbpre_ctx
	closed   bool
	children int
}
type Forwarder struct {
	ctx            *Context
	cache          *C.lbpre_rekey_cache
	proxy          *C.lbpre_proxy
	source, target []byte
}

func ptr(b []byte) *C.uint8_t { return (*C.uint8_t)(unsafe.Pointer(&b[0])) }
func status(n C.int) error {
	if n != C.LBPRE_OK {
		return fmt.Errorf("LatPRE error %d", int(n))
	}
	return nil
}
func rng() (*C.lbpre_rng, error) {
	var seed [32]byte
	if _, err := rand.Read(seed[:]); err != nil {
		return nil, err
	}
	r := C.lbpre_rng_new(ptr(seed[:]))
	clear(seed[:])
	if r == nil {
		return nil, errors.New("RNG allocation")
	}
	return r, nil
}
func New(seed []byte) (*Context, error) {
	if len(seed) != 32 {
		return nil, errors.New("matrix seed must have 32 bytes")
	}
	p := C.lbpre_setup(20, ptr(seed))
	if p == nil {
		return nil, errors.New("Light setup failed")
	}
	return &Context{p: p}, nil
}
func (c *Context) valid() bool { return c != nil && c.p != nil && !c.closed }
func (c *Context) Close() {
	if c == nil {
		return
	}
	c.closed = true
	if c.children == 0 && c.p != nil {
		C.lbpre_ctx_free(c.p)
		c.p = nil
	}
}
func (c *Context) KeyGen() ([]byte, []byte, error) {
	if !c.valid() {
		return nil, nil, errors.New("closed context")
	}
	r, e := rng()
	if e != nil {
		return nil, nil, e
	}
	defer C.lbpre_rng_free(r)
	pk, sk := make([]byte, PublicKeySize), make([]byte, SecretKeySize)
	e = status(C.lbpre_keygen(c.p, ptr(pk), C.size_t(len(pk)), ptr(sk), C.size_t(len(sk)), r))
	return pk, sk, e
}
func (c *Context) Encrypt(pk, msg []byte) ([]byte, error) {
	if !c.valid() || len(pk) != PublicKeySize || len(msg) != 32 {
		return nil, errors.New("invalid encrypt arguments")
	}
	r, e := rng()
	if e != nil {
		return nil, e
	}
	defer C.lbpre_rng_free(r)
	out := make([]byte, SourceSize)
	e = status(C.lbpre_encrypt(c.p, ptr(out), C.size_t(len(out)), ptr(pk), C.size_t(len(pk)), ptr(msg), r))
	return out, e
}
func (c *Context) DecryptSource(sk, ct []byte) ([]byte, error) {
	if !c.valid() || len(sk) != SecretKeySize || len(ct) != SourceSize {
		return nil, errors.New("invalid source decrypt arguments")
	}
	out := make([]byte, 32)
	e := status(C.lbpre_decrypt_source(c.p, ptr(out), ptr(ct), C.size_t(len(ct)), ptr(sk), C.size_t(len(sk))))
	return out, e
}
func (c *Context) DecryptTerminal(sk, ct []byte) ([]byte, error) {
	if !c.valid() || len(sk) != SecretKeySize || len(ct) != TerminalSize {
		return nil, errors.New("invalid terminal decrypt arguments")
	}
	out := make([]byte, 32)
	e := status(C.lbpre_decrypt_terminal(c.p, ptr(out), ptr(ct), C.size_t(len(ct)), ptr(sk), C.size_t(len(sk))))
	return out, e
}
func (c *Context) Rekey(sk, pk []byte) ([]byte, error) {
	if !c.valid() || len(sk) != SecretKeySize || len(pk) != PublicKeySize {
		return nil, errors.New("invalid rekey arguments")
	}
	r, e := rng()
	if e != nil {
		return nil, e
	}
	defer C.lbpre_rng_free(r)
	out := make([]byte, RekeySize)
	e = status(C.lbpre_rekeygen(c.p, ptr(out), C.size_t(len(out)), ptr(sk), C.size_t(len(sk)), ptr(pk), C.size_t(len(pk)), r))
	return out, e
}
func (c *Context) Prepare(rk, source, target []byte) (*Forwarder, error) {
	if !c.valid() || len(rk) != RekeySize || len(source) != PublicKeySize || len(target) != PublicKeySize {
		return nil, errors.New("invalid prepare arguments")
	}
	cache := C.lbpre_rekey_prepare(c.p, ptr(rk), C.size_t(len(rk)), ptr(source), C.size_t(len(source)), ptr(target), C.size_t(len(target)))
	if cache == nil {
		return nil, errors.New("rekey preparation failed")
	}
	p := C.lbpre_proxy_new(c.p)
	if p == nil {
		C.lbpre_rekey_cache_free(cache)
		return nil, errors.New("proxy allocation failed")
	}
	c.children++
	return &Forwarder{c, cache, p, append([]byte(nil), source...), append([]byte(nil), target...)}, nil
}
func (f *Forwarder) Close() {
	if f == nil || f.cache == nil {
		return
	}
	C.lbpre_proxy_free(f.proxy)
	C.lbpre_rekey_cache_free(f.cache)
	f.proxy = nil
	f.cache = nil
	f.ctx.children--
	if f.ctx.closed {
		f.ctx.Close()
	}
}
func (f *Forwarder) Transform(ct []byte) ([]byte, error) {
	if f == nil || f.cache == nil || !f.ctx.valid() || len(ct) != SourceSize {
		return nil, errors.New("invalid forwarding arguments")
	}
	if e := status(C.lbpre_register(f.proxy, ptr(f.source), C.size_t(len(f.source)), ptr(ct), C.size_t(len(ct)))); e != nil {
		return nil, e
	}
	r, e := rng()
	if e != nil {
		return nil, e
	}
	defer C.lbpre_rng_free(r)
	out := make([]byte, TerminalSize)
	e = status(C.lbpre_reencrypt(f.proxy, ptr(out), C.size_t(len(out)), f.cache, ptr(f.source), C.size_t(len(f.source)), ptr(f.target), C.size_t(len(f.target)), ptr(ct), C.size_t(len(ct)), r))
	return out, e
}

// Package classic adapts Proton's pinned forwarding implementation. It wraps
// a 32-byte share in a legacy v3 PKESK, not the final email-body key.
package classic

import (
	"bytes"
	"encoding/json"
	"errors"
	"github.com/ProtonMail/go-crypto/openpgp/packet"
	pgp "github.com/ProtonMail/go-crypto/openpgp/v2"
	"io"
	"time"
)

func config() *packet.Config {
	return &packet.Config{Algorithm: packet.PubKeyAlgoEdDSA, Curve: packet.Curve25519}
}
func readKey(data []byte) (*pgp.Entity, error) {
	keys, err := pgp.ReadKeyRing(bytes.NewReader(data))
	if err != nil {
		return nil, err
	}
	if len(keys) != 1 || keys[0].PrimaryKey.Version != 4 {
		return nil, errors.New("expected one v4 entity")
	}
	return keys[0], nil
}
func serialize(e *pgp.Entity) ([]byte, []byte, error) {
	var pub, priv bytes.Buffer
	if err := e.Serialize(&pub); err != nil {
		return nil, nil, err
	}
	if err := e.SerializePrivateWithoutSigning(&priv, nil); err != nil {
		return nil, nil, err
	}
	return pub.Bytes(), priv.Bytes(), nil
}
func Generate() (public, private []byte, err error) {
	e, err := pgp.NewEntity("Bob", "hybrid prototype", "bob@example.test", config())
	if err != nil {
		return nil, nil, err
	}
	return serialize(e)
}
func Authorize(sourcePrivate []byte) (public, private, proxy []byte, err error) {
	e, err := readKey(sourcePrivate)
	if err != nil {
		return nil, nil, nil, err
	}
	target, instances, err := e.NewForwardingEntity("Carol", "dedicated forwarding key", "carol@example.test", config(), true)
	if err != nil {
		return nil, nil, nil, err
	}
	if len(instances) != 1 {
		return nil, nil, nil, errors.New("expected one forwarding subkey")
	}
	public, private, err = serialize(target)
	if err != nil {
		return nil, nil, nil, err
	}
	proxy, err = json.Marshal(instances[0])
	return
}
func capsule(data []byte) (*packet.EncryptedKey, error) {
	r := bytes.NewReader(data)
	p, err := packet.Read(r)
	if err != nil {
		return nil, err
	}
	k, ok := p.(*packet.EncryptedKey)
	if !ok || r.Len() != 0 || k.Version != 3 || k.Algo != packet.PubKeyAlgoECDH || k.KeyId == 0 {
		return nil, errors.New("expected one non-anonymous legacy ECDH PKESK")
	}
	return k, nil
}
func Seal(public, share []byte) ([]byte, error) {
	if len(share) != 32 {
		return nil, errors.New("share must contain 32 bytes")
	}
	e, err := readKey(public)
	if err != nil {
		return nil, err
	}
	k, ok := e.EncryptionKey(time.Now(), nil)
	if !ok {
		return nil, errors.New("no encryption key")
	}
	var out bytes.Buffer
	err = packet.SerializeEncryptedKey(&out, k.PublicKey, packet.CipherAES256, share, nil)
	return out.Bytes(), err
}
func Open(private, data []byte) ([]byte, error) {
	e, err := readKey(private)
	if err != nil {
		return nil, err
	}
	k, err := capsule(data)
	if err != nil {
		return nil, err
	}
	for _, sub := range e.Subkeys {
		if sub.PrivateKey != nil && sub.PublicKey.KeyId == k.KeyId {
			if err = k.Decrypt(sub.PrivateKey, nil); err != nil {
				return nil, err
			}
			if k.CipherFunc != packet.CipherAES256 || len(k.Key) != 32 {
				return nil, errors.New("invalid share")
			}
			return append([]byte(nil), k.Key...), nil
		}
	}
	return nil, errors.New("no matching decryption subkey")
}
func Transform(proxy, data []byte) ([]byte, error) {
	var instance packet.ForwardingInstance
	dec := json.NewDecoder(bytes.NewReader(proxy))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&instance); err != nil {
		return nil, err
	}
	if err := dec.Decode(new(any)); err != io.EOF {
		return nil, errors.New("trailing proxy data")
	}
	k, err := capsule(data)
	if err != nil {
		return nil, err
	}
	transformed, err := k.ProxyTransform(instance)
	if err != nil {
		return nil, err
	}
	var out bytes.Buffer
	err = transformed.Serialize(&out)
	return out.Bytes(), err
}

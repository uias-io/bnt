package main

import (
	"crypto/rand"
	"errors"
	"sync"
	"time"

	"github.com/uias-io/bnt"
)

type KeyPool struct {
	keys map[uint32]*KeyPair
	mu   sync.RWMutex
}

type KeyPair struct {
	AESKey  []byte
	HMACKey []byte
	Method  *bnt.SigningMethodBinary
	Active  bool
	Created time.Time
}

// RotateKeys Business layer implements key rotation.
func (kp *KeyPool) RotateKeys() error {
	kp.mu.Lock()
	defer kp.mu.Unlock()

	// 1. Generate new keys.
	newKid := uint32(time.Now().Unix())
	aesKey := make([]byte, 32)
	hmacKey := make([]byte, 32)
	_, _ = rand.Read(aesKey)
	_, _ = rand.Read(hmacKey)

	// 2. Create a new SigningMethod.
	method, err := bnt.NewSigningMethodBinaryWithKID(aesKey, hmacKey, newKid)
	if err != nil {
		return err
	}

	// 3. Add to the key pool.
	kp.keys[newKid] = &KeyPair{
		AESKey:  aesKey,
		HMACKey: hmacKey,
		Method:  method,
		Active:  true,
		Created: time.Now(),
	}

	// 4. Optional: mark old keys as inactive, but keep them for verifying old tokens.
	for kid, pair := range kp.keys {
		if kid != newKid {
			pair.Active = false
		}
	}

	return nil
}

// KeyFunc Business-layer verification function.
func (kp *KeyPool) KeyFunc(token *bnt.Token) (bnt.SigningMethod, error) {
	kp.mu.RLock()
	defer kp.mu.RUnlock()

	pair, ok := kp.keys[token.Kid]
	if !ok {
		return nil, bnt.ErrTokenSignatureInvalid
	}
	return pair.Method, nil
}

// IssueToken Business layer issues a new token (using the active key).
func (kp *KeyPool) IssueToken(claims bnt.Claims) (string, error) {
	kp.mu.RLock()
	var activeMethod bnt.SigningMethod
	for _, pair := range kp.keys {
		if pair.Active {
			activeMethod = pair.Method
			break
		}
	}
	kp.mu.RUnlock()

	if activeMethod == nil {
		return "", errors.New("no active key")
	}

	token := bnt.NewToken(claims, activeMethod)
	return token.SignedString()
}

// VerifyToken Business layer verifies a token (automatically selecting the corresponding key).
func (kp *KeyPool) VerifyToken(tokenStr string, claims bnt.Claims) (*bnt.Token, error) {
	return bnt.ParseWithClaims(tokenStr, claims, kp.KeyFunc)
}

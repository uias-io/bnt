package main

import (
	"crypto/rand"
	"errors"
	"sync"
	"time"

	"github.com/hiuias/bnt"
)

// ========== 业务层密钥管理 ==========

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

// 业务层实现密钥轮换
func (kp *KeyPool) RotateKeys() error {
	kp.mu.Lock()
	defer kp.mu.Unlock()

	// 1. 生成新密钥
	newKid := uint32(time.Now().Unix())
	aesKey := make([]byte, 32)
	hmacKey := make([]byte, 32)
	rand.Read(aesKey)
	rand.Read(hmacKey)

	// 2. 创建新的SigningMethod
	method, err := bnt.NewSigningMethodBinaryWithKID(aesKey, hmacKey, newKid)
	if err != nil {
		return err
	}

	// 3. 添加到密钥池
	kp.keys[newKid] = &KeyPair{
		AESKey:  aesKey,
		HMACKey: hmacKey,
		Method:  method,
		Active:  true,
		Created: time.Now(),
	}

	// 4. 可选：旧密钥标记为非活跃，但保留用于验证旧token
	for kid, pair := range kp.keys {
		if kid != newKid {
			pair.Active = false
		}
	}

	return nil
}

// 业务层验证函数
func (kp *KeyPool) KeyFunc(token *bnt.Token) (bnt.SigningMethod, error) {
	kp.mu.RLock()
	defer kp.mu.RUnlock()

	pair, ok := kp.keys[token.Kid]
	if !ok {
		return nil, bnt.ErrTokenSignatureInvalid
	}
	return pair.Method, nil
}

// 业务层签发新token（使用活跃密钥）
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

// 业务层验证token（自动选择对应密钥）
func (kp *KeyPool) VerifyToken(tokenStr string, claims bnt.Claims) (*bnt.Token, error) {
	return bnt.ParseWithClaims(tokenStr, claims, kp.KeyFunc)
}

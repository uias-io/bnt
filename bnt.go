package bnt

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"time"
)

// 常量定义（安全参数）
const (
	AESKeyLen     = 32 // AES-256 密钥长度（必须32字节）
	GCMNonceLen   = 12 // GCM推荐Nonce长度
	HMACSigLen    = 32 // HMAC-SHA256 签名长度
	MinHMACKeyLen = 16 // HMAC密钥最小长度
)

// 预定义错误
var (
	ErrInvalidKey                = errors.New("key is invalid")
	ErrInvalidKeyType            = errors.New("key is of invalid type")
	ErrHashUnavailable           = errors.New("the requested hash function is unavailable")
	ErrTokenMalformed            = errors.New("token is malformed")
	ErrTokenUnverifiable         = errors.New("token is unverifiable")
	ErrTokenSignatureInvalid     = errors.New("token signature is invalid")
	ErrTokenRequiredClaimMissing = errors.New("token is missing required claim")
	ErrTokenInvalidAudience      = errors.New("token has invalid audience")
	ErrTokenExpired              = errors.New("token is expired")
	ErrTokenUsedBeforeIssued     = errors.New("token used before issued")
	ErrTokenInvalidIssuer        = errors.New("token has invalid issuer")
	ErrTokenInvalidSubject       = errors.New("token has invalid subject")
	ErrTokenNotValidYet          = errors.New("token is not valid yet")
	ErrTokenInvalidId            = errors.New("token has invalid id")
	ErrTokenInvalidClaims        = errors.New("token has invalid claims")
	ErrInvalidType               = errors.New("invalid type for claim")
	ErrTokenTooShort             = errors.New("token is too short")
	ErrTokenDecryptionFailed     = errors.New("token decryption failed")
	ErrTokenInvalidFormat        = errors.New("token has invalid format")
	ErrInvalidBase64             = errors.New("invalid base64 characters in token")
	ErrAESKeyLength              = errors.New("AES key length is invalid")
	ErrHMACKeyLength             = errors.New("HMAC key length is invalid")
	ErrCipherCreation            = errors.New("failed to create cipher")
	ErrGCMCreation               = errors.New("failed to create GCM")
	ErrNonceGeneration           = errors.New("failed to generate nonce")
	ErrHMACCalculation           = errors.New("failed to calculate HMAC")
	ErrClaimsMarshaling          = errors.New("failed to marshal claims")
	ErrClaimsUnmarshaling        = errors.New("failed to unmarshal claims")
	ErrBase64Decoding            = errors.New("failed to decode base64")
)

// 用于验证Base64字符串的正则表达式
var base64Regex = regexp.MustCompile(`^[A-Za-z0-9+/]+(={0,2})$`)

// Claims 定义claims接口，所有自定义claims需实现此接口
type Claims interface {
	Valid() error
}

// ClaimStrings 可以序列化为字符串数组或单个字符串
type ClaimStrings []string

// RegisteredClaims 包含标准的声明字段
type RegisteredClaims struct {
	Issuer    string       `json:"iss,omitempty"` // 签发者
	Subject   string       `json:"sub,omitempty"` // 主题
	Audience  ClaimStrings `json:"aud,omitempty"` // 接收者
	ExpiresAt *time.Time   `json:"exp,omitempty"` // 过期时间
	NotBefore *time.Time   `json:"nbf,omitempty"` // 生效时间
	IssuedAt  *time.Time   `json:"iat,omitempty"` // 签发时间
	ID        string       `json:"jti,omitempty"` // Token ID
}

// Valid 验证标准声明
func (c *RegisteredClaims) Valid() error {
	now := time.Now().UTC()

	// 验证签发者
	if c.Issuer == "" {
		return ErrTokenInvalidIssuer
	}

	// 验证主题
	if c.Subject == "" {
		return ErrTokenInvalidSubject
	}

	// 验证ID
	if c.ID == "" {
		return ErrTokenInvalidId
	}

	// 验证过期时间
	if c.ExpiresAt != nil && !c.ExpiresAt.IsZero() {
		expTime := *c.ExpiresAt
		if expTime.Before(now) {
			return ErrTokenExpired
		}
	}

	// 验证生效时间
	if c.NotBefore != nil && !c.NotBefore.IsZero() {
		nbfTime := *c.NotBefore
		if nbfTime.After(now) {
			return ErrTokenNotValidYet
		}
	}

	// 验证签发时间
	if c.IssuedAt != nil && !c.IssuedAt.IsZero() {
		iatTime := *c.IssuedAt
		if iatTime.After(now) {
			return ErrTokenUsedBeforeIssued
		}
	}

	return nil
}

// SigningMethod 定义签名方法接口
type SigningMethod interface {
	Alg() string
	Sign(payload []byte) ([]byte, error)
	Verify(signedData []byte) ([]byte, error)
}

// SigningMethodBinary 二进制签名实现
type SigningMethodBinary struct {
	aesKey  []byte
	hmacKey []byte
}

// NewSigningMethodBinary 创建新的二进制签名方法
func NewSigningMethodBinary(aesKey, hmacKey []byte) (*SigningMethodBinary, error) {
	if len(aesKey) != AESKeyLen {
		return nil, fmt.Errorf("%w: must be %d bytes (AES-256), got %d", ErrAESKeyLength, AESKeyLen, len(aesKey))
	}
	if len(hmacKey) < MinHMACKeyLen {
		return nil, fmt.Errorf("%w: too short (min %d bytes), got %d", ErrHMACKeyLength, MinHMACKeyLen, len(hmacKey))
	}
	return &SigningMethodBinary{
		aesKey:  aesKey,
		hmacKey: hmacKey,
	}, nil
}

// Alg 返回算法名称
func (s *SigningMethodBinary) Alg() string {
	return "BINARY-HS256"
}

// Sign 对payload进行签名，返回二进制token
func (s *SigningMethodBinary) Sign(payload []byte) ([]byte, error) {
	// 步骤1: AES-GCM加密payload
	block, err := aes.NewCipher(s.aesKey)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrCipherCreation, err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrGCMCreation, err)
	}

	nonce := make([]byte, GCMNonceLen)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrNonceGeneration, err)
	}

	// 加密，结果包含nonce
	encryptedPayload := gcm.Seal(nonce, nonce, payload, nil)

	// 步骤2: HMAC-SHA256签名
	mac := hmac.New(sha256.New, s.hmacKey)
	if _, err := mac.Write(encryptedPayload); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrHMACCalculation, err)
	}
	signature := mac.Sum(nil)

	// 步骤3: 拼接二进制流（加密payload + 签名）
	return append(encryptedPayload, signature...), nil
}

// Verify 验证签名并返回解密后的payload
func (s *SigningMethodBinary) Verify(signedData []byte) ([]byte, error) {
	// 步骤1: 检查长度
	if len(signedData) < HMACSigLen+GCMNonceLen {
		return nil, ErrTokenTooShort
	}

	// 步骤2: 分离加密payload和签名
	encryptedPayload := signedData[:len(signedData)-HMACSigLen]
	receivedSig := signedData[len(signedData)-HMACSigLen:]

	// 步骤3: 验证HMAC签名
	mac := hmac.New(sha256.New, s.hmacKey)
	if _, err := mac.Write(encryptedPayload); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrHMACCalculation, err)
	}
	expectedSig := mac.Sum(nil)
	if !hmac.Equal(receivedSig, expectedSig) {
		return nil, ErrTokenSignatureInvalid
	}

	// 步骤4: 解密payload
	block, err := aes.NewCipher(s.aesKey)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrCipherCreation, err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrGCMCreation, err)
	}

	nonce := encryptedPayload[:GCMNonceLen]
	ciphertext := encryptedPayload[GCMNonceLen:]

	// 解密
	decryptedPayload, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, ErrTokenDecryptionFailed
	}

	return decryptedPayload, nil
}

// Token 表示一个令牌对象
type Token struct {
	Raw       string                 // 原始令牌字符串
	Claims    Claims                 // 声明对象
	Method    SigningMethod          // 签名方法
	Signature []byte                 // 签名部分
	Header    map[string]interface{} // 头部信息（兼容JWT格式）
}

// NewToken 创建一个新的Token
func NewToken(claims Claims, method SigningMethod) *Token {
	return &Token{
		Claims: claims,
		Method: method,
		Header: map[string]interface{}{
			"alg": method.Alg(),
			"typ": "JWT",
		},
	}
}

// SignedString 生成签名后的token字符串，确保使用标准Base64编码
func (t *Token) SignedString() (string, error) {
	// 将claims序列化为JSON
	claimsBytes, err := json.Marshal(t.Claims)
	if err != nil {
		return "", fmt.Errorf("%w: %v", ErrClaimsMarshaling, err)
	}

	// 签名
	signedBytes, err := t.Method.Sign(claimsBytes)
	if err != nil {
		return "", fmt.Errorf("signing failed: %w", err)
	}

	// 使用标准Base64编码，确保URL安全
	encoded := base64.StdEncoding.EncodeToString(signedBytes)

	// 验证生成的Base64字符串是否符合标准
	if !base64Regex.MatchString(encoded) {
		return "", ErrInvalidBase64
	}

	t.Raw = encoded
	return encoded, nil
}

// Parse 解析并验证token字符串
func Parse(tokenStr string, claims Claims, method SigningMethod) (*Token, error) {
	// 验证输入的Base64格式
	if !base64Regex.MatchString(tokenStr) {
		return nil, ErrInvalidBase64
	}

	// Base64解码
	tokenBytes, err := base64.StdEncoding.DecodeString(tokenStr)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrBase64Decoding, err)
	}

	// 验证签名并获取解密后的payload
	decryptedBytes, err := method.Verify(tokenBytes)
	if err != nil {
		return nil, fmt.Errorf("signature verification failed: %w", err)
	}

	// 反序列化到claims
	if err := json.Unmarshal(decryptedBytes, claims); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrClaimsUnmarshaling, err)
	}

	// 验证claims
	if err := claims.Valid(); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrTokenInvalidClaims, err)
	}

	// 创建并返回token对象
	token := &Token{
		Raw:    tokenStr,
		Claims: claims,
		Method: method,
		Header: map[string]interface{}{
			"alg": method.Alg(),
			"typ": "JWT",
		},
	}

	return token, nil
}

// ParseWithClaims 解析令牌并使用提供的函数验证声明
func ParseWithClaims(tokenStr string, claims Claims, keyFunc func(*Token) (SigningMethod, error)) (*Token, error) {
	// 先解析令牌但不验证签名
	if !base64Regex.MatchString(tokenStr) {
		return nil, ErrInvalidBase64
	}

	tokenBytes, err := base64.StdEncoding.DecodeString(tokenStr)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrBase64Decoding, err)
	}

	if len(tokenBytes) < HMACSigLen+GCMNonceLen {
		return nil, ErrTokenTooShort
	}

	// 创建临时令牌以获取算法信息
	token := &Token{
		Raw: tokenStr,
		Header: map[string]interface{}{
			"alg": "BINARY-HS256", // 固定算法
			"typ": "JWT",
		},
	}

	// 获取签名方法
	method, err := keyFunc(token)
	if err != nil {
		return nil, err
	}

	// 现在验证签名
	decryptedBytes, err := method.Verify(tokenBytes)
	if err != nil {
		return nil, fmt.Errorf("signature verification failed: %w", err)
	}

	// 反序列化到claims
	if err := json.Unmarshal(decryptedBytes, claims); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrClaimsUnmarshaling, err)
	}

	// 验证claims
	if err := claims.Valid(); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrTokenInvalidClaims, err)
	}

	token.Claims = claims
	token.Method = method

	return token, nil
}

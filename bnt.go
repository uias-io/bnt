package bnt

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"time"
)

// [4字节Kid][4字节随机数][1字节版本][3字节保留][1字节标志][2字节原始Token长度][原始Token][12B nonce]

// 常量定义（安全参数）
const (
	AESKeyLen      = 32   // AES-256 密钥长度（必须32字节）
	GCMNonceLen    = 12   // GCM推荐Nonce长度
	HMACSigLen     = 32   // HMAC-SHA256 签名长度
	MinHMACKeyLen  = 16   // HMAC密钥最小长度
	MaxTokenLen    = 8192 // 最大token长度限制（8KB）
	HeaderPlainLen = 15   // 头部总长度：4Kid+4rand+1ver+3rsv+1flag+2len
)

// 预定义错误
var (
	ErrInvalidKey                = errors.New("key is invalid")
	ErrInvalidKeyType            = errors.New("key is of invalid type")
	ErrAESKeyLength              = errors.New("AES key length is invalid")
	ErrHMACKeyLength             = errors.New("HMAC key length is invalid")
	ErrHashUnavailable           = errors.New("the requested hash function is unavailable")
	ErrTokenMalformed            = errors.New("token is malformed")
	ErrTokenUnverifiable         = errors.New("token is unverifiable")
	ErrTokenSignatureInvalid     = errors.New("token signature is invalid")
	ErrTokenTooShort             = errors.New("token is too short")
	ErrTokenTooLarge             = errors.New("token exceeds maximum size")
	ErrTokenInvalidFormat        = errors.New("token has invalid format")
	ErrTokenDecryptionFailed     = errors.New("token decryption failed")
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
	ErrTokenTooManyRenewals      = errors.New("token has exceeded maximum renewals")
	ErrTokenRefreshNotAllowed    = errors.New("token does not allow refresh")
	ErrTokenRefreshExpired       = errors.New("cannot refresh expired token")
	ErrTokenRefreshNotYetValid   = errors.New("token not yet valid for refresh")
	ErrTokenRefreshOverflow      = errors.New("issue count overflow")
	ErrTokenRefreshInvalidTTL    = errors.New("invalid TTL for refresh")
	ErrTokenRefreshFailed        = errors.New("token refresh failed")
	ErrInvalidBase64             = errors.New("invalid base64 characters in token")
	ErrBase64Decoding            = errors.New("failed to decode base64")
	ErrCipherCreation            = errors.New("failed to create cipher")
	ErrGCMCreation               = errors.New("failed to create GCM")
	ErrNonceGeneration           = errors.New("failed to generate nonce")
	ErrHMACCalculation           = errors.New("failed to calculate HMAC")
	ErrClaimsMarshaling          = errors.New("failed to marshal claims")
	ErrClaimsUnmarshaling        = errors.New("failed to unmarshal claims")
)

// VerificationError 提供更详细的错误上下文
type VerificationError struct {
	Err  error
	Step string
	Info string
}

func (e *VerificationError) Error() string {
	if e.Info != "" {
		return fmt.Sprintf("%s at %s: %s", e.Err, e.Step, e.Info)
	}
	return fmt.Sprintf("%s at %s", e.Err, e.Step)
}

func (e *VerificationError) Unwrap() error {
	return e.Err
}

// Base64查找表
var base64Table [256]uint8

const (
	base64Invalid = 0
	base64Valid   = 1
)

// 初始化Base64查找表
func init() {
	// 标准Base64字符集: A-Z a-z 0-9 + /
	for c := 'A'; c <= 'Z'; c++ {
		base64Table[c] = base64Valid
	}
	for c := 'a'; c <= 'z'; c++ {
		base64Table[c] = base64Valid
	}
	for c := '0'; c <= '9'; c++ {
		base64Table[c] = base64Valid
	}
	base64Table['+'] = base64Valid
	base64Table['/'] = base64Valid
	base64Table['='] = base64Valid // 允许填充字符
}

// IsValidBase64 验证Base64字符串格式（高性能查表法）
func IsValidBase64(s string) bool {
	n := len(s)

	// 长度检查：不能为空，必须是4的倍数，不能超过最大限制
	if n == 0 || n%4 != 0 || n > MaxTokenLen {
		return false
	}

	// 检查填充字符
	eqCount := 0
	if n > 0 && s[n-1] == '=' {
		eqCount = 1
		if n > 1 && s[n-2] == '=' {
			eqCount = 2
		}
	}
	// Base64填充最多2个'='
	if eqCount > 2 {
		return false
	}

	// 验证非填充部分的字符
	limit := n - eqCount
	for i := 0; i < limit; i++ {
		c := s[i]
		// 快速检查ASCII范围（性能优化）
		if c > 127 {
			return false
		}
		if base64Table[c] == base64Invalid {
			return false
		}
	}

	return true
}

// Claims 定义claims接口，所有自定义claims需实现此接口
type Claims interface {
	Valid() error
}

// RegisteredClaims 包含标准的声明字段
type RegisteredClaims struct {
	ExpiresAt     *time.Time `json:"exp,omitempty"` // 过期时间
	NotBefore     *time.Time `json:"nbf,omitempty"` // 生效时间
	IssuedAt      *time.Time `json:"iat,omitempty"` // 签发时间
	ID            string     `json:"jti,omitempty"` // Token ID
	Ttl           uint32     `json:"ttl,omitempty"` // 有效时长（秒）
	IssueCount    uint32     `json:"isc,omitempty"` // 续签累计次数
	MaxIssueCount uint32     `json:"mic,omitempty"` // 最大允许续签次数
}

// Valid 验证标准声明
func (c *RegisteredClaims) Valid() error {
	now := time.Now().UTC()

	// 验证ID
	if c.ID == "" {
		return ErrTokenInvalidId
	}

	// 验证续签次数
	if c.IssueCount > c.MaxIssueCount {
		return ErrTokenTooManyRenewals
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

	// 验证TTL（基于签发时间）
	if c.IssuedAt != nil && c.Ttl > 0 {
		expTime := c.IssuedAt.Add(time.Duration(c.Ttl) * time.Second)
		if now.After(expTime) {
			return ErrTokenExpired
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
	kid     uint32 // Key ID，用于密钥轮换
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
		kid:     uint32(time.Now().Unix()),
	}, nil
}

// NewSigningMethodBinaryWithKID 创建带Key ID的二进制签名方法
func NewSigningMethodBinaryWithKID(aesKey, hmacKey []byte, kid uint32) (*SigningMethodBinary, error) {
	method, err := NewSigningMethodBinary(aesKey, hmacKey)
	if err != nil {
		return nil, err
	}
	method.kid = kid
	return method, nil
}

// Alg 返回算法名称
func (s *SigningMethodBinary) Alg() string {
	if s.kid != 0 {
		return fmt.Sprintf("BINARY-HS256-KID-%d", s.kid)
	}
	return "BINARY-HS256"
}

// Sign 对payload进行签名，返回二进制token
func (s *SigningMethodBinary) Sign(payload []byte) ([]byte, error) {
	if s.kid == 0 {
		return nil, errors.New("kid not configured")
	}
	if len(s.aesKey) != AESKeyLen {
		return nil, errors.New("aesKey must be 32 bytes for AES‑256")
	}
	if len(s.hmacKey) < MinHMACKeyLen {
		return nil, errors.New("hmacKey too short, min 16 bytes")
	}

	block, err := aes.NewCipher(s.aesKey)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrCipherCreation, err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrGCMCreation, err)
	}

	// 4字节随机数
	prefixRand := make([]byte, 4)
	if _, err := io.ReadFull(rand.Reader, prefixRand); err != nil {
		return nil, fmt.Errorf("rand prefix failed: %w", err)
	}
	// GCM nonce 12字节
	nonce := make([]byte, GCMNonceLen)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("rand nonce failed: %w", err)
	}

	// ==========组装15字节明文头部==========
	plainHeader := make([]byte, HeaderPlainLen)
	// 0‑3: kid uint32大端
	binary.BigEndian.PutUint32(plainHeader[0:4], s.kid)
	// 4‑7:4字节随机数
	copy(plainHeader[4:8], prefixRand)
	// 8:版本 0x01
	plainHeader[8] = 0x01
	//9‑11:保留位 0
	copy(plainHeader[9:12], []byte{0, 0, 0})
	//12:flags
	var flags byte = 0x01
	plainHeader[12] = flags
	// 13‑14 fullCipherLen 暂时留0，加密完成回填

	// AAD取前13字节！排除后面2字节密文长度（加密前不知道长度）
	aad := plainHeader[:13]

	// AES‑GCM加密 payload，fullCipherText = cipher+tag
	fullCipherText := gcm.Seal(nil, nonce, payload, aad)

	// 加密完成后回填密文长度到头部
	binary.BigEndian.PutUint16(plainHeader[13:15], uint16(len(fullCipherText)))

	// innerPayload = plainHeader(15) + fullCipherText + nonce(12)
	innerPayloadBuf := make([]byte, 0, HeaderPlainLen+len(fullCipherText)+GCMNonceLen)
	innerPayloadBuf = append(innerPayloadBuf, plainHeader...)
	innerPayloadBuf = append(innerPayloadBuf, fullCipherText...)
	innerPayloadBuf = append(innerPayloadBuf, nonce...)

	// HMAC‑SHA256 对innerPayloadBuf签名
	mac := hmac.New(sha256.New, s.hmacKey)
	if _, err = mac.Write(innerPayloadBuf); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrHMACCalculation, err)
	}
	signature := mac.Sum(nil)

	// 最终二进制 = innerPayload + HMAC签名
	finalToken := append(append([]byte(nil), innerPayloadBuf...), signature...)
	return finalToken, nil
}

// Verify 验证签名并返回解密后的payload
func (s *SigningMethodBinary) Verify(signedData []byte) ([]byte, error) {
	const minFullCipher = 16 // GCM最小密文长度(仅tag)

	if len(signedData) > MaxTokenLen {
		return nil, ErrTokenTooShort
	}
	//最小长度：15头部 + 最小密文16 + nonce12 + hmac32
	minTotal := HeaderPlainLen + minFullCipher + GCMNonceLen + HMACSigLen
	if len(signedData) < minTotal {
		return nil, ErrTokenTooShort
	}

	innerPayload := signedData[:len(signedData)-HMACSigLen]
	receivedSig := signedData[len(signedData)-HMACSigLen:]

	//第一步 HMAC签名校验
	mac := hmac.New(sha256.New, s.hmacKey)
	if _, err := mac.Write(innerPayload); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrHMACCalculation, err)
	}
	expectSig := mac.Sum(nil)
	if !hmac.Equal(receivedSig, expectSig) {
		return nil, ErrTokenSignatureInvalid
	}

	offset := 0
	plainHeader := innerPayload[offset : offset+HeaderPlainLen]
	offset += HeaderPlainLen

	//解析明文头部
	kid := binary.BigEndian.Uint32(plainHeader[0:4])
	ver := plainHeader[8]
	reserved := plainHeader[9:12]
	flags := plainHeader[12]
	fullCipherLen := int(binary.BigEndian.Uint16(plainHeader[13:15]))

	//协议版本、保留位、标志校验
	if ver != 0x01 {
		return nil, ErrTokenDecryptionFailed
	}
	if !bytes.Equal(reserved, []byte{0, 0, 0}) {
		return nil, ErrTokenDecryptionFailed
	}
	if flags != 0x01 {
		return nil, ErrTokenDecryptionFailed
	}

	//fullCipherLen安全边界校验
	maxAllowedCipher := MaxTokenLen - (HeaderPlainLen + GCMNonceLen + HMACSigLen)
	if fullCipherLen < minFullCipher || fullCipherLen > maxAllowedCipher {
		return nil, ErrTokenDecryptionFailed
	}

	remain := len(innerPayload) - offset
	need := fullCipherLen + GCMNonceLen
	if remain != need {
		return nil, ErrTokenTooShort
	}

	fullCipherText := innerPayload[offset : offset+fullCipherLen]
	offset += fullCipherLen
	nonce := innerPayload[offset : offset+GCMNonceLen]

	//校验kid与当前method实例匹配
	if kid != s.kid {
		return nil, ErrTokenSignatureInvalid
	}

	//AAD取完整13字节明文头部（已经包含4字节随机数）
	aad := plainHeader[:13]

	block, err := aes.NewCipher(s.aesKey)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrCipherCreation, err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrGCMCreation, err)
	}

	plain, err := gcm.Open(nil, nonce, fullCipherText, aad)
	if err != nil {
		return nil, ErrTokenDecryptionFailed
	}

	return plain, nil
}

// Token 表示一个令牌对象
type Token struct {
	Raw       string        // 原始令牌字符串
	Claims    Claims        // 声明对象
	Method    SigningMethod // 签名方法
	Signature []byte        // 签名部分
}

// NewToken 创建一个新的Token
func NewToken(claims Claims, method SigningMethod) *Token {
	return &Token{
		Claims: claims,
		Method: method,
	}
}

// SignedString 生成签名后的token字符串，确保使用标准Base64编码
func (t *Token) SignedString() (string, error) {
	// 将claims序列化为JSON
	claimsBytes, err := json.Marshal(t.Claims)
	if err != nil {
		return "", fmt.Errorf("%w: %w", ErrClaimsMarshaling, err)
	}

	// 签名
	signedBytes, err := t.Method.Sign(claimsBytes)
	if err != nil {
		return "", fmt.Errorf("signing failed: %w", err)
	}

	// 使用标准Base64编码
	encoded := base64.StdEncoding.EncodeToString(signedBytes)

	// 验证生成的Base64字符串是否符合标准（使用高性能查表法）
	if !IsValidBase64(encoded) {
		return "", ErrInvalidBase64
	}

	t.Raw = encoded
	return encoded, nil
}

// Refreshable 接口
type Refreshable interface {
	Refresh(tid string) error
}

// RegisteredClaims 实现 Refreshable
func (c *RegisteredClaims) Refresh(tid string) error {

	// 1. 检查是否允许续签
	if c.MaxIssueCount == 0 {
		return ErrTokenRefreshNotAllowed
	}

	// 2. 检查续签次数是否已达上限
	if c.IssueCount >= c.MaxIssueCount {
		return ErrTokenTooManyRenewals
	}

	// 3. 检查是否已过期（不允许续签过期 token）
	now := time.Now().UTC()
	if c.ExpiresAt != nil && !c.ExpiresAt.IsZero() && c.ExpiresAt.Before(now) {
		return ErrTokenRefreshExpired
	}

	// 4. 检查是否尚未生效
	if c.NotBefore != nil && !c.NotBefore.IsZero() && c.NotBefore.After(now) {
		return ErrTokenRefreshNotYetValid
	}

	// 5. 检查 IssueCount 是否会溢出
	if c.IssueCount == ^uint32(0) {
		return ErrTokenRefreshOverflow
	}

	// 6. 检查 TTL 是否有效
	if c.Ttl == 0 {
		return ErrTokenRefreshInvalidTTL
	}

	if tid == "" {
		return ErrTokenInvalidId
	}

	c.ID = tid
	c.IssueCount++
	c.IssuedAt = &now
	c.NotBefore = &now

	expTime := now.Add(time.Duration(c.Ttl) * time.Second)
	c.ExpiresAt = &expTime

	return nil
}

// Token 的 Refresh 方法
func (t *Token) Refresh(tid string) error {
	if refreshable, ok := t.Claims.(Refreshable); ok {
		return refreshable.Refresh(tid)
	}
	return errors.New("claims does not implement Refreshable interface")
}

// Parse 解析并验证token字符串
func Parse(tokenStr string, claims Claims, method SigningMethod) (*Token, error) {
	// 验证输入的Base64格式（使用高性能查表法）
	if !IsValidBase64(tokenStr) {
		return nil, ErrInvalidBase64
	}

	// Base64解码
	tokenBytes, err := base64.StdEncoding.DecodeString(tokenStr)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrBase64Decoding, err)
	}

	// 验证签名并获取解密后的payload
	decryptedBytes, err := method.Verify(tokenBytes)
	if err != nil {
		return nil, fmt.Errorf("signature verification failed: %w", err)
	}

	// 反序列化到claims
	if err := json.Unmarshal(decryptedBytes, claims); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrClaimsUnmarshaling, err)
	}

	// 验证claims
	if err := claims.Valid(); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrTokenInvalidClaims, err)
	}

	// 创建并返回token对象
	token := &Token{
		Raw:    tokenStr,
		Claims: claims,
		Method: method,
	}

	return token, nil
}

// ParseWithClaims 解析令牌并使用提供的函数验证声明
func ParseWithClaims(tokenStr string, claims Claims, keyFunc func(*Token) (SigningMethod, error)) (*Token, error) {
	// 先解析令牌但不验证签名（使用高性能查表法）
	if !IsValidBase64(tokenStr) {
		return nil, ErrInvalidBase64
	}

	tokenBytes, err := base64.StdEncoding.DecodeString(tokenStr)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrBase64Decoding, err)
	}

	if len(tokenBytes) < HMACSigLen+GCMNonceLen {
		return nil, ErrTokenTooShort
	}

	// 创建临时令牌
	token := &Token{
		Raw: tokenStr,
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
		return nil, fmt.Errorf("%w: %w", ErrClaimsUnmarshaling, err)
	}

	// 验证claims
	if err := claims.Valid(); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrTokenInvalidClaims, err)
	}

	token.Claims = claims
	token.Method = method

	return token, nil
}

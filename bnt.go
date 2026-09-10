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

// [4Bytes Kid][4Bytes Random][1Byte Version][4Bytes Reserved][1Byte Flags][2Bytes RawTokenLength][RawToken][12B nonce]
// Constant definitions (security parameters)
const (
	AESKeyLen      = 32   // AES‑256 key length (must be 32 bytes)
	GCMNonceLen    = 12   // Recommended GCM Nonce length
	HMACSigLen     = 32   // HMAC‑SHA256 signature length
	MinHMACKeyLen  = 16   // Minimum HMAC key length
	MaxTokenLen    = 8192 // Maximum token length limit (8KB)
	HeaderPlainLen = 16   // Total plain header length: 4Kid+4rand+1ver+3rsv+1flag+2len
)

// Predefined errors
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
	ErrClaimsUnmarshalling       = errors.New("failed to unmarshal claims")
	ErrTokenKidMismatch          = errors.New("token kid mismatch")
)

// VerificationError provides detailed error context
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

// Base64 lookup table
var base64Table [256]uint8

const (
	base64Invalid = 0
	base64Valid   = 1
)

// init initializes Base64 lookup table
func init() {
	// Standard Base64 charset: A‑Z a‑z 0‑9 + /
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
	base64Table['='] = base64Valid // Allow padding character
}

// IsValidBase64 validates Base64 string format with high‑performance lookup table
func IsValidBase64(s string) bool {
	n := len(s)

	// Length check: cannot be empty, must be multiple of 4, cannot exceed max limit
	if n == 0 || n%4 != 0 || n > MaxTokenLen {
		return false
	}

	// Check padding characters
	eqCount := 0
	if n > 0 && s[n-1] == '=' {
		eqCount = 1
		if n > 1 && s[n-2] == '=' {
			eqCount = 2
		}
	}

	// Validate characters excluding padding
	limit := n - eqCount
	for i := 0; i < limit; i++ {
		c := s[i]
		// Fast ASCII range check for performance optimization
		if c > 127 {
			return false
		}
		if base64Table[c] == base64Invalid {
			return false
		}
	}

	return true
}

// Claims defines claims interface, all custom claims must implement this interface
type Claims interface {
	Valid() error
}

// RegisteredClaims contains standard claim fields
type RegisteredClaims struct {
	ExpiresAt     *time.Time `json:"exp,omitempty"` // Expiration time
	NotBefore     *time.Time `json:"nbf,omitempty"` // Not‑before valid time
	IssuedAt      *time.Time `json:"iat,omitempty"` // Issued‑at timestamp
	ID            string     `json:"jti,omitempty"` // Token unique ID
	Ttl           uint32     `json:"ttl,omitempty"` // Valid duration in seconds
	IssueCount    uint32     `json:"isc,omitempty"` // Cumulative refresh count
	MaxIssueCount uint32     `json:"mic,omitempty"` // Maximum allowed refresh times
}

// Valid validates standard registered claims
func (c *RegisteredClaims) Valid() error {
	now := time.Now().UTC()

	// Validate token ID
	if c.ID == "" {
		return ErrTokenInvalidId
	}

	// Validate refresh count
	if c.IssueCount > c.MaxIssueCount {
		return ErrTokenTooManyRenewals
	}

	// Validate expiration time
	if c.ExpiresAt != nil && !c.ExpiresAt.IsZero() {
		expTime := *c.ExpiresAt
		if expTime.Before(now) {
			return ErrTokenExpired
		}
	}

	// Validate not‑before time
	if c.NotBefore != nil && !c.NotBefore.IsZero() {
		nbfTime := *c.NotBefore
		if nbfTime.After(now) {
			return ErrTokenNotValidYet
		}
	}

	// Validate issued‑at time
	if c.IssuedAt != nil && !c.IssuedAt.IsZero() {
		iatTime := *c.IssuedAt
		if iatTime.After(now) {
			return ErrTokenUsedBeforeIssued
		}
	}

	// Validate TTL based on issued‑at time
	if c.IssuedAt != nil && c.Ttl > 0 {
		expTime := c.IssuedAt.Add(time.Duration(c.Ttl) * time.Second)
		if now.After(expTime) {
			return ErrTokenExpired
		}
	}

	return nil
}

// SigningMethod defines signing algorithm interface
type SigningMethod interface {
	Alg() string
	Kid() uint32
	Sign(payload []byte) ([]byte, error)
	Verify(signedData []byte) ([]byte, error)
}

func (s *SigningMethodBinary) Kid() uint32 {
	return s.kid
}

// SigningMethodBinary binary signing implementation
type SigningMethodBinary struct {
	aesKey  []byte
	hmacKey []byte
	kid     uint32 // Key ID for key rotation support
}

// NewSigningMethodBinary creates new binary signing method instance
func NewSigningMethodBinary(aesKey, hmacKey []byte) (*SigningMethodBinary, error) {
	if len(aesKey) != AESKeyLen {
		return nil, fmt.Errorf("%w: must be %d bytes (AES‑256), got %d", ErrAESKeyLength, AESKeyLen, len(aesKey))
	}
	if len(hmacKey) < MinHMACKeyLen {
		return nil, fmt.Errorf("%w: too short (min %d bytes), got %d", ErrHMACKeyLength, MinHMACKeyLen, len(hmacKey))
	}
	return &SigningMethodBinary{
		aesKey:  aesKey,
		hmacKey: hmacKey,
		kid:     GenKid(),
	}, nil
}

// NewSigningMethodBinaryWithKID creates binary signing method with specified Key ID
func NewSigningMethodBinaryWithKID(aesKey, hmacKey []byte, kid uint32) (*SigningMethodBinary, error) {
	method, err := NewSigningMethodBinary(aesKey, hmacKey)
	if err != nil {
		return nil, err
	}
	method.kid = kid
	return method, nil
}

// Alg returns algorithm identifier string
func (s *SigningMethodBinary) Alg() string {
	if s.kid != 0 {
		return fmt.Sprintf("BINARY‑HS256‑KID‑%d", s.kid)
	}
	return "BINARY‑HS256"
}

// Sign signs payload and returns raw binary token
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

	// Raw token length must fit inside 2‑byte unsigned integer
	if len(payload) > 0xFFFF {
		return nil, ErrTokenTooLarge
	}

	block, err := aes.NewCipher(s.aesKey)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrCipherCreation, err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrGCMCreation, err)
	}

	// 4‑byte random prefix
	prefixRand := make([]byte, 4)
	if _, err := io.ReadFull(rand.Reader, prefixRand); err != nil {
		return nil, fmt.Errorf("rand prefix failed: %w", err)
	}

	// GCM nonce with 12 bytes
	nonce := make([]byte, GCMNonceLen)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("rand nonce failed: %w", err)
	}

	plainHeader := make([]byte, HeaderPlainLen)

	// 0‑3: kid stored as big‑endian uint32
	binary.BigEndian.PutUint32(plainHeader[0:4], s.kid)

	// 4‑7: 4‑byte random prefix
	copy(plainHeader[4:8], prefixRand)

	// 8: protocol version 0x01
	plainHeader[8] = 0x01

	// [9:13] reserved bytes, keep zero value

	// 13: flags byte
	plainHeader[13] = 0x01

	// 14‑15: raw payload length before encryption
	binary.BigEndian.PutUint16(plainHeader[14:16], uint16(len(payload)))

	// AAD uses full 16‑byte plain header including raw payload length
	aad := plainHeader[:16]

	// AES‑GCM encrypt payload, fullCipherText = ciphertext + authentication tag
	fullCipherText := gcm.Seal(nil, nonce, payload, aad)

	// signedBody = plainHeader(16) + fullCipherText + nonce(12)
	signedBody := make([]byte, 0, HeaderPlainLen+len(fullCipherText)+GCMNonceLen)
	signedBody = append(signedBody, plainHeader...)
	signedBody = append(signedBody, fullCipherText...)
	signedBody = append(signedBody, nonce...)

	// Compute HMAC‑SHA256 signature over signedBody
	mac := hmac.New(sha256.New, s.hmacKey)
	if _, err = mac.Write(signedBody); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrHMACCalculation, err)
	}
	signature := mac.Sum(nil)

	// Final binary token = signedBody concatenated with HMAC signature
	finalToken := append(append([]byte(nil), signedBody...), signature...)
	return finalToken, nil
}

// Verify validates signature and returns decrypted original payload
func (s *SigningMethodBinary) Verify(signedData []byte) ([]byte, error) {
	const minFullCipher = 16 // Minimum GCM ciphertext length (tag only)

	if len(signedData) > MaxTokenLen {
		return nil, ErrTokenTooLarge
	}
	// Minimum total length: 16 header + min cipher 16 + nonce12 + hmac32
	minTotal := HeaderPlainLen + minFullCipher + GCMNonceLen + HMACSigLen
	if len(signedData) < minTotal {
		return nil, ErrTokenTooShort
	}

	innerPayload := signedData[:len(signedData)-HMACSigLen]
	receivedSig := signedData[len(signedData)-HMACSigLen:]

	// Step1: verify HMAC signature
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

	// Parse plain header fields
	kid := binary.BigEndian.Uint32(plainHeader[0:4])
	ver := plainHeader[8]
	reserved := plainHeader[9:13] // 4‑byte reserved field
	flags := plainHeader[13]
	rawTokenLen := int(binary.BigEndian.Uint16(plainHeader[14:16])) // original payload length

	// Validate protocol version, reserved bytes and flags
	if ver != 0x01 {
		return nil, ErrTokenDecryptionFailed
	}
	if !bytes.Equal(reserved, []byte{0, 0, 0, 0}) {
		return nil, ErrTokenDecryptionFailed
	}
	if flags != 0x01 {
		return nil, ErrTokenDecryptionFailed
	}

	// Derive cipher length: ciphertext+tag = raw payload length + 16‑byte GCM tag
	fullCipherLen := rawTokenLen + minFullCipher

	// Safe boundary check for cipher length
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

	// Check whether kid matches current signing method instance
	if kid != s.kid {
		return nil, ErrTokenKidMismatch
	}

	// AAD must be exactly same 16‑byte plain header used during signing
	aad := plainHeader[:16]

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

// Token represents a parsed token object
type Token struct {
	Raw       string        // Original base64‑encoded token string
	Claims    Claims        // Parsed claim instance
	Method    SigningMethod // Attached signing algorithm
	Kid       uint32        // Key ID extracted from token
	Signature []byte        // Raw signature bytes
}

// NewToken creates a new Token instance with given claims and signing method
func NewToken(claims Claims, method SigningMethod) *Token {
	return &Token{
		Claims: claims,
		Method: method,
		Kid:    method.Kid(),
	}
}

// SignedString generates complete signed token encoded as standard Base64 string
func (t *Token) SignedString() (string, error) {
	// Marshal claims structure into JSON bytes
	claimsBytes, err := json.Marshal(t.Claims)
	if err != nil {
		return "", fmt.Errorf("%w: %w", ErrClaimsMarshaling, err)
	}

	// Execute signing process
	signedBytes, err := t.Method.Sign(claimsBytes)
	if err != nil {
		return "", fmt.Errorf("signing failed: %w", err)
	}

	// Encode binary token with standard Base64
	encoded := base64.StdEncoding.EncodeToString(signedBytes)

	// Validate generated base64 string with high‑performance lookup table
	if !IsValidBase64(encoded) {
		return "", ErrInvalidBase64
	}

	t.Raw = encoded
	return encoded, nil
}

// Refreshable defines interface for refresh‑capable claims
type Refreshable interface {
	Refresh(tid string) error
}

// Refresh RegisteredClaims implements Refreshable interface
func (c *RegisteredClaims) Refresh(tid string) error {

	// 1. Check if refresh feature is enabled
	if c.MaxIssueCount == 0 {
		return ErrTokenRefreshNotAllowed
	}

	// 2. Check whether refresh count reaches upper limit
	if c.IssueCount >= c.MaxIssueCount {
		return ErrTokenTooManyRenewals
	}

	// 3. Forbid refresh for already expired token
	now := time.Now().UTC()
	if c.ExpiresAt != nil && !c.ExpiresAt.IsZero() && c.ExpiresAt.Before(now) {
		return ErrTokenRefreshExpired
	}

	// 4. Forbid refresh before token becomes valid
	if c.NotBefore != nil && !c.NotBefore.IsZero() && c.NotBefore.After(now) {
		return ErrTokenRefreshNotYetValid
	}

	// 5. Prevent uint32 integer overflow on issue count increment
	if c.IssueCount == ^uint32(0) {
		return ErrTokenRefreshOverflow
	}

	// 6. Validate TTL value for refresh operation
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

// Refresh performs token refresh on Token wrapper
func (t *Token) Refresh(tid string) error {
	if refreshable, ok := t.Claims.(Refreshable); ok {
		return refreshable.Refresh(tid)
	}
	return errors.New("claims does not implement Refreshable interface")
}

// Parse parses and validates token string with fixed signing method
func Parse(tokenStr string, claims Claims, method SigningMethod) (*Token, error) {
	// Pre‑validate input Base64 format
	if !IsValidBase64(tokenStr) {
		return nil, ErrInvalidBase64
	}

	// Base64 decode to raw binary token
	tokenBytes, err := base64.StdEncoding.DecodeString(tokenStr)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrBase64Decoding, err)
	}

	// Verify signature and get decrypted payload
	decryptedBytes, err := method.Verify(tokenBytes)
	if err != nil {
		return nil, fmt.Errorf("signature verification failed: %w", err)
	}

	// Unmarshal JSON payload into target claims struct
	if err := json.Unmarshal(decryptedBytes, claims); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrClaimsUnmarshalling, err)
	}

	// Run claims business validation logic
	if err := claims.Valid(); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrTokenInvalidClaims, err)
	}

	// Construct final token object
	token := &Token{
		Raw:    tokenStr,
		Claims: claims,
		Method: method,
		Kid:    binary.BigEndian.Uint32(tokenBytes[0:4]),
	}

	return token, nil
}

// ParseWithClaims parses token and selects signing method dynamically via keyFunc callback for key‑rotation
func ParseWithClaims(tokenStr string, claims Claims, keyFunc func(*Token) (SigningMethod, error)) (*Token, error) {
	// Pre‑validate input Base64 string format
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
	kid := binary.BigEndian.Uint32(tokenBytes[0:4])

	// Build temporary token container only carrying kid for keyFunc
	token := &Token{
		Raw:    tokenStr,
		Claims: claims,
		Kid:    kid,
	}

	// Invoke callback to resolve corresponding signing method
	method, err := keyFunc(token)
	if err != nil {
		return nil, err
	}
	token.Method = method

	// Now perform full signature cryptographic verification
	decryptedBytes, err := method.Verify(tokenBytes)
	if err != nil {
		return nil, fmt.Errorf("signature verification failed: %w", err)
	}

	// Deserialize JSON payload into claims
	if err := json.Unmarshal(decryptedBytes, claims); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrClaimsUnmarshalling, err)
	}

	// Run claims logical validation
	if err := claims.Valid(); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrTokenInvalidClaims, err)
	}

	token.Claims = claims
	token.Method = method

	return token, nil
}

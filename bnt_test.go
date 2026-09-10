package bnt

import (
	"encoding/base64"
	"errors"
	"testing"
	"time"
)

// Fixed test keys, used only for unit tests; hardcoding keys in production is forbidden.
var (
	testAESKey         = []byte("0123456789abcdef0123456789abcdef") // 32-byte AES-256
	testHMACKey        = []byte("my-test-hmac-key-12345678")        // 24-byte HMAC key
	testKID     uint32 = 1001
)

// ptrTime is a helper function that returns a time pointer.
func ptrTime(t time.Time) *time.Time {
	return &t
}

// mustNewMethod creates a signing method; on failure it terminates the test immediately.
func mustNewMethod(t *testing.T) *SigningMethodBinary {
	t.Helper()
	m, err := NewSigningMethodBinaryWithKID(testAESKey, testHMACKey, testKID)
	if err != nil {
		t.Fatalf("NewSigningMethodBinaryWithKID failed: %v", err)
	}
	return m
}

// TestSignAndVerify covers the full flow of normal signing, token generation, parsing, and decryption.
func TestSignAndVerify(t *testing.T) {
	method := mustNewMethod(t)

	now := time.Now().UTC()
	claims := &RegisteredClaims{
		ID:        "jti-001",
		IssuedAt:  &now,
		NotBefore: &now,
		ExpiresAt: ptrTime(now.Add(1 * time.Hour)),
		Ttl:       3600,
	}

	tok := NewToken(claims, method)
	tokenStr, err := tok.SignedString()
	if err != nil {
		t.Fatalf("SignedString failed: %v", err)
	}
	if tokenStr == "" {
		t.Error("token string should not be empty")
	}

	outClaims := &RegisteredClaims{}
	parsed, err := Parse(tokenStr, outClaims, method)
	if err != nil {
		t.Fatalf("Parse failed: %v", err)
	}

	if parsed.Kid != testKID {
		t.Errorf("kid mismatch, want %d got %d", testKID, parsed.Kid)
	}
	if outClaims.ID != "jti-001" {
		t.Errorf("jti mismatch, want jti-001 got %s", outClaims.ID)
	}
}

// TestNewSigningMethodBinary_KeyLenCheck checks key length validation.
func TestNewSigningMethodBinary_KeyLenCheck(t *testing.T) {
	// Wrong AES key length.
	_, err := NewSigningMethodBinary([]byte("shortkey"), testHMACKey)
	if err == nil {
		t.Error("expected ErrAESKeyLength, got nil")
	}

	// HMAC key too short.
	shortHmac := []byte("1234567")
	_, err = NewSigningMethodBinary(testAESKey, shortHmac)
	if err == nil {
		t.Error("expected ErrHMACKeyLength, got nil")
	}
}

// TestIsValidBase64 tests the base64 validation function.
func TestIsValidBase64(t *testing.T) {
	cases := []struct {
		name string
		s    string
		want bool
	}{
		{"empty string", "", false},
		{"valid base64", "SGVsbG8gV29ybGQ=", true},
		{"invalid char $", "SGVsbG8g$$==", false},
		{"3 padding ==", "YQ===", false}, // Three equals signs is invalid.
		{"non 4-aligned len", "YQ=", false},
		{"utf8 char", "中文==", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := IsValidBase64(tc.s)
			if got != tc.want {
				t.Errorf("IsValidBase64(%q) = %v want %v", tc.s, got, tc.want)
			}
		})
	}
}

// TestTokenTamper tampers with the token and verifies that the HMAC signature check fails.
func TestTokenTamper(t *testing.T) {
	method := mustNewMethod(t)
	now := time.Now().UTC()
	claims := &RegisteredClaims{
		ID:        "jti-tamper",
		IssuedAt:  &now,
		ExpiresAt: ptrTime(now.Add(1 * time.Hour)),
		Ttl:       3600,
	}
	tok := NewToken(claims, method)
	tokenStr, err := tok.SignedString()
	if err != nil {
		t.Fatal(err)
	}

	// Tamper with one character of the base64 string.
	b := []byte(tokenStr)
	if len(b) > 0 {
		b[0] = 'X'
	}
	tampered := string(b)

	outClaims := &RegisteredClaims{}
	_, err = Parse(tampered, outClaims, method)
	if err == nil {
		t.Error("tampered token should return error")
	}
}

// TestTokenExpired validates an expired token.
func TestTokenExpired(t *testing.T) {
	method := mustNewMethod(t)
	now := time.Now().UTC()
	expTime := now.Add(-1 * time.Hour) // Expired one hour ago.
	claims := &RegisteredClaims{
		ID:        "jti-expire",
		IssuedAt:  ptrTime(now.Add(-2 * time.Hour)),
		ExpiresAt: &expTime,
		Ttl:       3600,
	}
	tok := NewToken(claims, method)
	tokenStr, err := tok.SignedString()
	if err != nil {
		t.Fatal(err)
	}

	outClaims := &RegisteredClaims{}
	_, err = Parse(tokenStr, outClaims, method)
	if err == nil {
		t.Error("expired token should return ErrTokenExpired")
	}
}

// TestTokenNotYetValid tests the case where nbf has not yet been reached.
func TestTokenNotYetValid(t *testing.T) {
	method := mustNewMethod(t)
	now := time.Now().UTC()
	nbf := now.Add(1 * time.Hour) // Becomes valid only one hour later.
	claims := &RegisteredClaims{
		ID:        "jti-nbf",
		IssuedAt:  &now,
		NotBefore: &nbf,
		ExpiresAt: ptrTime(now.Add(2 * time.Hour)),
		Ttl:       3600,
	}
	tok := NewToken(claims, method)
	tokenStr, err := tok.SignedString()
	if err != nil {
		t.Fatal(err)
	}

	outClaims := &RegisteredClaims{}
	_, err = Parse(tokenStr, outClaims, method)
	if err == nil {
		t.Error("token with future nbf should error")
	}
}

// TestTokenRefresh tests the Refresh (renewal) logic.
func TestTokenRefresh(t *testing.T) {
	method := mustNewMethod(t)
	now := time.Now().UTC()
	claims := &RegisteredClaims{
		ID:            "jti-old",
		IssuedAt:      &now,
		NotBefore:     &now,
		ExpiresAt:     ptrTime(now.Add(2 * time.Hour)),
		Ttl:           3600,
		IssueCount:    0,
		MaxIssueCount: 5,
	}
	tok := NewToken(claims, method)

	newJti := "jti-new-002"
	err := tok.Refresh(newJti)
	if err != nil {
		t.Fatalf("refresh failed: %v", err)
	}

	c, ok := tok.Claims.(*RegisteredClaims)
	if !ok {
		t.Fatal("claims type assert fail")
	}
	if c.ID != newJti {
		t.Errorf("refresh jti wrong, want %s got %s", newJti, c.ID)
	}
	if c.IssueCount != 1 {
		t.Errorf("issueCount want 1 got %d", c.IssueCount)
	}

	// Renewal reaches the limit.
	c.IssueCount = 5
	err = tok.Refresh("jti-over")
	if err == nil {
		t.Error("max renewals should return error")
	}
}

// TestParseWithClaims tests parsing with a keyFunc (key rotation scenario).
func TestParseWithClaims(t *testing.T) {
	method := mustNewMethod(t)
	now := time.Now().UTC()
	claims := &RegisteredClaims{
		ID:        "jti-keyfunc",
		IssuedAt:  &now,
		ExpiresAt: ptrTime(now.Add(1 * time.Hour)),
		Ttl:       3600,
	}
	tok := NewToken(claims, method)
	tokenStr, err := tok.SignedString()
	if err != nil {
		t.Fatal(err)
	}

	outClaims := &RegisteredClaims{}
	keyFunc := func(tk *Token) (SigningMethod, error) {
		if tk.Kid == testKID {
			return method, nil
		}
		return nil, ErrTokenSignatureInvalid
	}

	parsed, err := ParseWithClaims(tokenStr, outClaims, keyFunc)
	if err != nil {
		t.Fatalf("ParseWithClaims failed: %v", err)
	}
	if parsed.Kid != testKID {
		t.Errorf("kid mismatch")
	}
}

// TestSignWrongKid verifies that Verify errors when the kid does not match.
func TestSignWrongKid(t *testing.T) {
	m1, err := NewSigningMethodBinaryWithKID(testAESKey, testHMACKey, 1001)
	if err != nil {
		t.Fatal(err)
	}
	m2, err := NewSigningMethodBinaryWithKID(testAESKey, testHMACKey, 9999)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	claims := &RegisteredClaims{
		ID:        "jti-kidtest",
		IssuedAt:  &now,
		ExpiresAt: ptrTime(now.Add(1 * time.Hour)),
		Ttl:       3600,
	}
	tok := NewToken(claims, m1)
	tokenStr, err := tok.SignedString()
	if err != nil {
		t.Fatal(err)
	}
	outClaims := &RegisteredClaims{}
	_, err = Parse(tokenStr, outClaims, m2)
	if err == nil {
		t.Error("different kid should return ErrTokenKidMismatch")
	}
	if !errors.Is(err, ErrTokenKidMismatch) {
		t.Errorf("want root ErrTokenKidMismatch, got %v", err)
	}
}

// TestVersionFlagCheck checks invalid version numbers and flags.
func TestVersionFlagCheck(t *testing.T) {
	method := mustNewMethod(t)
	now := time.Now().UTC()
	claims := &RegisteredClaims{
		ID:        "jti-badver",
		IssuedAt:  &now,
		ExpiresAt: ptrTime(now.Add(1 * time.Hour)),
		Ttl:       3600,
	}
	tok := NewToken(claims, method)
	tokenStr, err := tok.SignedString()
	if err != nil {
		t.Fatal(err)
	}

	// Decode and manually modify the version byte.
	tokenBytes, err := base64.StdEncoding.DecodeString(tokenStr)
	if err != nil {
		t.Fatal(err)
	}
	// Change the version number to 0x02.
	tokenBytes[8] = 0x02
	alteredB64 := base64.StdEncoding.EncodeToString(tokenBytes)

	outClaims := &RegisteredClaims{}
	_, err = Parse(alteredB64, outClaims, method)
	if err == nil {
		t.Error("invalid version should return decryption failed error")
	}
}

func TestBadReservedHeader(t *testing.T) {
	method := mustNewMethod(t)
	now := time.Now().UTC()
	claims := &RegisteredClaims{
		ID:        "jti-bad-reserved",
		IssuedAt:  &now,
		ExpiresAt: ptrTime(now.Add(1 * time.Hour)),
		Ttl:       3600,
	}
	tok := NewToken(claims, method)
	tokenStr, err := tok.SignedString()
	if err != nil {
		t.Fatal(err)
	}

	tokenBytes, err := base64.StdEncoding.DecodeString(tokenStr)
	if err != nil {
		t.Fatal(err)
	}
	// Modify the reserved byte: set position 9 to 1.
	tokenBytes[9] = 0x01
	alteredB64 := base64.StdEncoding.EncodeToString(tokenBytes)

	outClaims := &RegisteredClaims{}
	_, err = Parse(alteredB64, outClaims, method)
	if err == nil {
		t.Error("non-zero reserved bytes should fail decryption")
	}
}

func TestBadFlags(t *testing.T) {
	method := mustNewMethod(t)
	now := time.Now().UTC()
	claims := &RegisteredClaims{
		ID:        "jti-bad-flags",
		IssuedAt:  &now,
		ExpiresAt: ptrTime(now.Add(1 * time.Hour)),
		Ttl:       3600,
	}
	tok := NewToken(claims, method)
	tokenStr, err := tok.SignedString()
	if err != nil {
		t.Fatal(err)
	}

	tokenBytes, err := base64.StdEncoding.DecodeString(tokenStr)
	if err != nil {
		t.Fatal(err)
	}
	// Change flags from 0x01 to 0x02.
	tokenBytes[13] = 0x02
	alteredB64 := base64.StdEncoding.EncodeToString(tokenBytes)

	outClaims := &RegisteredClaims{}
	_, err = Parse(alteredB64, outClaims, method)
	if err == nil {
		t.Error("invalid flags should return decryption failed error")
	}
}

func TestWrongHmacKey(t *testing.T) {
	// Same AES and same KID, but a different HMAC key.
	hmacKeyWrong := []byte("wrong-hmac-key-1234567890123456")
	mSign, err := NewSigningMethodBinaryWithKID(testAESKey, testHMACKey, testKID)
	if err != nil {
		t.Fatal(err)
	}
	mVerifyBadHmac, err := NewSigningMethodBinaryWithKID(testAESKey, hmacKeyWrong, testKID)
	if err != nil {
		t.Fatal(err)
	}

	now := time.Now().UTC()
	claims := &RegisteredClaims{
		ID:        "jti-wronghmac",
		IssuedAt:  &now,
		ExpiresAt: ptrTime(now.Add(1 * time.Hour)),
		Ttl:       3600,
	}
	tok := NewToken(claims, mSign)
	tokenStr, err := tok.SignedString()
	if err != nil {
		t.Fatal(err)
	}

	outClaims := &RegisteredClaims{}
	_, err = Parse(tokenStr, outClaims, mVerifyBadHmac)
	if err == nil {
		t.Error("using wrong HMAC key should fail signature verify")
	}
}

func TestClaimEmptyJti(t *testing.T) {
	method := mustNewMethod(t)
	now := time.Now().UTC()
	// ID is empty.
	claims := &RegisteredClaims{
		ID:        "",
		IssuedAt:  &now,
		ExpiresAt: ptrTime(now.Add(1 * time.Hour)),
		Ttl:       3600,
	}
	tok := NewToken(claims, method)
	tokenStr, err := tok.SignedString()
	if err != nil {
		t.Fatal(err)
	}

	outClaims := &RegisteredClaims{}
	_, err = Parse(tokenStr, outClaims, method)
	if err == nil {
		t.Error("empty jti should return ErrTokenInvalidId")
	}
}

func TestIatFuture(t *testing.T) {
	method := mustNewMethod(t)
	now := time.Now().UTC()
	futureIat := now.Add(2 * time.Hour)
	claims := &RegisteredClaims{
		ID:        "jti-future-iat",
		IssuedAt:  &futureIat,
		ExpiresAt: ptrTime(now.Add(3 * time.Hour)),
		Ttl:       3600,
	}
	tok := NewToken(claims, method)
	tokenStr, err := tok.SignedString()
	if err != nil {
		t.Fatal(err)
	}

	outClaims := &RegisteredClaims{}
	_, err = Parse(tokenStr, outClaims, method)
	if err == nil {
		t.Error("iat in future should return ErrTokenUsedBeforeIssued")
	}
}

func BenchmarkSign(b *testing.B) {
	method, err := NewSigningMethodBinaryWithKID(testAESKey, testHMACKey, testKID)
	if err != nil {
		b.Fatal(err)
	}
	now := time.Now().UTC()
	claims := &RegisteredClaims{
		ID:        "bench-jti-001",
		IssuedAt:  &now,
		ExpiresAt: ptrTime(now.Add(1 * time.Hour)),
		Ttl:       3600,
	}
	tok := NewToken(claims, method)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := tok.SignedString()
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkVerify(b *testing.B) {
	method, err := NewSigningMethodBinaryWithKID(testAESKey, testHMACKey, testKID)
	if err != nil {
		b.Fatal(err)
	}
	now := time.Now().UTC()
	claims := &RegisteredClaims{
		ID:        "bench-jti-001",
		IssuedAt:  &now,
		ExpiresAt: ptrTime(now.Add(1 * time.Hour)),
		Ttl:       3600,
	}
	tok := NewToken(claims, method)
	tokenStr, err := tok.SignedString()
	if err != nil {
		b.Fatal(err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		out := &RegisteredClaims{}
		_, err := Parse(tokenStr, out, method)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkToken_SignedString(b *testing.B) {
	aesKey := []byte("0123456789abcdef0123456789abcdef")
	hmacKey := []byte("hmac-key-for-bench-000000000000")

	method, err := NewSigningMethodBinaryWithKID(aesKey, hmacKey, 1001)
	if err != nil {
		b.Fatal(err)
	}

	now := time.Now().UTC()
	claims := &RegisteredClaims{
		ID:        "bench‑jti‑000001",
		IssuedAt:  ptrTime(now),
		ExpiresAt: ptrTime(now.Add(2 * time.Hour)),
		Ttl:       7200,
	}

	b.ResetTimer() // Skip the initialization time.

	for i := 0; i < b.N; i++ {
		tok := NewToken(claims, method)
		_, err := tok.SignedString()
		if err != nil {
			b.Fatalf("SignedString failed: %v", err)
		}
	}
}

// Full end-to-end parsing: Parse, including base64 decoding, decryption, and signature verification.
func BenchmarkParse_FullEndToEnd(b *testing.B) {
	aesKey := []byte("0123456789abcdef0123456789abcdef")
	hmacKey := []byte("hmac-key-for-bench-000000000000")

	method, err := NewSigningMethodBinaryWithKID(aesKey, hmacKey, 1001)
	if err != nil {
		b.Fatal(err)
	}

	now := time.Now().UTC()
	claims := &RegisteredClaims{
		ID:        "bench‑jti‑000001",
		IssuedAt:  ptrTime(now),
		ExpiresAt: ptrTime(now.Add(2 * time.Hour)),
		Ttl:       7200,
	}
	tok := NewToken(claims, method)
	tokenStr, err := tok.SignedString()
	if err != nil {
		b.Fatal(err)
	}

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		out := &RegisteredClaims{}
		_, err := Parse(tokenStr, out, method)
		if err != nil {
			b.Fatalf("parse failed: %v", err)
		}
	}
}

// go test -v ./...
// go test -bench=. -benchmem

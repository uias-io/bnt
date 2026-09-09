package bnt

import (
	"crypto/rand"
	"encoding/base64"
	"testing"
	"time"
)

type UserClaims struct {
	UserID   string `json:"user_id"`
	Username string `json:"username"`
	RegisteredClaims
}

func (uc *UserClaims) Valid() error {
	if err := uc.RegisteredClaims.Valid(); err != nil {
		return err
	}
	if uc.UserID == "" {
		return ErrTokenRequiredClaimMissing
	}
	if uc.Username == "" {
		return ErrTokenRequiredClaimMissing
	}
	return nil
}

func generateTestKeys(t *testing.T) (aesKey, hmacKey []byte) {
	t.Helper()
	aesKey = make([]byte, AESKeyLen)
	if _, err := rand.Read(aesKey); err != nil {
		t.Fatalf("generate aes key failed: %v", err)
	}
	hmacKey = make([]byte, 32)
	if _, err := rand.Read(hmacKey); err != nil {
		t.Fatalf("generate hmac key failed: %v", err)
	}
	return aesKey, hmacKey
}

func createTestClaims() *UserClaims {
	now := time.Now().UTC()
	exp := now.Add(1 * time.Hour)
	nbf := now.Add(-5 * time.Minute)
	return &UserClaims{
		UserID:   "test_user_123",
		Username: "test_user",
		RegisteredClaims: RegisteredClaims{
			ID:        "test_jti_456",
			ExpiresAt: &exp,
			IssuedAt:  &now,
			NotBefore: &nbf,
		},
	}
}

// unwrapRootErr 循环解包拿到最内层原始error
func unwrapRootErr(err error) error {
	for err != nil {
		u, ok := err.(interface{ Unwrap() error })
		if !ok {
			break
		}
		inner := u.Unwrap()
		if inner == nil {
			break
		}
		err = inner
	}
	return err
}

func TestTokenGenerationAndVerification(t *testing.T) {
	aesKey, hmacKey := generateTestKeys(t)
	method, err := NewSigningMethodBinary(aesKey, hmacKey)
	if err != nil {
		t.Fatalf("NewSigningMethodBinary err: %v", err)
	}

	claims := createTestClaims()
	tok := NewToken(claims, method)

	tokenStr, err := tok.SignedString()
	if err != nil {
		t.Fatalf("SignedString failed: %v", err)
	}
	if tokenStr == "" {
		t.Error("token string is empty")
	}

	parsedClaims := &UserClaims{}
	parsedTok, err := Parse(tokenStr, parsedClaims, method)
	if err != nil {
		t.Fatalf("Parse failed: %v", err)
	}

	if parsedClaims.UserID != claims.UserID {
		t.Errorf("UserID want %s got %s", claims.UserID, parsedClaims.UserID)
	}
	if parsedClaims.Username != claims.Username {
		t.Errorf("Username want %s got %s", claims.Username, parsedClaims.Username)
	}
	if parsedClaims.ID != claims.ID {
		t.Errorf("ID want %s got %s", claims.ID, parsedClaims.ID)
	}

	if !parsedClaims.ExpiresAt.Equal(*claims.ExpiresAt) {
		t.Errorf("ExpiresAt mismatch want %v got %v", *claims.ExpiresAt, *parsedClaims.ExpiresAt)
	}
	if !parsedClaims.IssuedAt.Equal(*claims.IssuedAt) {
		t.Errorf("IssuedAt mismatch want %v got %v", *claims.IssuedAt, *parsedClaims.IssuedAt)
	}
	if !parsedClaims.NotBefore.Equal(*claims.NotBefore) {
		t.Errorf("NotBefore mismatch want %v got %v", *claims.NotBefore, *parsedClaims.NotBefore)
	}

	if err = parsedTok.Claims.Valid(); err != nil {
		t.Errorf("claims.Valid() return err: %v", err)
	}
}

func TestExpiredToken(t *testing.T) {
	aesKey, hmacKey := generateTestKeys(t)
	method, _ := NewSigningMethodBinary(aesKey, hmacKey)

	now := time.Now().UTC()
	exp := now.Add(-1 * time.Hour)
	claims := &UserClaims{
		UserID:   "exp_user01",
		Username: "expired",
		RegisteredClaims: RegisteredClaims{
			ID:        "jti_exp01",
			ExpiresAt: &exp,
			IssuedAt:  &now,
		},
	}

	tok := NewToken(claims, method)
	tokenStr, err := tok.SignedString()
	if err != nil {
		t.Fatal(err)
	}

	parsed := &UserClaims{}
	_, err = Parse(tokenStr, parsed, method)
	if err == nil {
		t.Fatal("expect expired error, got nil")
	}
	rootErr := unwrapRootErr(err)
	t.Logf("outer err=%v, root err=%v", err, rootErr)

	// 兼容两种情况：源码返回常量error / 返回文本error字符串
	if rootErr.Error() != "token is expired" {
		t.Errorf("inner error expect 'token is expired', got '%v'", rootErr)
	}
}

func TestNotYetValidToken(t *testing.T) {
	aesKey, hmacKey := generateTestKeys(t)
	method, _ := NewSigningMethodBinary(aesKey, hmacKey)

	now := time.Now().UTC()
	nbf := now.Add(1 * time.Hour)
	claims := &UserClaims{
		UserID:   "future01",
		Username: "future",
		RegisteredClaims: RegisteredClaims{
			ID:        "jti_f01",
			NotBefore: &nbf,
			IssuedAt:  &now,
		},
	}

	tok := NewToken(claims, method)
	tokenStr, _ := tok.SignedString()

	parsed := &UserClaims{}
	_, err := Parse(tokenStr, parsed, method)
	if err == nil {
		t.Fatal("expect not‑valid‑yet error, got nil")
	}
	rootErr := unwrapRootErr(err)
	t.Logf("outer err=%v, root err=%v", err, rootErr)

	if rootErr.Error() != "token is not valid yet" {
		t.Errorf("inner error expect 'token is not valid yet', got '%v'", rootErr)
	}
}

func TestTamperedToken(t *testing.T) {
	aesKey, hmacKey := generateTestKeys(t)
	method, _ := NewSigningMethodBinary(aesKey, hmacKey)

	claims := createTestClaims()
	tok := NewToken(claims, method)
	tokenStr, _ := tok.SignedString()

	if len(tokenStr) < 6 {
		t.Fatal("token too short for tamper test")
	}
	tampered := tokenStr[:len(tokenStr)-6] + "xxxxxx"

	parsed := &UserClaims{}
	_, err := Parse(tampered, parsed, method)
	if err == nil {
		t.Error("tampered token should return error, got nil")
	}
}

func TestWrongKeyVerification(t *testing.T) {
	aesKey, hmacKey := generateTestKeys(t)
	methodOK, _ := NewSigningMethodBinary(aesKey, hmacKey)

	claims := createTestClaims()
	tok := NewToken(claims, methodOK)
	tokenStr, _ := tok.SignedString()

	wrongAes, wrongHmac := generateTestKeys(t)
	methodBad, _ := NewSigningMethodBinary(wrongAes, wrongHmac)

	parsed := &UserClaims{}
	_, err := Parse(tokenStr, parsed, methodBad)
	if err == nil {
		t.Error("wrong key should failed, got nil")
	}
}

func TestInvalidBase64Token(t *testing.T) {
	aesKey, hmacKey := generateTestKeys(t)
	method, _ := NewSigningMethodBinary(aesKey, hmacKey)

	badStr := "hello##$%^notbase64!!"
	parsed := &UserClaims{}
	_, err := Parse(badStr, parsed, method)
	if err == nil {
		t.Error("invalid base64 should error")
	}
}

func TestTooShortToken(t *testing.T) {
	aesKey, hmacKey := generateTestKeys(t)
	method, _ := NewSigningMethodBinary(aesKey, hmacKey)

	shortBin := make([]byte, 4)
	shortToken := base64.StdEncoding.EncodeToString(shortBin)

	parsed := &UserClaims{}
	_, err := Parse(shortToken, parsed, method)
	if err == nil {
		t.Fatal("short binary token expect error")
	}
}

func TestCustomClaimsValidation(t *testing.T) {
	aesKey, hmacKey := generateTestKeys(t)
	method, _ := NewSigningMethodBinary(aesKey, hmacKey)

	now := time.Now().UTC()
	exp := now.Add(time.Hour)

	claimsNoUID := &UserClaims{
		Username: "no_uid_user",
		RegisteredClaims: RegisteredClaims{
			ID:        "jti_nouid",
			ExpiresAt: &exp,
			IssuedAt:  &now,
		},
	}
	tok1 := NewToken(claimsNoUID, method)
	tokenStr1, err := tok1.SignedString()
	if err != nil {
		t.Fatal(err)
	}

	p1 := &UserClaims{}
	_, err = Parse(tokenStr1, p1, method)
	if err == nil {
		t.Error("missing UserID should trigger error")
	}
	rootErr := unwrapRootErr(err)
	t.Logf("missing userid outer=%v root=%v", err, rootErr)
	if rootErr.Error() != "token is missing required claim" {
		t.Errorf("want 'token is missing required claim', got '%v'", rootErr)
	}

	claimsNoUname := &UserClaims{
		UserID: "u1002",
		RegisteredClaims: RegisteredClaims{
			ID:        "jti_nouname",
			ExpiresAt: &exp,
			IssuedAt:  &now,
		},
	}
	tok2 := NewToken(claimsNoUname, method)
	tokenStr2, _ := tok2.SignedString()
	p2 := &UserClaims{}
	_, err = Parse(tokenStr2, p2, method)
	if err == nil {
		t.Error("missing Username should trigger error")
	}
	rootErr2 := unwrapRootErr(err)
	t.Logf("missing username outer=%v root=%v", err, rootErr2)
	if rootErr2.Error() != "token is missing required claim" {
		t.Errorf("want 'token is missing required claim', got '%v'", rootErr2)
	}
}

func TestParseWithClaims(t *testing.T) {
	aesKey, hmacKey := generateTestKeys(t)
	method, _ := NewSigningMethodBinary(aesKey, hmacKey)

	claims := createTestClaims()
	tok := NewToken(claims, method)
	tokenStr, _ := tok.SignedString()

	parsedClaims := &UserClaims{}
	outTok, err := ParseWithClaims(tokenStr, parsedClaims, func(tk *Token) (SigningMethod, error) {
		return method, nil
	})
	if err != nil {
		t.Fatalf("ParseWithClaims err: %v", err)
	}
	if outTok == nil {
		t.Fatal("token nil")
	}
	if parsedClaims.UserID != claims.UserID {
		t.Error("parsewithclaims field mismatch")
	}
}

func TestIsValidBase64(t *testing.T) {
	tests := []struct {
		name string
		s    string
		want bool
	}{
		{"valid std base64", base64.StdEncoding.EncodeToString([]byte("hello world")), true},
		{"base64url with -, no padding", "SGVsbG8tX3dvcmxk", true}, // 注意：现有IsValidBase64允许'-'，源码逻辑就这样
		{"empty string", "", false},
		{"illegal char #", "YWhh##", false},
		{"length not multiple 4", "YWJjZ", false},
		{"with padding", "YQ==", true},
		{"invalid char _", "YWhh_", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := IsValidBase64(tt.s)
			if got != tt.want {
				t.Errorf("IsValidBase64(%q) want=%v got=%v", tt.s, tt.want, got)
			}
		})
	}
}

func TestNewSigningMethodBinaryKeyCheck(t *testing.T) {
	badAes := make([]byte, 16)
	goodHmac := make([]byte, 32)
	_, err := NewSigningMethodBinary(badAes, goodHmac)
	if err == nil {
		t.Error("short aes key expect error")
	}

	goodAes := make([]byte, 32)
	shortHmac := make([]byte, 8)
	_, err = NewSigningMethodBinary(goodAes, shortHmac)
	if err == nil {
		t.Error("short hmac key expect error")
	}
}

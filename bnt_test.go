package bnt

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"testing"
	"time"
)

// 示例：自定义Claims
type UserClaims struct {
	UserID   string `json:"user_id"`
	Username string `json:"username"`
	RegisteredClaims
}

// Valid 验证自定义claims
func (uc *UserClaims) Valid() error {
	// 先验证标准声明
	if err := uc.RegisteredClaims.Valid(); err != nil {
		return err
	}

	// 验证自定义字段
	if uc.UserID == "" {
		return ErrTokenRequiredClaimMissing
	}

	if uc.Username == "" {
		return ErrTokenRequiredClaimMissing
	}

	return nil
}

// 生成测试用的密钥对
func generateTestKeys(t *testing.T) (aesKey, hmacKey []byte) {
	aesKey = make([]byte, AESKeyLen)
	if _, err := rand.Read(aesKey); err != nil {
		t.Fatalf("生成AES密钥失败: %v", err)
	}

	hmacKey = make([]byte, 32) // 使用32字节的HMAC密钥
	if _, err := rand.Read(hmacKey); err != nil {
		t.Fatalf("生成HMAC密钥失败: %v", err)
	}

	return aesKey, hmacKey
}

// 创建测试用的claims
func createTestClaims() *UserClaims {
	now := time.Now().UTC()
	expiresAt := now.Add(1 * time.Hour)
	notBefore := now.Add(-5 * time.Minute)

	return &UserClaims{
		UserID:   "test_user_123",
		Username: "test_user",
		RegisteredClaims: RegisteredClaims{
			ExpiresAt: &expiresAt,
			IssuedAt:  &now,
			NotBefore: &notBefore,
			Issuer:    "test_issuer",
			Subject:   "test_subject",
			ID:        "test_jti_456",
		},
	}
}

// 测试正常的Token生成和验证流程
func TestTokenGenerationAndVerification(t *testing.T) {
	aesKey, hmacKey := generateTestKeys(t)
	signingMethod, err := NewSigningMethodBinary(aesKey, hmacKey)
	if err != nil {
		t.Fatalf("创建签名方法失败: %v", err)
	}
	fmt.Println(aesKey)
	fmt.Println(hmacKey)
	fmt.Println(signingMethod)
	// 创建claims和token
	claims := createTestClaims()
	token := NewToken(claims, signingMethod)
	fmt.Println("claims", claims)
	// 生成token字符串
	tokenStr, err := token.SignedString()
	if err != nil {
		t.Fatalf("生成token失败: %v", err)
	}
	if tokenStr == "" {
		t.Error("生成的token为空字符串")
	}
	fmt.Println("==>", tokenStr)
	// 解析并验证token
	parsedClaims := &UserClaims{}
	parsedToken, err := Parse(tokenStr, parsedClaims, signingMethod)
	if err != nil {
		t.Fatalf("解析token失败: %v", err)
	}

	// 验证解析结果
	if parsedClaims.UserID != claims.UserID {
		t.Errorf("UserID不匹配: 期望 %s, 实际 %s", claims.UserID, parsedClaims.UserID)
	}
	if parsedClaims.Username != claims.Username {
		t.Errorf("Username不匹配: 期望 %s, 实际 %s", claims.Username, parsedClaims.Username)
	}
	if parsedClaims.Issuer != claims.Issuer {
		t.Errorf("Issuer不匹配: 期望 %s, 实际 %s", claims.Issuer, parsedClaims.Issuer)
	}
	if parsedClaims.Subject != claims.Subject {
		t.Errorf("Subject不匹配: 期望 %s, 实际 %s", claims.Subject, parsedClaims.Subject)
	}
	if parsedClaims.ID != claims.ID {
		t.Errorf("ID不匹配: 期望 %s, 实际 %s", claims.ID, parsedClaims.ID)
	}

	// 验证时间字段（修复指针比较问题）
	if claims.ExpiresAt != nil && parsedClaims.ExpiresAt != nil {
		if !parsedClaims.ExpiresAt.Equal(*claims.ExpiresAt) {
			t.Errorf("ExpiresAt不匹配: 期望 %v, 实际 %v", claims.ExpiresAt, parsedClaims.ExpiresAt)
		}
	} else if claims.ExpiresAt != parsedClaims.ExpiresAt {
		t.Error("ExpiresAt nil状态不匹配")
	}

	if claims.IssuedAt != nil && parsedClaims.IssuedAt != nil {
		if !parsedClaims.IssuedAt.Equal(*claims.IssuedAt) {
			t.Errorf("IssuedAt不匹配: 期望 %v, 实际 %v", claims.IssuedAt, parsedClaims.IssuedAt)
		}
	} else if claims.IssuedAt != parsedClaims.IssuedAt {
		t.Error("IssuedAt nil状态不匹配")
	}

	if claims.NotBefore != nil && parsedClaims.NotBefore != nil {
		if !parsedClaims.NotBefore.Equal(*claims.NotBefore) {
			t.Errorf("NotBefore不匹配: 期望 %v, 实际 %v", claims.NotBefore, parsedClaims.NotBefore)
		}
	} else if claims.NotBefore != parsedClaims.NotBefore {
		t.Error("NotBefore nil状态不匹配")
	}

	// 验证token有效性
	if err := parsedToken.Claims.Valid(); err != nil {
		t.Errorf("验证token有效性失败: %v", err)
	}
}

// 测试过期的Token
func TestExpiredToken(t *testing.T) {
	aesKey, hmacKey := generateTestKeys(t)
	signingMethod, err := NewSigningMethodBinary(aesKey, hmacKey)
	if err != nil {
		t.Fatalf("创建签名方法失败: %v", err)
	}

	// 创建已过期的claims
	now := time.Now().UTC()
	expiredTime := now.Add(-1 * time.Hour) // 1小时前过期
	claims := &UserClaims{
		UserID:   "expired_user",
		Username: "expired",
		RegisteredClaims: RegisteredClaims{
			ExpiresAt: &expiredTime,
			IssuedAt:  &now,
		},
	}

	// 生成token
	token := NewToken(claims, signingMethod)
	tokenStr, err := token.SignedString()
	if err != nil {
		t.Fatalf("生成token失败: %v", err)
	}

	// 尝试解析过期的token
	parsedClaims := &UserClaims{}
	_, err = Parse(tokenStr, parsedClaims, signingMethod)
	if err == nil {
		t.Error("预期解析过期token会失败，但成功了")
	} else if err.Error() != "invalid claims: token is expired" {
		t.Errorf("预期错误为'token is expired'，但得到: %v", err)
	}
}

// 测试尚未生效的Token
func TestNotYetValidToken(t *testing.T) {
	aesKey, hmacKey := generateTestKeys(t)
	signingMethod, err := NewSigningMethodBinary(aesKey, hmacKey)
	if err != nil {
		t.Fatalf("创建签名方法失败: %v", err)
	}

	// 创建尚未生效的claims
	now := time.Now().UTC()
	notBefore := now.Add(1 * time.Hour) // 1小时后生效
	claims := &UserClaims{
		UserID:   "future_user",
		Username: "future",
		RegisteredClaims: RegisteredClaims{
			NotBefore: &notBefore,
			IssuedAt:  &now,
		},
	}

	// 生成token
	token := NewToken(claims, signingMethod)
	tokenStr, err := token.SignedString()
	if err != nil {
		t.Fatalf("生成token失败: %v", err)
	}

	// 尝试解析尚未生效的token
	parsedClaims := &UserClaims{}
	_, err = Parse(tokenStr, parsedClaims, signingMethod)
	if err == nil {
		t.Error("预期解析尚未生效的token会失败，但成功了")
	} else if err.Error() != "invalid claims: token is not valid yet" {
		t.Errorf("预期错误为'token is not valid yet'，但得到: %v", err)
	}
}

// 测试被篡改的Token
func TestTamperedToken(t *testing.T) {
	aesKey, hmacKey := generateTestKeys(t)
	signingMethod, err := NewSigningMethodBinary(aesKey, hmacKey)
	if err != nil {
		t.Fatalf("创建签名方法失败: %v", err)
	}

	// 生成正常的token
	claims := createTestClaims()
	token := NewToken(claims, signingMethod)
	tokenStr, err := token.SignedString()
	if err != nil {
		t.Fatalf("生成token失败: %v", err)
	}

	// 篡改token
	if len(tokenStr) < 5 {
		t.Fatal("生成的token太短，无法进行篡改测试")
	}
	tamperedToken := tokenStr[:len(tokenStr)-5] + "abcde" // 修改最后5个字符

	// 尝试解析被篡改的token
	parsedClaims := &UserClaims{}
	_, err = Parse(tamperedToken, parsedClaims, signingMethod)
	if err == nil {
		t.Error("预期解析被篡改的token会失败，但成功了")
	}
}

// 测试使用错误的密钥验证Token
func TestWrongKeyVerification(t *testing.T) {
	aesKey, hmacKey := generateTestKeys(t)
	signingMethod, err := NewSigningMethodBinary(aesKey, hmacKey)
	if err != nil {
		t.Fatalf("创建签名方法失败: %v", err)
	}

	// 生成正常的token
	claims := createTestClaims()
	token := NewToken(claims, signingMethod)
	tokenStr, err := token.SignedString()
	if err != nil {
		t.Fatalf("生成token失败: %v", err)
	}

	// 使用错误的密钥尝试验证
	wrongAesKey, wrongHmacKey := generateTestKeys(t)
	wrongSigningMethod, err := NewSigningMethodBinary(wrongAesKey, wrongHmacKey)
	if err != nil {
		t.Fatalf("创建错误的签名方法失败: %v", err)
	}

	parsedClaims := &UserClaims{}
	_, err = Parse(tokenStr, parsedClaims, wrongSigningMethod)
	if err == nil {
		t.Error("预期使用错误密钥验证会失败，但成功了")
	}
}

// 测试无效的Base64格式Token
func TestInvalidBase64Token(t *testing.T) {
	aesKey, hmacKey := generateTestKeys(t)
	signingMethod, err := NewSigningMethodBinary(aesKey, hmacKey)
	if err != nil {
		t.Fatalf("创建签名方法失败: %v", err)
	}

	// 无效的Base64字符串
	invalidToken := "this is not a valid base64 string"

	parsedClaims := &UserClaims{}
	_, err = Parse(invalidToken, parsedClaims, signingMethod)
	if err == nil {
		t.Error("预期解析无效Base64的token会失败，但成功了")
	}
}

// 测试过短的Token
func TestTooShortToken(t *testing.T) {
	aesKey, hmacKey := generateTestKeys(t)
	signingMethod, err := NewSigningMethodBinary(aesKey, hmacKey)
	if err != nil {
		t.Fatalf("创建签名方法失败: %v", err)
	}

	// 过短的token（短于签名长度）
	shortToken := base64.URLEncoding.EncodeToString(make([]byte, 10))

	parsedClaims := &UserClaims{}
	_, err = Parse(shortToken, parsedClaims, signingMethod)
	if err == nil {
		t.Error("预期解析过短的token会失败，但成功了")
	} else if err.Error() != "invalid token: too short" {
		t.Errorf("预期错误为'invalid token: too short'，但得到: %v", err)
	}
}

// 测试自定义claims验证
func TestCustomClaimsValidation(t *testing.T) {
	aesKey, hmacKey := generateTestKeys(t)
	signingMethod, err := NewSigningMethodBinary(aesKey, hmacKey)
	if err != nil {
		t.Fatalf("创建签名方法失败: %v", err)
	}

	// 创建缺少必填字段的claims
	now := time.Now().UTC()
	expiresAt := now.Add(1 * time.Hour)

	// 缺少UserID的claims
	claimsWithoutUserID := &UserClaims{
		Username: "no_user_id",
		RegisteredClaims: RegisteredClaims{
			ExpiresAt: &expiresAt,
			IssuedAt:  &now,
		},
	}

	token1 := NewToken(claimsWithoutUserID, signingMethod)
	tokenStr1, err := token1.SignedString()
	if err != nil {
		t.Fatalf("生成token失败: %v", err)
	}

	parsedClaims1 := &UserClaims{}
	_, err = Parse(tokenStr1, parsedClaims1, signingMethod)
	if err == nil {
		t.Error("预期解析缺少UserID的token会失败，但成功了")
	} else if err.Error() != "invalid claims: user_id is required" {
		t.Errorf("预期错误为'user_id is required'，但得到: %v", err)
	}

	// 缺少Username的claims
	claimsWithoutUsername := &UserClaims{
		UserID: "no_username",
		RegisteredClaims: RegisteredClaims{
			ExpiresAt: &expiresAt,
			IssuedAt:  &now,
		},
	}

	token2 := NewToken(claimsWithoutUsername, signingMethod)
	tokenStr2, err := token2.SignedString()
	if err != nil {
		t.Fatalf("生成token失败: %v", err)
	}

	parsedClaims2 := &UserClaims{}
	_, err = Parse(tokenStr2, parsedClaims2, signingMethod)
	if err == nil {
		t.Error("预期解析缺少Username的token会失败，但成功了")
	} else if err.Error() != "invalid claims: username is required" {
		t.Errorf("预期错误为'username is required'，但得到: %v", err)
	}
}

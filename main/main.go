package main

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/hiuias/bnt"
	"time"
)

// 生成测试用的密钥对
func generateTestKeys() (aesKey, hmacKey []byte) {
	aesKey = make([]byte, bnt.AESKeyLen)
	if _, err := rand.Read(aesKey); err != nil {
		fmt.Println(err)
	}

	hmacKey = make([]byte, 32) // 使用32字节的HMAC密钥
	if _, err := rand.Read(hmacKey); err != nil {
		fmt.Printf("生成HMAC密钥失败: %v", err)
	}

	return aesKey, hmacKey
}

// 示例：从环境变量获取密钥
func GetKeysFromEnv() (aesKey, hmacKey []byte, err error) {
	// 生成 AES 密钥 (32 字节)
	// 生成 32 字节的随机数据并 Base64 编码
	// openssl rand -base64 32
	aesKeyStr := "nZ/ShAOj/VFPz+pJ7dxNy9Y6TuWOp/d412sHuLHfSw8="
	// 生成 HMAC 密钥 (至少 16 字节，推荐 32 字节)
	// 生成 32 字节的随机数据并 Base64 编码
	// openssl rand -base64 32
	hmacKeyStr := "mJT6l4KpRmATxVtXsDTk8fZ8iORGx3Lm8v0fFyPUme8="

	if aesKeyStr == "" || hmacKeyStr == "" {
		return nil, nil, errors.New("encryption keys not set in environment")
	}

	// Base64解码密钥（假设密钥以Base64格式存储）
	aesKey, err = base64.StdEncoding.DecodeString(aesKeyStr)
	if err != nil {
		return nil, nil, fmt.Errorf("invalid AES key: %w", err)
	}

	hmacKey, err = base64.StdEncoding.DecodeString(hmacKeyStr)
	if err != nil {
		return nil, nil, fmt.Errorf("invalid HMAC key: %w", err)
	}

	return aesKey, hmacKey, nil
}

type UserInfo struct {
	User struct {
		Domain struct {
			Id   string `json:"id"`
			Name string `json:"name"`
		} `json:"domain"`
		ID   string `json:"id"`
		Name struct {
			Account string `json:"account"`
		} `json:"name"`
	} `json:"user"`
}

// 示例：自定义Claims
type UserClaims struct {
	UserInfo *UserInfo `json:"user_info"`
	bnt.RegisteredClaims
}

// 创建测试用的claims
func createClaims() *UserClaims {
	now := time.Now().UTC()
	expiresAt := now.Add(3 * time.Hour)
	s := &UserInfo{}
	s.User.Domain.Id = "5dbc59fd33e94b70a60d9b55633f53d2"
	s.User.Domain.Name = "sys_svc_snms"
	s.User.ID = "5dbc59fd33e94b70a60d9b55633f53d2"
	s.User.Name.Account = "sys_svc_snms"
	return &UserClaims{
		UserInfo: s,
		RegisteredClaims: bnt.RegisteredClaims{
			Issuer:    "test_issuer",
			Subject:   "test_subject",
			Audience:  []string{"sys_svc_snms", "sys_svc_snms"},
			ExpiresAt: &expiresAt, // 过期时间
			NotBefore: &now,       // 生效时间
			IssuedAt:  &now,       // 签发时间
			ID:        "jti/d0fdd71e67f24c938f956f4b4522c208",
		},
	}
}

func main() {
	// aesKey, hmacKey := generateTestKeys()
	aesKey, hmacKey, err := GetKeysFromEnv()
	if err != nil {
		fmt.Printf("创建key方法失败: %v", err)
		return
	}
	signingMethod, err := bnt.NewSigningMethodBinary(aesKey, hmacKey)
	if err != nil {
		fmt.Printf("创建签名方法失败: %v", err)
	}
	fmt.Println(aesKey)
	fmt.Println(hmacKey)
	fmt.Println("signingMethod", signingMethod)

	// 创建claims和token
	claims := createClaims()
	token := bnt.NewToken(claims, signingMethod)
	fmt.Println("claims", claims)

	// 生成token字符串
	tokenStr, err := token.SignedString()
	if err != nil {
		fmt.Printf("生成token失败: %v", err)
	}
	if tokenStr == "" {
		fmt.Printf("生成的token为空字符串")
	}
	fmt.Println("==>", tokenStr)

	// 解析并验证token
	parsedClaims := &UserClaims{}
	parsedToken, err := bnt.Parse(tokenStr, parsedClaims, signingMethod)
	if err != nil {
		fmt.Printf("解析token失败: %v\n", err)
		return
	}

	fmt.Printf("---+++++++===> %+v\n", parsedClaims)

	// 验证token有效性
	if err := parsedToken.Claims.Valid(); err != nil {
		fmt.Printf("验证token有效性失败: %v\n", err)
	}

	jsonData, err := json.Marshal(parsedClaims)
	if err != nil {
		fmt.Println(err)
		return
	}

	fmt.Println("json: ", string(jsonData))
}

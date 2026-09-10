# BNT \- 二进制令牌库

> ### Binary Network Token

**BNT** 是一款高性能、高安全的 **二进制加密令牌** Go 库，替代传统令牌。基于 **AES\-256\-GCM 加密 \+ HMAC\-SHA256 完整性校验**，性能优秀，内置密钥轮换、令牌续签、全套安全校验机制。

## 核心特性

- **性能高效**：二进制结构，签名/验签性能优秀

- **令牌安全**：AES\-256\-GCM 对称加密 \+ HMAC\-SHA256 防篡改双校验

- **密钥轮换** ：内置 KID 密钥 ID 机制，支持平滑密钥升级、多密钥并存

- **令牌续签**：支持可控次数刷新令牌，自定义最大续签次数，防无限续期

- **多维度校验**：过期时间、生效时间、签发时间、令牌ID、头部合法性、密钥匹配校验

- **高健壮性**：完整 Base64 校验、参数边界限制、防畸形输入攻击

## 令牌结构

固定二进制帧结构，结构紧凑、解析极速：

```Plain Text
[4字节KID][4字节随机数][1字节版本][4字节保留位][1字节标志位][2字节载荷长度][加密载荷][12B nonce]
```

- 保留位强制清零，防恶意构造头部

- GCM 12字节标准随机数，兼容密码学规范

- 尾部 HMAC\-SHA256 全局防篡改校验

## 快速开始

### 1\. 基础签名与验签

```go
package main

import (
	"errors"
	"fmt"
	"time"

	"github.com/uias-io/bnt"
)

func main() {
	// 密钥配置：AES-256必须32字节，HMAC密钥≥16字节（生产环境禁止硬编码）
	var (
		aesKey  = []byte("0123456789abcdef0123456789abcdef")
		hmacKey = []byte("my-production-hmac-key-123456")
		kid     uint32 = 1001 // 密钥ID，用于密钥轮换
	)

	// 初始化签名方法
	method, err := bnt.NewSigningMethodBinaryWithKID(aesKey, hmacKey, kid)
	if err != nil {
		panic(err)
	}

	// 构造标准声明
	now := time.Now().UTC()
	claims := &bnt.RegisteredClaims{
		ID:        "token-20260910-001", // 唯一令牌ID
		IssuedAt:  bnt.PtrTime(now),
		ExpiresAt: bnt.PtrTime(now.Add(2 * time.Hour)), // 2小时过期
		Ttl:       7200,
	}

	// 生成签名Token
	token := bnt.NewToken(claims, method)
	tokenStr, err := token.SignedString()
	if err != nil {
		panic(err)
	}
	fmt.Println("生成BNT Token:", tokenStr)

	// 解析并验证Token
	outClaims := &bnt.RegisteredClaims{}
	parsed, err := bnt.Parse(tokenStr, outClaims, method)
	if err != nil {
		// 精准错误判断
		switch {
		case errors.Is(err, bnt.ErrTokenExpired):
			fmt.Println("Token已过期")
		case errors.Is(err, bnt.ErrTokenKidMismatch):
			fmt.Println("密钥ID不匹配")
		default:
			fmt.Println("Token验证失败:", err)
		}
		return
	}

	fmt.Printf("验证成功！KID: %d, TokenID: %s\n", parsed.Kid, outClaims.ID)
}
```

### 2\. 令牌续签功能

支持限制最大续签次数，防止令牌永久有效，保障安全：

```go
func refreshTokenDemo() {
	method, _ := bnt.NewSigningMethodBinaryWithKID(aesKey, hmacKey, 1001)
	now := time.Now().UTC()

	// 初始化支持续签的声明：最大续签5次
	claims := &bnt.RegisteredClaims{
		ID:            "old-token-id",
		IssuedAt:      bnt.PtrTime(now),
		ExpiresAt:     bnt.PtrTime(now.Add(1 * time.Hour)),
		Ttl:           3600,
		IssueCount:    0,
		MaxIssueCount: 5,
	}

	token := bnt.NewToken(claims, method)

	// 续签，更换新的TokenID
	newJti := "new-token-id-002"
	if err := token.Refresh(newJti); err != nil {
		panic(err)
	}

	// 续签后自动更新：签发时间、生效时间、过期时间、续签次数
	fmt.Println("续签后TokenID:", claims.ID)
	fmt.Println("当前续签次数:", claims.IssueCount)
}
```

### 3\. 密钥轮换（多KID适配）

通过 `ParseWithClaims` 实现动态匹配密钥，支持平滑密钥更新：

```go
func parseWithKeyRotate(tokenStr string) (*bnt.Token, error) {
	// 模拟多密钥映射（生产环境从配置中心读取）
	keyMap := map[uint32]*bnt.SigningMethodBinary{
		1001: mustNewMethod(1001), // 旧密钥
		1002: mustNewMethod(1002), // 新密钥
	}

	claims := &bnt.RegisteredClaims{}
	// 根据Token中的KID动态选择验证密钥
	return bnt.ParseWithClaims(tokenStr, claims, func(tk *bnt.Token) (bnt.SigningMethod, error) {
		method, ok := keyMap[tk.Kid]
		if !ok {
			return nil, bnt.ErrTokenKidMismatch
		}
		return method, nil
	})
}

func mustNewMethod(kid uint32) *bnt.SigningMethodBinary {
	m, _ := bnt.NewSigningMethodBinaryWithKID(aesKey, hmacKey, kid)
	return m
}
```

## 性能压测结果

测试环境：`Windows10 Intel(R) Core(TM) i7-9750H CPU @ 2.60GHz`

```bash
BenchmarkSign-12                  249412    4556 ns/op     2931 B/op   23 allocs/op
BenchmarkVerify-12                240841    4513 ns/op     2136 B/op   22 allocs/op
BenchmarkToken_SignedString-12    258718    4528 ns/op     2963 B/op   23 allocs/op
BenchmarkParse_FullEndToEnd-12    240712    4697 ns/op     2160 B/op   22 allocs/op
```

- **签名 QPS：约 21 9500 /核**
- **验签 QPS：约 22 1600 /核**
- **完整签发 (SignedString)：4.53μs，约 22.08 万 QPS / 核**
- **完整验签 (Parse)：4.70μs，约 21.29 万 QPS / 核**

## 安全测试验证

完成全量安全测试，无任何崩溃、panic、越界漏洞：

- 单元测试全覆盖：篡改、过期、未生效、密钥错误、KID不匹配、非法头部

- 三轮 120s 长时间 Fuzz 模糊测试，畸形输入全部安全拦截，无崩溃

- 所有 Fuzz 新增边界用例重放通过，鲁棒性拉满

- 严格的 Base64 格式校验、长度限制、头部字段强校验

## 生产环境安全规范

1. **禁止硬编码密钥**：AES/HMAC 密钥必须从配置中心、环境变量、密钥管理服务读取

2. **密钥长度强制规范**：AES 固定32字节（AES\-256），HMAC 密钥≥16字节，建议24字节以上

3. **优先显式KID**：生产使用 `NewSigningMethodBinaryWithKID`，不依赖自动随机KID

4. **精简Claims**：仅存放核心标识，禁止存放大量业务数据，避免Token膨胀

5. **限制续签次数**：生产环境务必配置 `MaxIssueCount`，禁止无限续期

## 测试命令

```bash
# 运行全部单元测试
go test -v ./...

# 性能压测
go test -bench=. -benchmem

# 模糊安全测试
go test -fuzz=FuzzBntParse -fuzztime=120s
go test -fuzz=FuzzBntRawBytes -fuzztime=120s
go test -fuzz=FuzzBntSignVerify -fuzztime=120s

# 重放fuzz边界用例
go test -run=FuzzBntParse
go test -run=FuzzBntRawBytes
go test -run=FuzzBntSignVerify
```

> Linux生成相关密钥

```bash
# 生成 AES 密钥 (32 字节) 随机数据并 Base64 编码
openssl rand -base64 32

# 生成 HMAC 密钥 (至少 16 字节，推荐 32 字节),并 Base64 编码
openssl rand -base64 32
```

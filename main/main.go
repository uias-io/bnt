package main

import (
	"errors"
	"fmt"
	"time"

	"github.com/hiuias/bnt"
)

// BizClaims 自定义声明，嵌入标准RegisteredClaims，增加自己业务字段
type BizClaims struct {
	bnt.RegisteredClaims

	// 额外业务信息
	Role    string `json:"role"`     // 用户角色
	OrgID   string `json:"org_id"`   // 所属组织ID
	IsAdmin bool   `json:"is_admin"` // 是否管理员
}

// Valid 实现 bnt.Claims 接口
func (c *BizClaims) Valid() error {
	// 执行原有标准校验（过期、签发者、续签次数等）
	if err := c.RegisteredClaims.Valid(); err != nil {
		return err
	}
	// 自定义业务校验规则
	if c.OrgID == "" {
		return errors.New("org_id 不能为空")
	}
	return nil
}

func main() {
	// ========== 密钥准备 ==========
	// AES-256 固定32字节；HMAC密钥≥16字节，生产环境必须密码学随机生成！
	aesKey := []byte("01234567890123456789012345678901") // 32字节
	hmacKey := []byte("abcdefgh12345678abcdefgh12345678")

	// 创建签名实例
	kid := uint32(time.Now().Unix())
	signMethod, err := bnt.NewSigningMethodBinaryWithKID(aesKey, hmacKey, kid)
	if err != nil {
		panic(err)
	}

	// 构造【自定义Claims】，带上额外业务字段
	now := time.Now().UTC()
	claims := &BizClaims{
		RegisteredClaims: bnt.RegisteredClaims{
			ID:            "jti-xxxx001",
			IssuedAt:      &now,
			ExpiresAt:     func() *time.Time { t := now.Add(1 * time.Hour); return &t }(),
			Ttl:           3600, // 有效时长秒
			MaxIssueCount: 2,    // 最多允许续签2次
		},
		// 填充额外信息
		Role:    "色角",
		OrgID:   "org-0005",
		IsAdmin: false,
	}

	// 创建内存token对象
	tokenObj := bnt.NewToken(claims, signMethod)

	fmt.Println("||||||||||||||")
	fmt.Println(tokenObj.Claims)
	// 签名加密，得到对外下发token字符串
	tokenStr, err := tokenObj.SignedString()
	if err != nil {
		panic(fmt.Sprintf("签发失败:%v", err))
	}

	fmt.Println("生成Token字符串：")
	fmt.Println(tokenStr)
	fmt.Println()

	// -------------------- 模拟服务端验证token --------------------
	fmt.Println("===== 开始验证Token =====")
	parseClaims := &BizClaims{} // 使用自定义结构体接收解析结果
	parsedToken, err := bnt.Parse(tokenStr, parseClaims, signMethod)
	if err != nil {
		panic(fmt.Sprintf("验证失败：%v", err))
	}
	fmt.Println()
	fmt.Println("验证成功！")
	fmt.Println(parsedToken.Claims)

	// -------------------- Token续签演示 --------------------
	fmt.Println("===== 执行Token续签 =====")
	err = parsedToken.Refresh("zzzzzzzzzzzzzzzzzzzzzzz")
	if err != nil {
		panic(fmt.Sprintf("续签失败：%v", err))
	}

	fmt.Println()
	fmt.Println("||||||||||||||")
	fmt.Println(parsedToken.Claims)
	// Refresh只修改内存，需要重新SignedString拿到新token
	newTokenStr, err := parsedToken.SignedString()
	if err != nil {
		panic(err)
	}
	fmt.Println("续签后新Token：")
	fmt.Println(newTokenStr)
	// 解析续签后的token，自定义字段依然保留
	fmt.Println("\n===== 校验续签后的Token =====")
	renewClaims := &BizClaims{}
	aa, err := bnt.Parse(newTokenStr, renewClaims, signMethod)
	if err != nil {
		panic(err)
	}

	fmt.Println()
	fmt.Printf("续签后 角色:%s  组织:%s  续签次数:%d\n", renewClaims.Role, renewClaims.OrgID, renewClaims.IssueCount)
	fmt.Println(aa.Claims)
}

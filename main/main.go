package main

import (
	"errors"
	"fmt"
	"time"

	"github.com/uias-io/bnt"
)

// BizClaims is a custom claims struct that embeds the standard RegisteredClaims and adds business-specific fields.
type BizClaims struct {
	bnt.RegisteredClaims

	// Extra business information.
	Role    string `json:"role"`     // User role
	OrgID   string `json:"org_id"`   // Owning organization ID
	IsAdmin bool   `json:"is_admin"` // Whether the user is an admin
}

// Valid implements the bnt.Claims interface.
func (c *BizClaims) Valid() error {
	// Run the original standard validation (expiration, issuer, refresh count, etc.).
	if err := c.RegisteredClaims.Valid(); err != nil {
		return err
	}
	// Custom business validation rules.
	if c.OrgID == "" {
		return errors.New("org_id cannot be empty")
	}
	return nil
}

func main() {
	// ========== Key preparation ==========
	// AES-256 uses a fixed 32 bytes; HMAC key must be >= 16 bytes, and in production it must be generated with a cryptographically secure random source!
	aesKey := []byte("01234567890123456789012345678901") // 32 bytes
	hmacKey := []byte("abcdefgh12345678abcdefgh12345678")

	// Create a signing instance.
	// kid := uint32(time.Now().Unix())
	signMethod, err := bnt.NewSigningMethodBinaryWithKID(aesKey, hmacKey, bnt.GenKid())
	if err != nil {
		panic(err)
	}

	// Build [custom Claims] with extra business fields.
	now := time.Now().UTC()
	claims := &BizClaims{
		RegisteredClaims: bnt.RegisteredClaims{
			ID:            "jti-xxxx001",
			IssuedAt:      &now,
			NotBefore:     &now,
			ExpiresAt:     func() *time.Time { t := now.Add(1 * time.Hour); return &t }(),
			Ttl:           3600, // Validity duration in seconds
			MaxIssueCount: 0,    // Allow at most 2 refreshes
		},
		// Fill in extra information.
		Role:    "色角",
		OrgID:   "org-0005",
		IsAdmin: false,
	}

	// Create an in-memory token object.
	tokenObj := bnt.NewToken(claims, signMethod)

	fmt.Println("||||||||||||||")
	fmt.Println("-->", tokenObj)
	// Sign and encrypt to obtain the token string to be issued externally.
	tokenStr, err := tokenObj.SignedString()
	if err != nil {
		panic(fmt.Sprintf("signing failed: %v", err))
	}

	fmt.Println("Generated token string:")
	fmt.Println(tokenStr)
	fmt.Println()

	// -------------------- Simulate server-side token verification --------------------
	fmt.Println("===== Starting token verification =====")
	parseClaims := &BizClaims{} // Use the custom struct to receive the parse result
	parsedToken, err := bnt.Parse(tokenStr, parseClaims, signMethod)
	if err != nil {
		panic(fmt.Sprintf("verification failed: %v", err))
	}
	fmt.Println()
	fmt.Println("Verification succeeded!")
	fmt.Println(parsedToken.Claims)

	// -------------------- Token refresh demo --------------------
	fmt.Println("===== Performing token refresh =====")

	time.Sleep(5 * time.Second)
	err = parsedToken.Refresh("zzzzzzzzzzzzzzzzzzzzzzz")
	if err != nil {
		panic(fmt.Sprintf("refresh failed: %v", err))
	}

	fmt.Println()
	fmt.Println("||||||||||||||")
	fmt.Println(parsedToken.Claims)
	// Refresh only modifies memory; you need to call SignedString again to get the new token.
	newTokenStr, err := parsedToken.SignedString()
	if err != nil {
		panic(err)
	}
	fmt.Println("New token after refresh:")
	fmt.Println(newTokenStr)
	// Parse the refreshed token; custom fields are still preserved.
	fmt.Println("\n===== Verifying the refreshed token =====")
	renewClaims := &BizClaims{}
	aa, err := bnt.Parse(newTokenStr, renewClaims, signMethod)
	if err != nil {
		panic(err)
	}

	fmt.Println()
	fmt.Printf("After refresh  Role:%s  Org:%s  Refresh count:%d\n", renewClaims.Role, renewClaims.OrgID, renewClaims.IssueCount)
	fmt.Println(aa.Claims)

	fmt.Println()
}

package bnt

import (
	"encoding/base64"
	"testing"
	"time"
)

// FuzzBntParse fuzzes the Parse entry point, feeding various garbled base64 strings to Parse.
func FuzzBntParse(f *testing.F) {
	// Seed case: one normal token as a base seed; fuzz will mutate based on it.
	method, err := NewSigningMethodBinaryWithKID(testAESKey, testHMACKey, testKID)
	if err != nil {
		f.Fatal(err)
	}
	now := time.Now().UTC()
	seedClaims := &RegisteredClaims{
		ID:        "seed-jti-001",
		IssuedAt:  &now,
		ExpiresAt: ptrTime(now.Add(1 * time.Hour)),
		Ttl:       3600,
	}
	tok := NewToken(seedClaims, method)
	seedTokenStr, err := tok.SignedString()
	if err != nil {
		f.Fatal(err)
	}
	f.Add(seedTokenStr)

	f.Fuzz(func(t *testing.T, tokenStr string) {
		outClaims := &RegisteredClaims{}
		// As long as it does not panic, returning any error is normal; crashing is forbidden.
		_, _ = Parse(tokenStr, outClaims, method)
	})
}

// FuzzBntRawBytes directly fuzzes the raw binary token bytes.
func FuzzBntRawBytes(f *testing.F) {
	method, err := NewSigningMethodBinaryWithKID(testAESKey, testHMACKey, testKID)
	if err != nil {
		f.Fatal(err)
	}
	now := time.Now().UTC()
	seedClaims := &RegisteredClaims{
		ID:        "raw-seed",
		IssuedAt:  &now,
		ExpiresAt: ptrTime(now.Add(1 * time.Hour)),
		Ttl:       3600,
	}
	tok := NewToken(seedClaims, method)
	tokenStr, err := tok.SignedString()
	if err != nil {
		f.Fatal(err)
	}
	rawBytes, _ := base64.StdEncoding.DecodeString(tokenStr)
	f.Add(rawBytes)

	f.Fuzz(func(t *testing.T, raw []byte) {
		// Encode into a base64 string and pass it to Parse.
		b64 := base64.StdEncoding.EncodeToString(raw)
		outClaims := &RegisteredClaims{}
		_, _ = Parse(b64, outClaims, method)
	})
}

func FuzzBntSignVerify(f *testing.F) {
	method, err := NewSigningMethodBinaryWithKID(testAESKey, testHMACKey, testKID)
	if err != nil {
		f.Fatal(err)
	}
	now := time.Now().UTC()
	seedClaims := &RegisteredClaims{
		ID:        "fuzz-sign-verify",
		IssuedAt:  &now,
		ExpiresAt: ptrTime(now.Add(1 * time.Hour)),
		Ttl:       3600,
	}
	tok := NewToken(seedClaims, method)
	seedToken, err := tok.SignedString()
	if err != nil {
		f.Fatal(err)
	}
	f.Add(seedToken)

	f.Fuzz(func(t *testing.T, tokenStr string) {
		out := &RegisteredClaims{}
		_, _ = Parse(tokenStr, out, method)
	})
}

// # Run for a period of time to automatically discover anomalies.
// go test -fuzz=FuzzBntParse -fuzztime=120s
// go test -fuzz=FuzzBntRawBytes -fuzztime=120s
// go test -fuzz=FuzzBntSignVerify -fuzztime=120s

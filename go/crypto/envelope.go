// Package crypto provides the platform's BYOK envelope-encryption helper
// (A4.3-c, master-design D5): a per-write data key is generated under the
// TENANT's CMK (or the platform CMK when the tenant has not registered one),
// the plaintext is sealed with AES-256-GCM under that data key, and the
// KMS-wrapped data key is stored alongside the ciphertext. Decrypt unwraps the
// data key via KMS and opens the GCM envelope.
//
// The KMS surface is the two-method KMSAPI interface so services can pass the
// real *kms.Client and tests a fake. The envelope wire format is a single
// self-describing JSON blob (key ARN + wrapped key + nonce + ciphertext), so a
// stored envelope can always be decrypted later even after the tenant's
// registered key changes — the envelope remembers which key wrapped it.
package crypto

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	cryptorand "crypto/rand"
	"encoding/json"
	"fmt"
)

// KMSAPI is the subset of the AWS KMS client the envelope helper uses.
// *kms.Client satisfies it via thin adapters in each consuming service (the
// signatures here use plain Go types so this lib carries NO aws-sdk dependency
// — the A4.2 SDK-skew lesson: a shared lib pinning aws-sdk versions poisons
// every consumer's go.mod).
type KMSAPI interface {
	// GenerateDataKey returns (plaintextKey, wrappedKey, error) for keyARN.
	// plaintextKey MUST be 32 bytes (AES-256).
	GenerateDataKey(ctx context.Context, keyARN string) (plaintext []byte, wrapped []byte, err error)
	// Decrypt unwraps a wrapped data key. KMS infers the CMK from the blob; the
	// envelope's KeyARN is passed for providers that need it.
	Decrypt(ctx context.Context, keyARN string, wrapped []byte) (plaintext []byte, err error)
}

// Envelope is the stored ciphertext blob.
type Envelope struct {
	// KeyARN is the CMK that wrapped DataKey — the tenant's BYOK key or the
	// platform CMK. Recorded so audits (and CloudTrail) can prove which key
	// protected the data, and so decrypt works after a tenant key rotation.
	KeyARN  string `json:"key_arn"`
	DataKey []byte `json:"data_key"` // KMS-wrapped (ciphertext) data key
	Nonce   []byte `json:"nonce"`
	Cipher  []byte `json:"cipher"` // AES-256-GCM sealed plaintext
}

// Encrypt seals plaintext under a fresh data key wrapped by keyARN.
func Encrypt(ctx context.Context, kmsc KMSAPI, keyARN string, plaintext []byte) ([]byte, error) {
	if keyARN == "" {
		return nil, fmt.Errorf("crypto: key ARN required")
	}
	dk, wrapped, err := kmsc.GenerateDataKey(ctx, keyARN)
	if err != nil {
		return nil, fmt.Errorf("crypto: generate data key under %s: %w", keyARN, err)
	}
	if len(dk) != 32 {
		return nil, fmt.Errorf("crypto: data key must be 32 bytes, got %d", len(dk))
	}
	block, err := aes.NewCipher(dk)
	if err != nil {
		return nil, fmt.Errorf("crypto: aes: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("crypto: gcm: %w", err)
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := cryptorand.Read(nonce); err != nil {
		return nil, fmt.Errorf("crypto: nonce: %w", err)
	}
	sealed := gcm.Seal(nil, nonce, plaintext, []byte(keyARN))
	env := Envelope{KeyARN: keyARN, DataKey: wrapped, Nonce: nonce, Cipher: sealed}
	out, err := json.Marshal(env)
	if err != nil {
		return nil, fmt.Errorf("crypto: marshal envelope: %w", err)
	}
	return out, nil
}

// Decrypt opens an envelope produced by Encrypt.
func Decrypt(ctx context.Context, kmsc KMSAPI, envelope []byte) ([]byte, error) {
	var env Envelope
	if err := json.Unmarshal(envelope, &env); err != nil {
		return nil, fmt.Errorf("crypto: unmarshal envelope: %w", err)
	}
	dk, err := kmsc.Decrypt(ctx, env.KeyARN, env.DataKey)
	if err != nil {
		return nil, fmt.Errorf("crypto: unwrap data key (%s): %w", env.KeyARN, err)
	}
	if len(dk) != 32 {
		return nil, fmt.Errorf("crypto: unwrapped key must be 32 bytes, got %d", len(dk))
	}
	block, err := aes.NewCipher(dk)
	if err != nil {
		return nil, fmt.Errorf("crypto: aes: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("crypto: gcm: %w", err)
	}
	if len(env.Nonce) != gcm.NonceSize() {
		return nil, fmt.Errorf("crypto: bad nonce size %d", len(env.Nonce))
	}
	plaintext, err := gcm.Open(nil, env.Nonce, env.Cipher, []byte(env.KeyARN))
	if err != nil {
		return nil, fmt.Errorf("crypto: open: %w", err)
	}
	return plaintext, nil
}

// KeyARNOf reports which CMK protects an envelope without decrypting it
// (BYOK verification + audit tooling).
func KeyARNOf(envelope []byte) (string, error) {
	var env Envelope
	if err := json.Unmarshal(envelope, &env); err != nil {
		return "", fmt.Errorf("crypto: unmarshal envelope: %w", err)
	}
	return env.KeyARN, nil
}

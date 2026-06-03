package crypto

import (
	"bytes"
	"context"
	cryptorand "crypto/rand"
	"encoding/json"
	"errors"
	"testing"
)

// fakeKMS wraps data keys by XOR with a per-key pad — enough to assert the
// right key ARN is used and that decrypt round-trips.
type fakeKMS struct {
	pads  map[string]byte
	calls []string
}

func (f *fakeKMS) GenerateDataKey(ctx context.Context, keyARN string) ([]byte, []byte, error) {
	pad, ok := f.pads[keyARN]
	if !ok {
		return nil, nil, errors.New("unknown key: " + keyARN)
	}
	f.calls = append(f.calls, "gen:"+keyARN)
	dk := make([]byte, 32)
	if _, err := cryptorand.Read(dk); err != nil {
		return nil, nil, err
	}
	wrapped := make([]byte, 32)
	for i, b := range dk {
		wrapped[i] = b ^ pad
	}
	return dk, wrapped, nil
}

func (f *fakeKMS) Decrypt(ctx context.Context, keyARN string, wrapped []byte) ([]byte, error) {
	pad, ok := f.pads[keyARN]
	if !ok {
		return nil, errors.New("unknown key: " + keyARN)
	}
	f.calls = append(f.calls, "dec:"+keyARN)
	dk := make([]byte, len(wrapped))
	for i, b := range wrapped {
		dk[i] = b ^ pad
	}
	return dk, nil
}

const tenantKey = "arn:aws:kms:us-east-1:1:key/tenant"
const platformKey = "arn:aws:kms:us-east-1:1:key/platform"

func newFake() *fakeKMS {
	return &fakeKMS{pads: map[string]byte{tenantKey: 0x5a, platformKey: 0xa5}}
}

func TestRoundTripUnderTenantKey(t *testing.T) {
	kmsc := newFake()
	secret := []byte(`{"ssn":"123-45-6789"}`)
	env, err := Encrypt(context.Background(), kmsc, tenantKey, secret)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(env, secret) {
		t.Fatal("plaintext leaked into envelope")
	}
	// Envelope records the tenant CMK (the BYOK acceptance assertion).
	arn, err := KeyARNOf(env)
	if err != nil || arn != tenantKey {
		t.Fatalf("expected envelope wrapped by tenant key, got %q err=%v", arn, err)
	}
	got, err := Decrypt(context.Background(), kmsc, env)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, secret) {
		t.Fatalf("round trip mismatch: %q", got)
	}
	if kmsc.calls[0] != "gen:"+tenantKey || kmsc.calls[1] != "dec:"+tenantKey {
		t.Fatalf("unexpected KMS calls: %v", kmsc.calls)
	}
}

func TestFallbackKeySelectionIsCallerConcern(t *testing.T) {
	// A tenant without BYOK encrypts under the platform CMK; the envelope
	// remembers it, so a later BYOK registration cannot orphan old data.
	kmsc := newFake()
	env, err := Encrypt(context.Background(), kmsc, platformKey, []byte("x"))
	if err != nil {
		t.Fatal(err)
	}
	arn, _ := KeyARNOf(env)
	if arn != platformKey {
		t.Fatalf("expected platform key, got %s", arn)
	}
	if _, err := Decrypt(context.Background(), kmsc, env); err != nil {
		t.Fatal(err)
	}
}

func TestTamperedCiphertextFails(t *testing.T) {
	kmsc := newFake()
	env, _ := Encrypt(context.Background(), kmsc, tenantKey, []byte("secret"))
	// Flip a byte inside the JSON's cipher field by decoding, mutating, re-encoding.
	var e Envelope
	if err := json.Unmarshal(env, &e); err != nil {
		t.Fatal(err)
	}
	e.Cipher[0] ^= 0xff
	tampered, _ := json.Marshal(e)
	if _, err := Decrypt(context.Background(), kmsc, tampered); err == nil {
		t.Fatal("tampered envelope must not decrypt")
	}
}

func TestUnknownKeyErrors(t *testing.T) {
	kmsc := newFake()
	if _, err := Encrypt(context.Background(), kmsc, "arn:nope", []byte("x")); err == nil {
		t.Fatal("unknown key must error")
	}
	if _, err := Encrypt(context.Background(), kmsc, "", []byte("x")); err == nil {
		t.Fatal("empty key must error")
	}
}

package policy

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strconv"
	"sync"
	"testing"
	"time"
)

// signBundle builds a wire-format signed bundle for a CompiledBundle using the
// canonical message = decimal(version) | "|" | body-json. Mirrors the loader's
// verification so tests produce bundles the loader accepts.
func signBundle(t *testing.T, priv ed25519.PrivateKey, b CompiledBundle) []byte {
	t.Helper()
	body, err := json.Marshal(b)
	if err != nil {
		t.Fatalf("marshal body: %v", err)
	}
	msg := append([]byte(strconv.Itoa(b.Version)+"|"), body...)
	sig := ed25519.Sign(priv, msg)
	wire, err := json.Marshal(signedBundle{
		Version: b.Version,
		Body:    body,
		Sig:     base64.StdEncoding.EncodeToString(sig),
	})
	if err != nil {
		t.Fatalf("marshal wire: %v", err)
	}
	return wire
}

type stubFetcher struct {
	mu      sync.Mutex
	payload []byte
	err     error
	calls   int
}

func (s *stubFetcher) set(p []byte, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.payload, s.err = p, err
}

func (s *stubFetcher) Fetch(_ context.Context) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.calls++
	return s.payload, s.err
}

func (s *stubFetcher) callCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.calls
}

func TestLoader_RejectsBadSignatureKeepsCache(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}

	v1 := CompiledBundle{
		Version: 1,
		System: map[RoleObj]PolicyRule{
			{Role: "viewer", ObjectType: "contact"}: {Read: true},
		},
	}
	good := signBundle(t, priv, v1)

	f := &stubFetcher{}
	f.set(good, nil)
	l := NewLoader(f, pub)

	if err := l.Reload(context.Background()); err != nil {
		t.Fatalf("first reload: %v", err)
	}
	if l.Current().Version != 1 {
		t.Fatalf("want v1 loaded, got %d", l.Current().Version)
	}

	// Tamper: flip a byte of the body but keep the (now-stale) signature, claim v2.
	var wire signedBundle
	if err := json.Unmarshal(good, &wire); err != nil {
		t.Fatal(err)
	}
	tampered := CompiledBundle{
		Version: 2,
		System: map[RoleObj]PolicyRule{
			{Role: "viewer", ObjectType: "contact"}: {Read: true, Delete: true},
		},
	}
	tbody, _ := json.Marshal(tampered)
	badWire, _ := json.Marshal(signedBundle{Version: 2, Body: tbody, Sig: wire.Sig})
	f.set(badWire, nil)

	if err := l.Reload(context.Background()); err == nil {
		t.Fatal("reload of tampered bundle: want error, got nil")
	}
	if l.Current().Version != 1 {
		t.Fatalf("cache must be kept at v1 after bad sig, got %d", l.Current().Version)
	}
	if l.Current().System[RoleObj{Role: "viewer", ObjectType: "contact"}].Delete {
		t.Fatal("tampered grant leaked into cache")
	}
}

func TestLoader_OnlySwapsOnHigherVersion(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	f := &stubFetcher{}
	l := NewLoader(f, pub)

	v2 := CompiledBundle{Version: 2, System: map[RoleObj]PolicyRule{{Role: "r", ObjectType: "o"}: {Read: true}}}
	f.set(signBundle(t, priv, v2), nil)
	if err := l.Reload(context.Background()); err != nil {
		t.Fatal(err)
	}
	if l.Current().Version != 2 {
		t.Fatalf("want v2, got %d", l.Current().Version)
	}

	// A validly-signed but older v1 must not replace v2.
	v1 := CompiledBundle{Version: 1, System: map[RoleObj]PolicyRule{{Role: "r", ObjectType: "o"}: {Read: true, Update: true}}}
	f.set(signBundle(t, priv, v1), nil)
	if err := l.Reload(context.Background()); err != nil {
		t.Fatalf("reload older version should be a no-op, not error: %v", err)
	}
	if l.Current().Version != 2 {
		t.Fatalf("older version must not swap; want v2, got %d", l.Current().Version)
	}

	// Same version is also a no-op.
	f.set(signBundle(t, priv, v2), nil)
	if err := l.Reload(context.Background()); err != nil {
		t.Fatal(err)
	}
	if l.Current().Version != 2 {
		t.Fatalf("want v2, got %d", l.Current().Version)
	}
}

func TestLoader_FetchErrorKeepsCache(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	f := &stubFetcher{}
	v1 := CompiledBundle{Version: 1, System: map[RoleObj]PolicyRule{{Role: "r", ObjectType: "o"}: {Read: true}}}
	f.set(signBundle(t, priv, v1), nil)
	l := NewLoader(f, pub)
	if err := l.Reload(context.Background()); err != nil {
		t.Fatal(err)
	}

	f.set(nil, errors.New("s3 down"))
	if err := l.Reload(context.Background()); err == nil {
		t.Fatal("want fetch error propagated")
	}
	if l.Current().Version != 1 {
		t.Fatalf("cache kept on fetch error; want v1, got %d", l.Current().Version)
	}
}

func TestLoader_CurrentBeforeReloadIsZero(t *testing.T) {
	pub, _, _ := ed25519.GenerateKey(nil)
	l := NewLoader(&stubFetcher{}, pub)
	if l.Current().Version != 0 {
		t.Fatalf("want zero bundle before any reload, got %+v", l.Current())
	}
}

func TestLoader_WatchPolls(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	f := &stubFetcher{}
	v1 := CompiledBundle{Version: 1, System: map[RoleObj]PolicyRule{{Role: "r", ObjectType: "o"}: {Read: true}}}
	f.set(signBundle(t, priv, v1), nil)
	l := NewLoader(f, pub)

	ctx, cancel := context.WithCancel(context.Background())
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		l.Watch(ctx, 5*time.Millisecond)
	}()

	deadline := time.After(2 * time.Second)
	for {
		if l.Current().Version == 1 && f.callCount() >= 1 {
			break
		}
		select {
		case <-deadline:
			cancel()
			wg.Wait()
			t.Fatalf("Watch did not poll+load within deadline (version=%d calls=%d)", l.Current().Version, f.callCount())
		case <-time.After(2 * time.Millisecond):
		}
	}

	// Publish v2; Watch should pick it up on a subsequent poll.
	v2 := CompiledBundle{Version: 2, System: map[RoleObj]PolicyRule{{Role: "r", ObjectType: "o"}: {Read: true, Update: true}}}
	f.set(signBundle(t, priv, v2), nil)

	deadline = time.After(2 * time.Second)
	for l.Current().Version != 2 {
		select {
		case <-deadline:
			cancel()
			wg.Wait()
			t.Fatalf("Watch did not pick up v2, version=%d", l.Current().Version)
		case <-time.After(2 * time.Millisecond):
		}
	}
	cancel()
	wg.Wait()
}

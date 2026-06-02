package policy

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"sync/atomic"
	"time"
)

// Fetcher retrieves the raw signed-bundle bytes from wherever the governance
// service publishes them (S3, an HTTP endpoint, the local filesystem in tests).
// The concrete S3 implementation lives in each service, not in this shared lib,
// so that this package depends only on the standard library.
type Fetcher interface {
	Fetch(ctx context.Context) (signed []byte, err error)
}

// signedBundle is the on-the-wire envelope. Body is the raw JSON encoding of a
// CompiledBundle; Sig is the base64 ed25519 signature over the canonical message
// decimal(Version) | "|" | Body. Signing over the raw body bytes (not a
// re-marshalled copy) avoids canonicalization ambiguity.
type signedBundle struct {
	Version int             `json:"version"`
	Body    json.RawMessage `json:"body"`
	Sig     string          `json:"sig"`
}

// canonicalMessage is the exact byte sequence that is signed and verified.
func canonicalMessage(version int, body []byte) []byte {
	return append([]byte(strconv.Itoa(version)+"|"), body...)
}

// Loader fetches, verifies, caches and hot-reloads the signed policy bundle. The
// current bundle is held in an atomic.Pointer so that Current() and any Engine
// reading through it are lock-free on the hot path. A reload only swaps the
// cache for a validly-signed bundle whose version is strictly greater than the
// one currently held; any failure (fetch error, bad signature, malformed JSON)
// leaves the existing cache untouched.
type Loader struct {
	fetcher Fetcher
	pub     ed25519.PublicKey
	cur     atomic.Pointer[CompiledBundle]
}

// NewLoader returns a Loader that fetches via f and verifies signatures with pub.
// No fetch is performed until Reload or Watch is called; Current returns the zero
// CompiledBundle until then.
func NewLoader(f Fetcher, pub ed25519.PublicKey) *Loader {
	return &Loader{fetcher: f, pub: pub}
}

// Current returns the latest verified bundle, or the zero CompiledBundle if none
// has been loaded yet. Lock-free.
func (l *Loader) Current() CompiledBundle {
	if p := l.cur.Load(); p != nil {
		return *p
	}
	return CompiledBundle{}
}

// Reload fetches the signed bundle, verifies its signature, and atomically swaps
// it into the cache if its version is strictly greater than the current one.
// On any error the cache is preserved and the error is returned. A validly-signed
// bundle whose version is not newer is a successful no-op (nil error).
func (l *Loader) Reload(ctx context.Context) error {
	raw, err := l.fetcher.Fetch(ctx)
	if err != nil {
		return fmt.Errorf("policy: fetch bundle: %w", err)
	}

	var env signedBundle
	if err := json.Unmarshal(raw, &env); err != nil {
		return fmt.Errorf("policy: decode signed envelope: %w", err)
	}

	sig, err := base64.StdEncoding.DecodeString(env.Sig)
	if err != nil {
		return fmt.Errorf("policy: decode signature: %w", err)
	}
	if !ed25519.Verify(l.pub, canonicalMessage(env.Version, env.Body), sig) {
		return errors.New("policy: bundle signature verification failed")
	}

	var bundle CompiledBundle
	if err := json.Unmarshal(env.Body, &bundle); err != nil {
		return fmt.Errorf("policy: decode bundle body: %w", err)
	}
	if bundle.Version != env.Version {
		return fmt.Errorf("policy: envelope version %d != body version %d", env.Version, bundle.Version)
	}

	if cur := l.cur.Load(); cur != nil && bundle.Version <= cur.Version {
		// Not newer than what we already have: keep the current cache.
		return nil
	}
	l.cur.Store(&bundle)
	return nil
}

// Watch polls the source every interval, calling Reload, until ctx is cancelled.
// Reload errors are swallowed (the cache is intentionally preserved on failure);
// a transient outage therefore does not disrupt evaluation. Watch performs an
// immediate first reload before entering the polling loop.
func (l *Loader) Watch(ctx context.Context, interval time.Duration) {
	_ = l.Reload(ctx)

	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			_ = l.Reload(ctx)
		}
	}
}

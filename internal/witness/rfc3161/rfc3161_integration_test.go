//go:build integration

// Live integration test for the RFC 3161 notary against a public timestamp
// authority. Requires outbound network.
//
//	go test -tags integration ./internal/witness/rfc3161/...
package rfc3161

import (
	"crypto/sha256"
	"testing"
)

// Public RFC 3161 TSAs to try, in order. They occasionally rate-limit, so we
// fall through to the next on failure.
var tsaEndpoints = []struct{ name, url string }{
	{"DigiCert", "http://timestamp.digicert.com"},
	{"FreeTSA", "https://freetsa.org/tsr"},
}

func TestRFC3161LiveRoundTrip(t *testing.T) {
	id := sha256.Sum256([]byte("multi-log checkpoint id"))
	other := sha256.Sum256([]byte("a different checkpoint id"))

	var lastErr error
	for _, ep := range tsaEndpoints {
		n := New(ep.name, ep.url)
		proof, err := n.Stamp(id[:])
		if err != nil {
			lastErr = err
			t.Logf("%s unavailable: %v", ep.name, err)
			continue
		}

		// The proof must verify against the stamped id...
		if err := n.Verify(proof, id[:]); err != nil {
			t.Fatalf("%s: valid proof failed to verify: %v", ep.name, err)
		}
		// ...and must NOT verify against any other id (this is what catches a
		// tampered checkpoint).
		if err := n.Verify(proof, other[:]); err == nil {
			t.Fatalf("%s: proof wrongly verified against a different id", ep.name)
		}
		t.Logf("%s: real RFC 3161 token obtained and verified (%d bytes)", ep.name, len(proof.Token))
		return
	}
	t.Skipf("no public TSA reachable: %v", lastErr)
}

//go:build integration

// Live integration test for the OpenTimestamps notary. Requires outbound
// network to the public calendar servers.
//
//	go test -tags integration ./internal/witness/opentimestamps/...
package opentimestamps

import (
	"crypto/sha256"
	"os"
	"testing"
)

func TestOTSLiveStampAndVerify(t *testing.T) {
	id := sha256.Sum256([]byte("multi-log checkpoint for OTS"))
	other := sha256.Sum256([]byte("a different checkpoint"))

	n := New("OpenTimestamps (Bitcoin)")
	proof, err := n.Stamp(id[:])
	if err != nil {
		t.Skipf("no OTS calendar reachable: %v", err)
	}
	t.Logf("got OTS proof: %d bytes", len(proof.Token))

	// Optionally dump the .ots so the reference `ots` CLI can validate interop.
	if out := os.Getenv("OTS_OUT"); out != "" {
		if err := os.WriteFile(out, proof.Token, 0o644); err != nil {
			t.Fatal(err)
		}
		t.Logf("wrote %s", out)
	}

	// The proof must verify against the stamped id...
	if err := n.Verify(proof, id[:]); err != nil {
		t.Fatalf("valid OTS proof failed to verify: %v", err)
	}
	// ...and must NOT verify against any other id.
	if err := n.Verify(proof, other[:]); err == nil {
		t.Fatal("OTS proof wrongly verified against a different id")
	}

	// A fresh proof is pending (Bitcoin confirmation takes hours).
	uris, err := n.PendingURIs(proof)
	if err != nil {
		t.Fatal(err)
	}
	if len(uris) == 0 {
		t.Fatal("expected at least one pending calendar URI on a fresh proof")
	}
	t.Logf("pending on %d calendar(s); Bitcoin attestation present=%v", len(uris), n.HasBitcoin(proof))
}

package opentimestamps

import (
	"bytes"
	"crypto/sha256"
	"testing"
)

func TestVaruintRoundTrip(t *testing.T) {
	for _, n := range []uint64{0, 1, 127, 128, 300, 16384, 1 << 20, 1<<32 + 7} {
		var buf bytes.Buffer
		writeVaruint(&buf, n)
		got, err := newReader(buf.Bytes()).varuint()
		if err != nil || got != n {
			t.Fatalf("varuint %d round-trip: got %d err %v", n, got, err)
		}
	}
}

// A linear proof (one op per node, ending in a pending attestation) must
// serialize and parse back identically — this is the shape calendars return.
func TestLinearTimestampRoundTrip(t *testing.T) {
	digest := sha256.Sum256([]byte("checkpoint"))
	leaf := &timestamp{msg: []byte("whatever")}
	leaf.attestations = append(leaf.attestations, attestation{tag: tagPending, uri: "https://alice.btc.calendar.opentimestamps.org"})
	mid := &timestamp{msg: []byte("mid"), ops: []opEdge{{o: op{tag: opSHA256}, child: leaf}}}
	root := &timestamp{msg: digest[:], ops: []opEdge{{o: op{tag: opAppend, arg: []byte("nonce-bytes-here")}, child: mid}}}

	var buf bytes.Buffer
	root.serialize(&buf)
	parsed, err := deserializeTimestamp(newReader(buf.Bytes()), digest[:])
	if err != nil {
		t.Fatal(err)
	}

	var buf2 bytes.Buffer
	parsed.serialize(&buf2)
	if !bytes.Equal(buf.Bytes(), buf2.Bytes()) {
		t.Fatal("linear timestamp did not round-trip identically")
	}
	atts := collect(parsed)
	if len(atts) != 1 || !atts[0].isPending() || atts[0].uri == "" {
		t.Fatalf("expected one pending attestation, got %+v", atts)
	}
}

// A fork (a node with multiple outgoing edges) exercises the 0xff marker.
func TestForkRoundTrip(t *testing.T) {
	digest := sha256.Sum256([]byte("x"))
	a1 := &timestamp{msg: []byte("a"), attestations: []attestation{{tag: tagPending, uri: "https://alice"}}}
	a2 := &timestamp{msg: []byte("b"), attestations: []attestation{{tag: tagBitcoin, height: 800000}}}
	root := &timestamp{msg: digest[:], ops: []opEdge{
		{o: op{tag: opAppend, arg: []byte{1, 2}}, child: a1},
		{o: op{tag: opPrepend, arg: []byte{3, 4}}, child: a2},
	}}

	var buf bytes.Buffer
	root.serialize(&buf)
	parsed, err := deserializeTimestamp(newReader(buf.Bytes()), digest[:])
	if err != nil {
		t.Fatal(err)
	}
	var buf2 bytes.Buffer
	parsed.serialize(&buf2)
	if !bytes.Equal(buf.Bytes(), buf2.Bytes()) {
		t.Fatal("fork did not round-trip identically")
	}

	atts := collect(parsed)
	if len(atts) != 2 {
		t.Fatalf("expected 2 attestations, got %d", len(atts))
	}
	_, btc, ok := findBitcoin(parsed)
	if !ok || btc.height != 800000 {
		t.Fatalf("expected bitcoin attestation at height 800000, got %v %d", ok, btc.height)
	}
}

func TestDetachedFileRoundTrip(t *testing.T) {
	digest := sha256.Sum256([]byte("the canonical checkpoint"))
	leaf := &timestamp{msg: []byte("l"), attestations: []attestation{{tag: tagPending, uri: "https://bob"}}}
	root := &timestamp{msg: digest[:], ops: []opEdge{{o: op{tag: opSHA256}, child: leaf}}}
	dtf := &detachedFile{fileHashOp: opSHA256, ts: root}

	b := dtf.serialize()
	parsed, err := parseDetachedFile(b)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(parsed.ts.msg, digest[:]) {
		t.Fatal("file digest did not survive round-trip")
	}
	if !bytes.Equal(parsed.serialize(), b) {
		t.Fatal("detached file did not round-trip identically")
	}
}

// op.apply must implement the transforms calendars rely on.
func TestOpApply(t *testing.T) {
	msg := []byte{0xaa, 0xbb}
	if got := (op{tag: opAppend, arg: []byte{0xcc}}).apply(msg); !bytes.Equal(got, []byte{0xaa, 0xbb, 0xcc}) {
		t.Fatalf("append: %x", got)
	}
	if got := (op{tag: opPrepend, arg: []byte{0xcc}}).apply(msg); !bytes.Equal(got, []byte{0xcc, 0xaa, 0xbb}) {
		t.Fatalf("prepend: %x", got)
	}
	want := sha256.Sum256(msg)
	if got := (op{tag: opSHA256}).apply(msg); !bytes.Equal(got, want[:]) {
		t.Fatalf("sha256: %x", got)
	}
}

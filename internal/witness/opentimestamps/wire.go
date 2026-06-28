// Package opentimestamps implements the OpenTimestamps Notary: it anchors a
// checkpoint id to the public Bitcoin chain via OTS calendar servers.
//
// This file implements the OpenTimestamps proof wire format (operations,
// attestations, the timestamp tree, and the detached-file envelope) so we can
// build standards-compliant .ots proofs and verify them. The format: a proof is
// a tree rooted at a digest; edges are operations (append/prepend/sha256/...)
// transforming the message, and leaves are attestations (a pending calendar URI
// or a Bitcoin block height). See https://opentimestamps.org.
package opentimestamps

import (
	"bytes"
	"crypto/sha1"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"

	"golang.org/x/crypto/ripemd160"
)

// Operation tags.
const (
	opAppend    = 0xf0
	opPrepend   = 0xf1
	opSHA1      = 0x02
	opRIPEMD160 = 0x03
	opSHA256    = 0x08
)

// Attestation tags (8-byte magic prefixes).
var (
	tagPending = []byte{0x83, 0xdf, 0xe3, 0x0d, 0x2e, 0xf9, 0x0c, 0x8e}
	tagBitcoin = []byte{0x05, 0x88, 0x96, 0x0d, 0x73, 0xd7, 0x19, 0x01}
)

// headerMagic prefixes a detached timestamp (.ots) file.
var headerMagic = []byte("\x00OpenTimestamps\x00\x00Proof\x00\xbf\x89\xe2\xe8\x84\xe8\x92\x94")

// op is one edge in the proof tree.
type op struct {
	tag byte
	arg []byte // append/prepend only
}

func (o op) apply(msg []byte) []byte {
	switch o.tag {
	case opAppend:
		return append(append([]byte{}, msg...), o.arg...)
	case opPrepend:
		return append(append([]byte{}, o.arg...), msg...)
	case opSHA256:
		s := sha256.Sum256(msg)
		return s[:]
	case opSHA1:
		s := sha1.Sum(msg)
		return s[:]
	case opRIPEMD160:
		h := ripemd160.New()
		h.Write(msg)
		return h.Sum(nil)
	default:
		return msg
	}
}

func (o op) serialize(buf *bytes.Buffer) {
	buf.WriteByte(o.tag)
	if o.tag == opAppend || o.tag == opPrepend {
		writeVarbytes(buf, o.arg)
	}
}

func deserializeOp(tag byte, r *reader) (op, error) {
	switch tag {
	case opAppend, opPrepend:
		arg, err := r.varbytes()
		if err != nil {
			return op{}, err
		}
		return op{tag: tag, arg: arg}, nil
	case opSHA1, opRIPEMD160, opSHA256:
		return op{tag: tag}, nil
	default:
		return op{}, fmt.Errorf("opentimestamps: unsupported op tag 0x%02x", tag)
	}
}

// attestation is a leaf of the proof tree.
type attestation struct {
	tag    []byte
	uri    string // pending
	height uint64 // bitcoin
	raw    []byte // unknown attestation body
}

func (a attestation) isPending() bool { return bytes.Equal(a.tag, tagPending) }
func (a attestation) isBitcoin() bool { return bytes.Equal(a.tag, tagBitcoin) }

func (a attestation) serialize(buf *bytes.Buffer) {
	buf.Write(a.tag)
	var body bytes.Buffer
	switch {
	case a.isPending():
		writeVarbytes(&body, []byte(a.uri))
	case a.isBitcoin():
		writeVaruint(&body, a.height)
	default:
		body.Write(a.raw)
	}
	writeVarbytes(buf, body.Bytes())
}

func deserializeAttestation(r *reader) (attestation, error) {
	tag, err := r.readN(8)
	if err != nil {
		return attestation{}, err
	}
	body, err := r.varbytes()
	if err != nil {
		return attestation{}, err
	}
	a := attestation{tag: tag}
	br := newReader(body)
	switch {
	case bytes.Equal(tag, tagPending):
		uri, err := br.varbytes()
		if err != nil {
			return attestation{}, err
		}
		a.uri = string(uri)
	case bytes.Equal(tag, tagBitcoin):
		h, err := br.varuint()
		if err != nil {
			return attestation{}, err
		}
		a.height = h
	default:
		a.raw = body
	}
	return a, nil
}

// opEdge is an operation and the subtree it leads to.
type opEdge struct {
	o     op
	child *timestamp
}

// timestamp is a node in the proof tree.
type timestamp struct {
	msg          []byte
	attestations []attestation
	ops          []opEdge
}

// serialize writes the tree. Every outgoing edge except the last is prefixed
// with 0xff; attestation edges are written as 0x00 + attestation.
func (t *timestamp) serialize(buf *bytes.Buffer) {
	total := len(t.attestations) + len(t.ops)
	i := 0
	for _, a := range t.attestations {
		if i < total-1 {
			buf.WriteByte(0xff)
		}
		buf.WriteByte(0x00)
		a.serialize(buf)
		i++
	}
	for _, e := range t.ops {
		if i < total-1 {
			buf.WriteByte(0xff)
		}
		e.o.serialize(buf)
		e.child.serialize(buf)
		i++
	}
}

func deserializeTimestamp(r *reader, msg []byte) (*timestamp, error) {
	t := &timestamp{msg: msg}
	one := func(tag byte) error {
		if tag == 0x00 {
			a, err := deserializeAttestation(r)
			if err != nil {
				return err
			}
			t.attestations = append(t.attestations, a)
			return nil
		}
		o, err := deserializeOp(tag, r)
		if err != nil {
			return err
		}
		child, err := deserializeTimestamp(r, o.apply(msg))
		if err != nil {
			return err
		}
		t.ops = append(t.ops, opEdge{o: o, child: child})
		return nil
	}
	tag, err := r.readByte()
	if err != nil {
		return nil, err
	}
	for tag == 0xff {
		next, err := r.readByte()
		if err != nil {
			return nil, err
		}
		if err := one(next); err != nil {
			return nil, err
		}
		tag, err = r.readByte()
		if err != nil {
			return nil, err
		}
	}
	if err := one(tag); err != nil {
		return nil, err
	}
	return t, nil
}

// detachedFile is the .ots envelope: header, version, file-hash op, digest, tree.
type detachedFile struct {
	fileHashOp byte
	ts         *timestamp
}

func (d *detachedFile) serialize() []byte {
	var buf bytes.Buffer
	buf.Write(headerMagic)
	writeVaruint(&buf, 1) // major version
	buf.WriteByte(d.fileHashOp)
	buf.Write(d.ts.msg) // the file digest
	d.ts.serialize(&buf)
	return buf.Bytes()
}

func parseDetachedFile(b []byte) (*detachedFile, error) {
	r := newReader(b)
	magic, err := r.readN(len(headerMagic))
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(magic, headerMagic) {
		return nil, errors.New("opentimestamps: bad .ots header magic")
	}
	if _, err := r.varuint(); err != nil { // version
		return nil, err
	}
	fileHashOp, err := r.readByte()
	if err != nil {
		return nil, err
	}
	if fileHashOp != opSHA256 {
		return nil, fmt.Errorf("opentimestamps: unsupported file hash op 0x%02x", fileHashOp)
	}
	digest, err := r.readN(32)
	if err != nil {
		return nil, err
	}
	ts, err := deserializeTimestamp(r, digest)
	if err != nil {
		return nil, err
	}
	return &detachedFile{fileHashOp: fileHashOp, ts: ts}, nil
}

// --- varint / varbytes / reader helpers ---

func writeVaruint(buf *bytes.Buffer, n uint64) {
	for n >= 0x80 {
		buf.WriteByte(byte(n&0x7f) | 0x80)
		n >>= 7
	}
	buf.WriteByte(byte(n))
}

func writeVarbytes(buf *bytes.Buffer, b []byte) {
	writeVaruint(buf, uint64(len(b)))
	buf.Write(b)
}

type reader struct{ r *bytes.Reader }

func newReader(b []byte) *reader { return &reader{r: bytes.NewReader(b)} }

func (rd *reader) readByte() (byte, error) { return rd.r.ReadByte() }

func (rd *reader) readN(n int) ([]byte, error) {
	out := make([]byte, n)
	if _, err := io.ReadFull(rd.r, out); err != nil {
		return nil, err
	}
	return out, nil
}

func (rd *reader) varuint() (uint64, error) {
	var result uint64
	var shift uint
	for {
		b, err := rd.r.ReadByte()
		if err != nil {
			return 0, err
		}
		result |= uint64(b&0x7f) << shift
		if b&0x80 == 0 {
			return result, nil
		}
		shift += 7
	}
}

func (rd *reader) varbytes() ([]byte, error) {
	n, err := rd.varuint()
	if err != nil {
		return nil, err
	}
	return rd.readN(int(n))
}

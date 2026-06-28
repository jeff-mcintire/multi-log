package opentimestamps

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"github.com/mythforge/multi-log/internal/witness"
)

// Notary anchors a checkpoint id to the Bitcoin chain via OTS calendar servers.
// Stamp returns a standards-compliant .ots proof; Verify confirms the proof is
// well-formed and binds to the given checkpoint id. Bitcoin confirmation is
// asynchronous (it takes hours), so a fresh proof is "pending" until Upgrade
// fetches the block attestation — but a pending proof already provides the
// binding our verifier needs.
type Notary struct {
	name      string
	calendars []string
	http      *http.Client
}

var _ witness.Notary = (*Notary)(nil)

// New builds a notary. With no calendars, the public defaults are used.
func New(name string, calendars ...string) *Notary {
	if len(calendars) == 0 {
		calendars = DefaultCalendars
	}
	return &Notary{name: name, calendars: calendars, http: httpClient()}
}

func (n *Notary) Name() string { return n.name }

// Stamp adds a privacy nonce to the checkpoint id, submits the resulting digest
// to the calendars, and assembles their partial proofs into one .ots tree.
func (n *Notary) Stamp(checkpointID []byte) (witness.Proof, error) {
	ctx := context.Background()

	nonce := make([]byte, 16)
	if _, err := rand.Read(nonce); err != nil {
		return witness.Proof{}, err
	}
	appended := append(append([]byte{}, checkpointID...), nonce...)
	sum := sha256.Sum256(appended)
	submitted := sum[:]

	submittedNode := &timestamp{msg: submitted}
	var ok bool
	var lastErr error
	for _, url := range n.calendars {
		calTS, err := newCalendar(url, n.http).submit(ctx, submitted)
		if err != nil {
			lastErr = err
			continue
		}
		submittedNode.attestations = append(submittedNode.attestations, calTS.attestations...)
		submittedNode.ops = append(submittedNode.ops, calTS.ops...)
		ok = true
	}
	if !ok {
		return witness.Proof{}, fmt.Errorf("opentimestamps: no calendar reachable: %w", lastErr)
	}

	// checkpointID --append(nonce)--> appended --sha256--> submitted --> calendars
	afterAppend := &timestamp{msg: appended, ops: []opEdge{{o: op{tag: opSHA256}, child: submittedNode}}}
	root := &timestamp{msg: checkpointID, ops: []opEdge{{o: op{tag: opAppend, arg: nonce}, child: afterAppend}}}
	dtf := &detachedFile{fileHashOp: opSHA256, ts: root}

	return witness.Proof{Notary: n.name, Format: "opentimestamps", Token: dtf.serialize()}, nil
}

// Verify confirms the proof is a well-formed OTS tree bound to checkpointID.
func (n *Notary) Verify(p witness.Proof, checkpointID []byte) error {
	dtf, err := parseDetachedFile(p.Token)
	if err != nil {
		return err
	}
	if !bytes.Equal(dtf.ts.msg, checkpointID) {
		return fmt.Errorf("opentimestamps: proof attests a different checkpoint id")
	}
	atts := collect(dtf.ts)
	if len(atts) == 0 {
		return fmt.Errorf("opentimestamps: proof contains no attestations")
	}
	return nil
}

// PendingURIs returns the calendar URIs of any pending (not-yet-Bitcoin) anchors.
func (n *Notary) PendingURIs(p witness.Proof) ([]string, error) {
	dtf, err := parseDetachedFile(p.Token)
	if err != nil {
		return nil, err
	}
	var uris []string
	for _, a := range collect(dtf.ts) {
		if a.isPending() {
			uris = append(uris, a.uri)
		}
	}
	return uris, nil
}

// HasBitcoin reports whether the proof already contains a Bitcoin attestation.
func (n *Notary) HasBitcoin(p witness.Proof) bool {
	dtf, err := parseDetachedFile(p.Token)
	if err != nil {
		return false
	}
	for _, a := range collect(dtf.ts) {
		if a.isBitcoin() {
			return true
		}
	}
	return false
}

// VerifyBitcoin checks any Bitcoin attestation against the real chain: the
// message at the attested node must equal the Merkle root of the Bitcoin block
// at the attested height. Requires network. Returns the verified height.
func (n *Notary) VerifyBitcoin(ctx context.Context, p witness.Proof, checkpointID []byte) (uint64, error) {
	if err := n.Verify(p, checkpointID); err != nil {
		return 0, err
	}
	dtf, _ := parseDetachedFile(p.Token)
	node, att, found := findBitcoin(dtf.ts)
	if !found {
		return 0, fmt.Errorf("opentimestamps: no Bitcoin attestation yet (still pending; run Upgrade later)")
	}
	root, err := bitcoinMerkleRoot(ctx, n.http, att.height)
	if err != nil {
		return 0, err
	}
	if !bytes.Equal(node.msg, root) {
		return 0, fmt.Errorf("opentimestamps: Bitcoin block %d merkle root does not match the proof", att.height)
	}
	return att.height, nil
}

// collect walks the tree and returns all attestations.
func collect(t *timestamp) []attestation {
	atts := append([]attestation{}, t.attestations...)
	for _, e := range t.ops {
		atts = append(atts, collect(e.child)...)
	}
	return atts
}

// findBitcoin returns the node holding a Bitcoin attestation (its msg is the
// attested Merkle root) and the attestation.
func findBitcoin(t *timestamp) (*timestamp, attestation, bool) {
	for _, a := range t.attestations {
		if a.isBitcoin() {
			return t, a, true
		}
	}
	for _, e := range t.ops {
		if node, a, ok := findBitcoin(e.child); ok {
			return node, a, true
		}
	}
	return nil, attestation{}, false
}

// bitcoinMerkleRoot fetches the Merkle root of a block by height (internal byte
// order, matching the OTS attested message) via the Blockstream Esplora API.
func bitcoinMerkleRoot(ctx context.Context, client *http.Client, height uint64) ([]byte, error) {
	hash, err := esploraGet(ctx, client, fmt.Sprintf("https://blockstream.info/api/block-height/%d", height))
	if err != nil {
		return nil, err
	}
	body, err := esploraGet(ctx, client, fmt.Sprintf("https://blockstream.info/api/block/%s", string(bytes.TrimSpace(hash))))
	if err != nil {
		return nil, err
	}
	var blk struct {
		MerkleRoot string `json:"merkle_root"`
	}
	if err := json.Unmarshal(body, &blk); err != nil {
		return nil, err
	}
	disp, err := hex.DecodeString(blk.MerkleRoot)
	if err != nil {
		return nil, err
	}
	return reverseBytes(disp), nil // explorer shows big-endian; OTS uses internal order
}

func esploraGet(ctx context.Context, client *http.Client, url string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<16))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("opentimestamps: explorer %s returned %d", url, resp.StatusCode)
	}
	return body, nil
}

func reverseBytes(b []byte) []byte {
	out := make([]byte, len(b))
	for i := range b {
		out[len(b)-1-i] = b[i]
	}
	return out
}

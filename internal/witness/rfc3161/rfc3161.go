// Package rfc3161 implements a Notary backed by an RFC 3161 timestamp authority.
//
// The TSA signs a token attesting that a given hash (here, a checkpoint id)
// existed at a point in time. The token is signed with the TSA's private key, so
// although we store it ourselves, an insider cannot forge a token binding a
// different checkpoint id — that is the independence we need. In production, pin
// the TSA's certificate and verify the token's chain to it; this notary verifies
// the token's integrity and that it attests exactly our checkpoint id.
package rfc3161

import (
	"bytes"
	"context"
	"crypto"
	_ "crypto/sha256" // register SHA-256 for the timestamp library
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/digitorus/timestamp"

	"github.com/mythforge/multi-log/internal/witness"
)

// Notary talks to a single RFC 3161 TSA endpoint (e.g. https://freetsa.org/tsr).
type Notary struct {
	name string
	url  string
	http *http.Client
}

var _ witness.Notary = (*Notary)(nil)

func New(name, url string) *Notary {
	return &Notary{name: name, url: url, http: &http.Client{Timeout: 30 * time.Second}}
}

func (n *Notary) Name() string { return n.name }

// Stamp builds an RFC 3161 request over the checkpoint id, sends it to the TSA,
// and returns the signed timestamp response as the proof token.
func (n *Notary) Stamp(checkpointID []byte) (witness.Proof, error) {
	req := timestamp.Request{
		HashAlgorithm: crypto.SHA256,
		HashedMessage: checkpointID,
		Certificates:  true, // ask the TSA to embed its cert chain in the token
	}
	der, err := req.Marshal()
	if err != nil {
		return witness.Proof{}, fmt.Errorf("rfc3161: marshal request: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(context.Background(), http.MethodPost, n.url, bytes.NewReader(der))
	if err != nil {
		return witness.Proof{}, err
	}
	httpReq.Header.Set("Content-Type", "application/timestamp-query")
	httpReq.Header.Set("Accept", "application/timestamp-reply")

	resp, err := n.http.Do(httpReq)
	if err != nil {
		return witness.Proof{}, fmt.Errorf("rfc3161: request to %s: %w", n.url, err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return witness.Proof{}, err
	}
	if resp.StatusCode != http.StatusOK {
		return witness.Proof{}, fmt.Errorf("rfc3161: TSA returned %d: %s", resp.StatusCode, string(body))
	}

	// Confirm the token is well-formed and attests our id before keeping it.
	if _, err := parseAndCheck(body, checkpointID); err != nil {
		return witness.Proof{}, err
	}
	return witness.Proof{Notary: n.name, Format: "rfc3161", Token: body}, nil
}

// Verify parses the stored token, validates its signature (ParseResponse rejects
// a tampered token), and confirms it attests exactly the given checkpoint id.
func (n *Notary) Verify(p witness.Proof, checkpointID []byte) error {
	_, err := parseAndCheck(p.Token, checkpointID)
	return err
}

func parseAndCheck(token, checkpointID []byte) (*timestamp.Timestamp, error) {
	ts, err := timestamp.ParseResponse(token)
	if err != nil {
		return nil, fmt.Errorf("rfc3161: parse/verify token: %w", err)
	}
	if ts.HashAlgorithm != crypto.SHA256 {
		return nil, fmt.Errorf("rfc3161: unexpected hash algorithm %v", ts.HashAlgorithm)
	}
	if !bytes.Equal(ts.HashedMessage, checkpointID) {
		return nil, fmt.Errorf("rfc3161: token attests a different checkpoint id")
	}
	return ts, nil
}

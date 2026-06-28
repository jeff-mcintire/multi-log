package opentimestamps

import (
	"bytes"
	"context"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"time"
)

// DefaultCalendars are the public OpenTimestamps calendar servers.
var DefaultCalendars = []string{
	"https://alice.btc.calendar.opentimestamps.org",
	"https://bob.btc.calendar.opentimestamps.org",
	"https://finney.calendar.opentimestamps.org",
}

type calendar struct {
	url  string
	http *http.Client
}

func newCalendar(url string, client *http.Client) *calendar {
	return &calendar{url: url, http: client}
}

// submit posts a digest to the calendar and returns the partial timestamp proof
// rooted at that digest (serialized bytes, not wrapped in a .ots header).
func (c *calendar) submit(ctx context.Context, digest []byte) (*timestamp, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.url+"/digest", bytes.NewReader(digest))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/octet-stream")
	req.Header.Set("Accept", "application/octet-stream")
	body, err := c.do(req)
	if err != nil {
		return nil, err
	}
	return deserializeTimestamp(newReader(body), digest)
}

// upgrade fetches the (possibly Bitcoin-anchored) timestamp for a commitment.
func (c *calendar) upgrade(ctx context.Context, commitment []byte) (*timestamp, error) {
	url := c.url + "/timestamp/" + hex.EncodeToString(commitment)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/octet-stream")
	body, err := c.do(req)
	if err != nil {
		return nil, err
	}
	return deserializeTimestamp(newReader(body), commitment)
}

func (c *calendar) do(req *http.Request) ([]byte, error) {
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("opentimestamps: %s: %w", c.url, err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("opentimestamps: %s returned %d: %s", c.url, resp.StatusCode, string(body))
	}
	return body, nil
}

func httpClient() *http.Client { return &http.Client{Timeout: 30 * time.Second} }

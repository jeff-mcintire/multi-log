// Package witnessbuild constructs the witnesses (WORM store + notaries) from the
// environment. The anchorer and verifier both call it so they agree on witness
// names and — for the offline mock notaries — secrets. In real mode the notaries
// are self-verifying (RFC 3161 cert / OpenTimestamps), so no shared secret.
package witnessbuild

import (
	"context"
	"time"

	"github.com/mythforge/multi-log/internal/config"
	"github.com/mythforge/multi-log/internal/witness"
	"github.com/mythforge/multi-log/internal/witness/opentimestamps"
	"github.com/mythforge/multi-log/internal/witness/rfc3161"
	"github.com/mythforge/multi-log/internal/witness/s3worm"
)

// Stable witness names, shared by anchorer (Stamp) and verifier (Verify).
const (
	TSAName = "RFC 3161 TSA"
	OTSName = "OpenTimestamps (Bitcoin)"
)

// WORM builds the S3 Object Lock CheckpointStore and ensures its bucket exists.
func WORM(ctx context.Context) (witness.CheckpointStore, error) {
	retain := 24 * time.Hour
	if d, err := time.ParseDuration(config.Env("WORM_RETAIN", "")); err == nil && d > 0 {
		retain = d
	}
	st := s3worm.New(s3worm.Config{
		Region:       config.Env("S3_REGION", "us-east-1"),
		Bucket:       config.Env("S3_BUCKET", "multilog-worm"),
		AccessKey:    config.Env("S3_ACCESS_KEY", "minioadmin"),
		SecretKey:    config.Env("S3_SECRET_KEY", "minioadmin"),
		Endpoint:     config.Env("S3_ENDPOINT", "http://localhost:9100"),
		UsePathStyle: true,
		RetainFor:    retain,
	})
	if err := st.EnsureBucket(ctx); err != nil {
		return nil, err
	}
	return st, nil
}

// Notaries builds the two timestamp notaries. NOTARY_MODE=real uses the live
// RFC 3161 TSA and OpenTimestamps; the default "mock" uses HMAC stand-ins so the
// stack runs fully offline and deterministically.
func Notaries() []witness.Notary {
	if config.Env("NOTARY_MODE", "mock") == "real" {
		return []witness.Notary{
			rfc3161.New(TSAName, config.Env("TSA_URL", "http://timestamp.digicert.com")),
			opentimestamps.New(OTSName),
		}
	}
	return []witness.Notary{
		witness.NewMockNotary(TSAName, config.Env("NOTARY_TSA_SECRET", "tsa-demo-secret")),
		witness.NewMockNotary(OTSName, config.Env("NOTARY_OTS_SECRET", "ots-demo-secret")),
	}
}

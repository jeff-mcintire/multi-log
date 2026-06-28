//go:build integration

// Integration test for the S3 Object Lock WORM store, run against MinIO.
//
//	docker run -d -p 9100:9000 -e MINIO_ROOT_USER=minioadmin \
//	  -e MINIO_ROOT_PASSWORD=minioadmin minio/minio server /data
//	go test -tags integration ./internal/witness/s3worm/...
package s3worm

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/smithy-go"

	"github.com/mythforge/multi-log/internal/chain"
	"github.com/mythforge/multi-log/internal/checkpoint"
	"github.com/mythforge/multi-log/internal/witness"
)

func testConfig() Config {
	return Config{
		Region:       "us-east-1",
		Bucket:       "multilog-worm-test",
		AccessKey:    "minioadmin",
		SecretKey:    "minioadmin",
		Endpoint:     "http://localhost:9100",
		UsePathStyle: true,
		RetainFor:    2 * time.Hour,
	}
}

func sampleCheckpoint(tenant string) checkpoint.Checkpoint {
	store := chain.NewStore()
	sealer := chain.NewSealer(store)
	for i := 0; i < 3; i++ {
		sealer.Seal(tenant, "api", fmt.Sprintf("line %d", i), int64(i), int64(i))
	}
	return checkpoint.Build(tenant, store.Tenant(tenant), nil, 1)
}

func TestS3ObjectLockWORM(t *testing.T) {
	st := New(testConfig())
	ctx := context.Background()
	if err := st.EnsureBucket(ctx); err != nil {
		t.Fatalf("EnsureBucket (is MinIO up on :9100?): %v", err)
	}

	// Unique tenant per run so repeated runs don't collide with locked objects.
	tenant := fmt.Sprintf("acme-%d", time.Now().UnixNano())
	cp := sampleCheckpoint(tenant)

	// 1. Put, then read it back intact.
	if err := st.Put(cp); err != nil {
		t.Fatalf("Put: %v", err)
	}
	got, ok, err := st.Get(tenant, cp.SeqEnd)
	if err != nil || !ok {
		t.Fatalf("Get: ok=%v err=%v", ok, err)
	}
	if string(got.CheckpointID) != string(cp.CheckpointID) {
		t.Fatal("round-tripped checkpoint id does not match")
	}
	if got.EntryCount != cp.EntryCount {
		t.Fatalf("entry count mismatch: got %d want %d", got.EntryCount, cp.EntryCount)
	}

	// 2. Application-level immutability: a second Put is refused.
	if err := st.Put(cp); !errors.Is(err, witness.ErrImmutable) {
		t.Fatalf("expected ErrImmutable on overwrite, got %v", err)
	}

	// 3. Platform-level immutability: the COMPLIANCE retention lock must prevent
	//    deletion of the written version — even with full S3 credentials.
	client := rawClient()
	versionID := firstVersionID(t, client, tenant, cp.SeqEnd)
	_, delErr := client.DeleteObject(ctx, &s3.DeleteObjectInput{
		Bucket:    aws.String(testConfig().Bucket),
		Key:       aws.String(key(tenant, cp.SeqEnd)),
		VersionId: aws.String(versionID),
	})
	if delErr == nil {
		t.Fatal("expected Object Lock to block deletion of the locked version, but delete succeeded")
	}
	var apiErr smithy.APIError
	if !errors.As(delErr, &apiErr) {
		t.Fatalf("expected an S3 API error blocking deletion, got %v", delErr)
	}
	t.Logf("deletion correctly blocked by Object Lock: %s", apiErr.ErrorCode())

	// 4. All lists the anchored checkpoint.
	all, err := st.All(tenant)
	if err != nil {
		t.Fatalf("All: %v", err)
	}
	if len(all) != 1 || all[0].SeqEnd != cp.SeqEnd {
		t.Fatalf("All returned %d checkpoints, want 1", len(all))
	}
}

func rawClient() *s3.Client {
	cfg := testConfig()
	return s3.NewFromConfig(aws.Config{
		Region:      cfg.Region,
		Credentials: credentials.NewStaticCredentialsProvider(cfg.AccessKey, cfg.SecretKey, ""),
	}, func(o *s3.Options) {
		o.BaseEndpoint = aws.String(cfg.Endpoint)
		o.UsePathStyle = true
	})
}

func firstVersionID(t *testing.T, client *s3.Client, tenant string, seqEnd uint64) string {
	t.Helper()
	out, err := client.ListObjectVersions(context.Background(), &s3.ListObjectVersionsInput{
		Bucket: aws.String(testConfig().Bucket),
		Prefix: aws.String(key(tenant, seqEnd)),
	})
	if err != nil {
		t.Fatalf("ListObjectVersions: %v", err)
	}
	if len(out.Versions) == 0 {
		t.Fatal("no object versions found")
	}
	return aws.ToString(out.Versions[0].VersionId)
}

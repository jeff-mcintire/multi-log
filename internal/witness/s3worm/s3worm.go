// Package s3worm implements the WORM CheckpointStore backed by S3 Object Lock.
//
// With Object Lock in COMPLIANCE mode, a written object version cannot be
// deleted or altered by anyone — not even the AWS root account — until its
// retention period expires. Run the bucket in an isolated AWS account whose IAM
// is unreachable from the application's runtime role, and this is the anchor an
// insider with full database access cannot rewrite. Works unchanged against
// MinIO, which implements the same Object Lock semantics for local testing.
package s3worm

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"sort"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	s3types "github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/aws/smithy-go"

	"github.com/mythforge/multi-log/internal/checkpoint"
	"github.com/mythforge/multi-log/internal/witness"
)

// Config configures the store. Endpoint/UsePathStyle are for S3-compatible
// servers such as MinIO; leave Endpoint empty for real AWS.
type Config struct {
	Region       string
	Bucket       string
	AccessKey    string
	SecretKey    string
	Endpoint     string // e.g. http://localhost:9100 for MinIO; "" for AWS
	UsePathStyle bool
	RetainFor    time.Duration // Object Lock retention applied to each checkpoint
}

// Store is an S3 Object Lock-backed CheckpointStore.
type Store struct {
	client    *s3.Client
	bucket    string
	retainFor time.Duration
}

var _ witness.CheckpointStore = (*Store)(nil)

// New builds the client. It does not create the bucket; call EnsureBucket once.
func New(cfg Config) *Store {
	client := s3.NewFromConfig(aws.Config{
		Region:      cfg.Region,
		Credentials: credentials.NewStaticCredentialsProvider(cfg.AccessKey, cfg.SecretKey, ""),
	}, func(o *s3.Options) {
		if cfg.Endpoint != "" {
			o.BaseEndpoint = aws.String(cfg.Endpoint)
		}
		o.UsePathStyle = cfg.UsePathStyle
	})
	retain := cfg.RetainFor
	if retain == 0 {
		retain = 365 * 24 * time.Hour
	}
	return &Store{client: client, bucket: cfg.Bucket, retainFor: retain}
}

func (s *Store) Name() string { return "S3 Object Lock (WORM)" }

// EnsureBucket creates the bucket with Object Lock enabled if it does not exist.
// Object Lock can only be enabled at creation time and requires versioning,
// which S3 enables automatically. (Real AWS outside us-east-1 also needs a
// LocationConstraint; us-east-1 and MinIO do not.)
func (s *Store) EnsureBucket(ctx context.Context) error {
	_, err := s.client.HeadBucket(ctx, &s3.HeadBucketInput{Bucket: aws.String(s.bucket)})
	if err == nil {
		return nil
	}
	_, err = s.client.CreateBucket(ctx, &s3.CreateBucketInput{
		Bucket:                     aws.String(s.bucket),
		ObjectLockEnabledForBucket: aws.Bool(true),
	})
	return err
}

func key(tenantID string, seqEnd uint64) string {
	return fmt.Sprintf("%s/checkpoints/%020d.json", tenantID, seqEnd)
}

// Put writes the checkpoint under a COMPLIANCE-mode retention lock. It first
// refuses an application-level overwrite; the lock then guarantees the written
// version is immutable regardless of any later attempt.
func (s *Store) Put(cp checkpoint.Checkpoint) error {
	ctx := context.Background()
	k := key(cp.TenantID, cp.SeqEnd)

	if _, ok, err := s.Get(cp.TenantID, cp.SeqEnd); err != nil {
		return err
	} else if ok {
		return witness.ErrImmutable
	}

	body, err := checkpoint.Marshal(cp)
	if err != nil {
		return err
	}
	retainUntil := time.Now().Add(s.retainFor)
	_, err = s.client.PutObject(ctx, &s3.PutObjectInput{
		Bucket:                    aws.String(s.bucket),
		Key:                       aws.String(k),
		Body:                      bytes.NewReader(body),
		ContentType:               aws.String("application/json"),
		ObjectLockMode:            s3types.ObjectLockModeCompliance,
		ObjectLockRetainUntilDate: aws.Time(retainUntil),
	})
	return err
}

func (s *Store) Get(tenantID string, seqEnd uint64) (checkpoint.Checkpoint, bool, error) {
	ctx := context.Background()
	out, err := s.client.GetObject(ctx, &s3.GetObjectInput{
		Bucket: aws.String(s.bucket),
		Key:    aws.String(key(tenantID, seqEnd)),
	})
	if err != nil {
		if isNotFound(err) {
			return checkpoint.Checkpoint{}, false, nil
		}
		return checkpoint.Checkpoint{}, false, err
	}
	defer out.Body.Close()
	data, err := io.ReadAll(out.Body)
	if err != nil {
		return checkpoint.Checkpoint{}, false, err
	}
	cp, err := checkpoint.Unmarshal(data)
	if err != nil {
		return checkpoint.Checkpoint{}, false, err
	}
	return cp, true, nil
}

func (s *Store) All(tenantID string) ([]checkpoint.Checkpoint, error) {
	ctx := context.Background()
	prefix := tenantID + "/checkpoints/"
	var cps []checkpoint.Checkpoint
	p := s3.NewListObjectsV2Paginator(s.client, &s3.ListObjectsV2Input{
		Bucket: aws.String(s.bucket),
		Prefix: aws.String(prefix),
	})
	for p.HasMorePages() {
		page, err := p.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		for _, obj := range page.Contents {
			out, err := s.client.GetObject(ctx, &s3.GetObjectInput{
				Bucket: aws.String(s.bucket),
				Key:    obj.Key,
			})
			if err != nil {
				return nil, err
			}
			data, err := io.ReadAll(out.Body)
			out.Body.Close()
			if err != nil {
				return nil, err
			}
			cp, err := checkpoint.Unmarshal(data)
			if err != nil {
				return nil, err
			}
			cps = append(cps, cp)
		}
	}
	sort.Slice(cps, func(i, j int) bool { return cps[i].SeqEnd < cps[j].SeqEnd })
	return cps, nil
}

func isNotFound(err error) bool {
	var apiErr smithy.APIError
	if errors.As(err, &apiErr) {
		switch apiErr.ErrorCode() {
		case "NotFound", "NoSuchKey":
			return true
		}
	}
	return false
}

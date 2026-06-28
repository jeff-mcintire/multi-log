# multi-log

A multi-tenant, multi-source, **tamper-evident** log aggregation system.

Logs are made provably immutable not with a blockchain, but with the mechanism a
blockchain would use internally: a per-tenant **hash chain** plus periodic
**Merkle-root checkpoints** that are **anchored to independent witnesses**. The
security comes from anchoring each checkpoint somewhere an insider can't rewrite
— not from the chain alone.

See the full design and phased plan in
`~/.claude/plans/hi-claude-could-you-joyful-eclipse.md`.

## What's built

The **immutability core** — the novel, highest-risk part of the system — with
**real witness backends**:

| Witness | Role | Backend |
|---------|------|---------|
| WORM store | durably **stores** the checkpoint object, immutably | **S3 Object Lock** (COMPLIANCE mode) — real, via AWS SDK v2 |
| Timestamp authority | **attests** the checkpoint id with a signed token | **RFC 3161** — real, talks to any TSA |
| Public chain | **attests** the checkpoint id, anchored publicly | OpenTimestamps — *interface ready, client is the next piece* |

The two kinds aren't symmetric: WORM stores the object; a notary returns a
self-verifying proof you keep. Three independent witnesses = one WORM store + two
notaries.

## Run it

```bash
go run ./cmd/demo   # walkthrough: clean verify, then 3 tamper scenarios caught
go test ./...       # hermetic unit tests (no network, no docker)
```

The demo (in-memory witnesses, zero dependencies) shows three attacks:

1. **Naive edit** — rewrite a row, leave the chain → caught by chain replay.
2. **Sophisticated edit** — rewrite a row *and* recompute the whole chain so it's
   self-consistent → caught three ways: the WORM record and *both* notary proofs
   disagree with the rebuilt checkpoint.
3. **Tail truncation** — delete the most recent entry (no sequence gap) → caught
   because the checkpoint commits to an entry count.

### Integration tests (real backends)

```bash
docker compose -f deploy/docker-compose.yml up -d   # MinIO for S3 Object Lock
go test -tags integration ./...                     # MinIO + a public TSA
```

- `s3worm` test proves the WORM property end-to-end: the checkpoint round-trips,
  overwrites are refused, and deleting the locked object version is **blocked by
  Object Lock even with full credentials**.
- `rfc3161` test obtains a **real signed timestamp token** from a public TSA
  (DigiCert), verifies it attests our checkpoint id, and confirms it does *not*
  verify against any other id.

## Layout

| Path | Role | Production mapping |
|------|------|--------------------|
| `internal/crypto/canonical.go` | Canonical, versioned encoding + hashing — the keystone | same |
| `internal/chain/` | Log store + single-writer-per-tenant **sealer** | ClickHouse + sealer service |
| `internal/checkpoint/` | Merkle tree + **checkpoint** builder + JSON codec | anchorer service |
| `internal/witness/` | `CheckpointStore` + `Notary` interfaces; in-memory + mock impls | — |
| `internal/witness/s3worm/` | **S3 Object Lock** WORM store (AWS SDK v2) | S3, isolated account |
| `internal/witness/rfc3161/` | **RFC 3161** timestamp notary | a TSA |
| `internal/verify/` | Recompute everything; match WORM + notary proofs | verifier service + customer CLI |
| `cmd/demo/` | Wires it together and runs the tamper scenarios | — |
| `deploy/docker-compose.yml` | Local infra (MinIO now; full stack in Phase 1) | — |

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
| Public chain | **attests** the checkpoint id, anchored to Bitcoin | **OpenTimestamps** — real client; proofs validate in the official `ots` CLI |

The two kinds aren't symmetric: WORM stores the object; a notary returns a
self-verifying proof you keep. Three independent witnesses = one WORM store + two
notaries.

## Phase 1 — the data plane

A multi-tenant, multi-source pipeline: agents ship logs → the gateway
authenticates and seals them → ClickHouse stores them → the query API and Grafana
read them back, strictly scoped per tenant.

```
Vector ─▶ gateway (X-API-Key → tenant, seal, seq+hash) ─▶ ClickHouse
                              ▲                                  │
        control plane (tenants + API keys, Postgres)            ▼
                                              queryproxy / Grafana (tenant-scoped)
```

Run the whole stack:

```bash
docker compose -f deploy/docker-compose.yml up -d --build
./scripts/bootstrap.sh                 # creates a tenant, prints an API key

export MULTILOG_API_KEY=mlog_...        # from bootstrap
curl -s -X POST localhost:8080/ingest -H "X-API-Key: $MULTILOG_API_KEY" \
  -d '[{"source":"api","message":"hello multi-log"}]'
curl -s "localhost:8082/logs?q=hello" -H "X-API-Key: $MULTILOG_API_KEY"
```

- **Grafana** at <http://localhost:3000> (anonymous admin) with a provisioned
  ClickHouse datasource, a logs dashboard, and a sample alert rule.
- **Vector** (the agent path) ships sample logs once you set the key:
  `MULTILOG_API_KEY=mlog_... docker compose -f deploy/docker-compose.yml --profile agents up -d vector`.

Tenant isolation is enforced in the query API: a key resolves to exactly one
tenant, and every query is bound to that tenant id — there is no cross-tenant
read path.

## Phase 2 — anchoring + continuous verification

The data plane and the immutability core are wired together by two services:

```
ClickHouse ─▶ anchorer (per-tenant checkpoints) ─▶ WORM (S3 Object Lock)
                       │                          ├▶ RFC 3161 TSA   ┐ proofs
                       │                          └▶ OpenTimestamps ┘ kept in Postgres
                       ▼
                 verifier ◀── reloads ClickHouse, matches against WORM + notary proofs
                 GET /verify (on demand) + scheduled sweep (alerts on mismatch)
```

- **anchorer** (`cmd/anchorer`, port 8083): on a cadence (and via `POST /anchor`),
  it reads entries sealed since each tenant's last checkpoint, batches them into
  windows, writes each checkpoint to the WORM store + a Postgres working copy, and
  stamps its id with every notary. Checkpoints chain and commit to entry counts.
- **verifier** (`cmd/verifier`, port 8084): `GET /verify` reloads the chain from
  ClickHouse, loads the proofs we hold, and matches everything against the WORM
  record and the notaries — returning `409` with pinpointed issues on any
  mismatch. A scheduled sweep logs an alert when tampering is detected.

`NOTARY_MODE=mock` (default) keeps the stack fully offline and deterministic; set
it to `real` to use a live RFC 3161 TSA and OpenTimestamps.

The Phase 2 integration test (`internal/dataplane/phase2_e2e_test.go`) seals →
anchors → verifies, then tampers the **actual ClickHouse rows** and proves
detection: a naive edit (chain), a sophisticated edit that also recomputes the
chain (WORM + both notary proofs disagree), and a tail truncation (committed
count). Run it with the infra up:

```bash
docker compose -f deploy/docker-compose.yml up -d clickhouse postgres minio
go test -tags integration -run TestPhase2 ./internal/dataplane/...
```

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
- `opentimestamps` test stamps a checkpoint id against the **public OTS calendar
  servers**, gets a real `.ots` proof, verifies it binds to the id, and rejects
  any other id. The proof is standards-compliant — the official `ots info` CLI
  parses it. Bitcoin confirmation is asynchronous (hours); `VerifyBitcoin` checks
  an upgraded proof's Merkle root against the real chain via a block explorer.

## Layout

| Path | Role | Production mapping |
|------|------|--------------------|
| `internal/crypto/canonical.go` | Canonical, versioned encoding + hashing — the keystone | same |
| `internal/chain/` | Log store + single-writer-per-tenant **sealer** | ClickHouse + sealer service |
| `internal/checkpoint/` | Merkle tree + **checkpoint** builder + JSON codec | anchorer service |
| `internal/witness/` | `CheckpointStore` + `Notary` interfaces; in-memory + mock impls | — |
| `internal/witness/s3worm/` | **S3 Object Lock** WORM store (AWS SDK v2) | S3, isolated account |
| `internal/witness/rfc3161/` | **RFC 3161** timestamp notary | a TSA |
| `internal/witness/opentimestamps/` | **OpenTimestamps** notary + `.ots` wire codec | public calendars + Bitcoin |
| `internal/verify/` | Recompute everything; match WORM + notary proofs | verifier service + customer CLI |
| `internal/logstore/` | ClickHouse log store: schema, batch append, tenant-scoped search | ClickHouse |
| `internal/control/` | Postgres control plane: tenants + hashed API keys | Postgres |
| `internal/ingest/` | Persistent sealer + ingest gateway handler | gateway service |
| `internal/queryapi/` | Tenant-scoped read API | queryproxy service |
| `internal/anchorstore/` | Postgres working copy of checkpoints + notary proofs | Postgres |
| `internal/anchor/` | Builds + anchors per-tenant checkpoints to the witnesses | anchorer service |
| `internal/verifylive/` | Reloads ClickHouse + proofs, runs verification | verifier service |
| `internal/witnessbuild/` | Builds WORM + notaries from env (shared by both) | — |
| `cmd/gateway`, `cmd/controlplane`, `cmd/queryproxy` | Phase 1 service binaries | — |
| `cmd/anchorer`, `cmd/verifier` | Phase 2 service binaries | — |
| `cmd/demo/` | Wires it together and runs the tamper scenarios | — |
| `deploy/docker-compose.yml` | Full local stack (infra + all services) | — |

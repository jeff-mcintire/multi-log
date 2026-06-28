// Command demo is a self-contained walkthrough of multi-log's immutability core.
// It seals logs for two tenants, anchors each Merkle checkpoint to a WORM store
// and two notaries, verifies cleanly, then runs three tampering scenarios and
// shows the verifier catching each one — including a sophisticated insider who
// edits a row AND recomputes the whole hash chain.
//
// This demo uses in-memory witness stand-ins so it runs with no dependencies.
// The real backends (S3 Object Lock, RFC 3161) live in internal/witness/s3worm
// and internal/witness/rfc3161 and satisfy the same interfaces.
//
// Run with: go run ./cmd/demo
package main

import (
	"fmt"
	"strings"

	"github.com/mythforge/multi-log/internal/chain"
	"github.com/mythforge/multi-log/internal/checkpoint"
	"github.com/mythforge/multi-log/internal/crypto"
	"github.com/mythforge/multi-log/internal/verify"
	"github.com/mythforge/multi-log/internal/witness"
)

const (
	green = "\033[32m"
	red   = "\033[31m"
	dim   = "\033[2m"
	bold  = "\033[1m"
	reset = "\033[0m"
)

const windowSize = 6

// baseTime is a fixed epoch so the demo is fully deterministic.
const baseTime int64 = 1_700_000_000_000_000_000

var sampleLogs = map[string][]struct{ source, raw string }{
	"acme-corp": {
		{"api", `{"lvl":"info","msg":"user login","user":"alice","ip":"10.0.0.4"}`},
		{"api", `{"lvl":"info","msg":"user login","user":"bob","ip":"10.0.0.9"}`},
		{"authz", `{"lvl":"warn","msg":"permission denied","user":"bob","res":"billing"}`},
		{"api", `{"lvl":"info","msg":"invoice created","id":"INV-1001","amt":4200}`},
		{"authz", `{"lvl":"alert","msg":"admin role granted","by":"alice","to":"carol"}`},
		{"api", `{"lvl":"info","msg":"export started","user":"carol","rows":50000}`},
		{"k8s", `{"lvl":"info","msg":"pod scheduled","pod":"api-7f9","node":"node-2"}`},
		{"authz", `{"lvl":"alert","msg":"unauthorized access attempt","user":"mallory","res":"secrets"}`},
		{"api", `{"lvl":"info","msg":"payment captured","id":"PAY-77","amt":4200}`},
		{"k8s", `{"lvl":"warn","msg":"OOMKilled","pod":"worker-3","node":"node-1"}`},
		{"api", `{"lvl":"info","msg":"user logout","user":"alice"}`},
		{"authz", `{"lvl":"info","msg":"api key rotated","user":"carol"}`},
	},
	"globex": {
		{"app", `{"lvl":"info","msg":"order placed","order":"G-501","total":120}`},
		{"app", `{"lvl":"error","msg":"payment gateway timeout","order":"G-501"}`},
		{"app", `{"lvl":"info","msg":"retry succeeded","order":"G-501"}`},
		{"host", `{"lvl":"warn","msg":"disk usage high","mount":"/var","pct":88}`},
		{"app", `{"lvl":"info","msg":"order shipped","order":"G-501","carrier":"UPS"}`},
		{"host", `{"lvl":"crit","msg":"sshd auth failure","user":"root","ip":"8.8.8.8"}`},
		{"app", `{"lvl":"info","msg":"refund issued","order":"G-477","amt":60}`},
		{"host", `{"lvl":"info","msg":"backup completed","size":"2.1GB"}`},
	},
}

// system bundles a fresh store + witnesses for one scenario.
type system struct {
	store    *chain.Store
	worm     witness.CheckpointStore
	ledger   *witness.ProofLedger
	notaries []witness.Notary
}

// build seals all sample logs and anchors checkpoints to the WORM store and the
// two notaries.
func build() *system {
	store := chain.NewStore()
	sealer := chain.NewSealer(store)
	worm := witness.NewMemStore("S3 Object Lock (WORM)")
	notaries := []witness.Notary{
		witness.NewMockNotary("RFC 3161 TSA", "tsa-signing-key"),
		witness.NewMockNotary("OpenTimestamps (Bitcoin)", "ots-signing-key"),
	}
	ledger := witness.NewProofLedger()

	t := baseTime
	for _, tenant := range tenantOrder() {
		for _, l := range sampleLogs[tenant] {
			sealer.Seal(tenant, l.source, l.raw, t, t)
			t += 1_000_000_000
		}
	}

	anchoredAt := t
	for _, tenant := range tenantOrder() {
		entries := store.Tenant(tenant)
		var prevID []byte
		for start := 0; start < len(entries); start += windowSize {
			end := start + windowSize
			if end > len(entries) {
				end = len(entries)
			}
			cp := checkpoint.Build(tenant, entries[start:end], prevID, anchoredAt)
			if err := worm.Put(cp); err != nil {
				panic(err)
			}
			for _, n := range notaries {
				p, err := n.Stamp(cp.CheckpointID)
				if err != nil {
					panic(err)
				}
				ledger.Add(tenant, cp.SeqEnd, p)
			}
			prevID = cp.CheckpointID
			anchoredAt += 1_000_000_000
		}
	}

	return &system{store: store, worm: worm, ledger: ledger, notaries: notaries}
}

func tenantOrder() []string { return []string{"acme-corp", "globex"} }

// insiderReseal simulates a sophisticated attacker who, after editing rows,
// recomputes the entire per-tenant hash chain so it is internally consistent.
func insiderReseal(store *chain.Store, tenant string) {
	prev := crypto.Genesis(tenant)
	for _, e := range store.Tenant(tenant) {
		e.PrevHash = prev
		leaf := crypto.EntryLeaf(tenant, e.Seq, e.EventTime, e.IngestTime, e.Source, e.Raw)
		e.EntryHash = crypto.ChainHash(prev, leaf)
		prev = e.EntryHash
	}
}

func main() {
	banner("multi-log — immutability core prototype")
	fmt.Printf("%sTwo tenants, %d + %d log entries, anchored to 1 WORM store + 2 notaries in %d-entry windows.%s\n",
		dim, len(sampleLogs["acme-corp"]), len(sampleLogs["globex"]), windowSize, reset)

	section("0. Baseline — nothing tampered")
	sys := build()
	showWitnesses(sys)
	runVerify(sys, "Everything should verify.")

	section("1. Naive tamper — edit a row, leave the chain alone")
	sys = build()
	target := sys.store.Tenant("acme-corp")[7]
	fmt.Printf("%s  attacker rewrites acme-corp seq 7 to hide an unauthorized-access alert%s\n", dim, reset)
	target.Raw = `{"lvl":"info","msg":"health check ok","user":"mallory"}`
	runVerify(sys, "Chain replay alone catches this — the stored entry_hash no longer matches.")

	section("2. Sophisticated tamper — edit a row AND recompute the chain")
	sys = build()
	target = sys.store.Tenant("acme-corp")[8]
	fmt.Printf("%s  attacker rewrites acme-corp seq 8, then re-seals the whole chain so it's self-consistent%s\n", dim, reset)
	target.Raw = `{"lvl":"info","msg":"payment captured","id":"PAY-77","amt":1}`
	insiderReseal(sys.store, "acme-corp")
	runVerify(sys, "Chain replay now PASSES — but the WORM record and both notary proofs disagree.")

	section("3. Truncation — delete the most recent entry")
	sys = build()
	fmt.Printf("%s  attacker deletes globex seq 7 (the latest log) to make an event disappear%s\n", dim, reset)
	sys.store.Delete("globex", 7)
	insiderReseal(sys.store, "globex")
	runVerify(sys, "No sequence gap (it was the tail) — but the checkpoint committed an entry count.")

	banner("takeaway")
	fmt.Printf("%sThe hash chain catches careless edits. The %sindependent witnesses%s%s catch the careful ones —\n", reset, bold, reset, reset)
	fmt.Printf("an insider can rewrite the database perfectly, but cannot rewrite the checkpoint already in\n")
	fmt.Printf("WORM storage, nor forge the timestamp-authority and public-chain proofs over its id.\n")
}

func runVerify(sys *system, note string) {
	fmt.Printf("%s  %s%s\n", dim, note, reset)
	rep := verify.Verify(sys.store, sys.worm, sys.ledger, sys.notaries)
	if rep.OK() {
		fmt.Printf("  %s%s✓ VERIFIED%s  %d entries, %d checkpoints, %d notary proofs checked — no tampering.\n",
			bold, green, reset, rep.EntriesChecked, rep.CheckpointsSeen, rep.ProofsChecked)
		return
	}
	fmt.Printf("  %s%s✗ TAMPERING DETECTED%s  (%d entries, %d checkpoints, %d proofs checked)\n",
		bold, red, reset, rep.EntriesChecked, rep.CheckpointsSeen, rep.ProofsChecked)
	for _, iss := range rep.Issues {
		fmt.Printf("    %s-%s %s\n", red, reset, iss)
	}
}

func showWitnesses(sys *system) {
	for _, tenant := range tenantOrder() {
		fmt.Printf("%s  %s checkpoints (in WORM):%s\n", dim, tenant, reset)
		cps, _ := sys.worm.All(tenant)
		for _, cp := range cps {
			fmt.Printf("%s    seq %d..%d  count=%d  root=%s  id=%s%s\n",
				dim, cp.SeqStart, cp.SeqEnd, cp.EntryCount,
				witness.Hex(cp.MerkleRoot), witness.Hex(cp.CheckpointID), reset)
		}
	}
}

func section(title string) {
	fmt.Printf("\n%s%s%s\n", bold, title, reset)
	fmt.Println(dim + strings.Repeat("-", len(title)) + reset)
}

func banner(title string) {
	fmt.Printf("\n%s%s%s%s\n", bold, strings.ToUpper(title), reset, reset)
	fmt.Println(strings.Repeat("=", len(title)))
}

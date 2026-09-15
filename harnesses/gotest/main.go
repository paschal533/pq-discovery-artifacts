// Does go-ethereum behave the way COEXISTENCE.md says it does?
//
// Claim C-06a says geth decodes ENRs permissively, verifies as a separate step, and
// skips a bad record individually instead of discarding the response. That was
// established by reading p2p/enr/enr.go, p2p/enode/node.go and p2p/discover/v5_udp.go.
// This runs it, against go-ethereum v1.17.5.
//
// Method matches the Rust poison.rs and the Nim enr_decode_test.nim: take a real,
// signed record and rewrite the RLP string "v4" to "v5". Both are two bytes, so every
// length prefix stays correct and the bytes remain well-formed RLP. Only the scheme
// changes.
package main

import (
	"bytes"
	"crypto/ecdsa"
	"fmt"

	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/p2p/discover/v5wire"
	"github.com/ethereum/go-ethereum/p2p/enode"
	"github.com/ethereum/go-ethereum/p2p/enr"
	"github.com/ethereum/go-ethereum/rlp"
)

func mustKey() *ecdsa.PrivateKey {
	k, err := crypto.GenerateKey()
	if err != nil {
		panic(err)
	}
	return k
}

// signedRecord returns a valid v4 record and its RLP encoding.
func signedRecord(port uint16) (*enr.Record, []byte) {
	var r enr.Record
	r.Set(enr.UDP(port))
	if err := enode.SignV4(&r, mustKey()); err != nil {
		panic(err)
	}
	raw, err := rlp.EncodeToBytes(&r)
	if err != nil {
		panic(err)
	}
	return &r, raw
}

// toV5 rewrites the n-th RLP-encoded string "v4" (0x82 'v' '4') to "v5".
// Length-preserving, so the RLP stays structurally valid.
func toV5(raw []byte, n int) []byte {
	out := bytes.Clone(raw)
	seen := 0
	for i := 0; i+2 < len(out); i++ {
		if out[i] == 0x82 && out[i+1] == 'v' && out[i+2] == '4' {
			seen++
			if seen == n {
				out[i+2] = '5'
				return out
			}
		}
	}
	panic(fmt.Sprintf("wanted occurrence %d of \"v4\", found only %d", n, seen))
}

func main() {
	fmt.Println("go-ethereum v1.17.5 ENR decode behaviour")
	fmt.Println("=======================================")

	_, raw := signedRecord(9000)
	fmt.Printf("  built a v4 record, %d bytes\n\n", len(raw))

	// 1. control
	var ctl enr.Record
	fmt.Printf("  1. valid v4 record, rlp decode  -> %v\n", errText(rlp.DecodeBytes(raw, &ctl)))
	_, err := enode.New(enode.ValidSchemes, &ctl)
	fmt.Printf("     ... then enode.New          -> %v\n", errText(err))

	// 2. the same record with id = "v5". This is the claim: DECODE SUCCEEDS.
	v5raw := toV5(raw, 1)
	if len(v5raw) != len(raw) {
		panic("substitution changed the length")
	}
	var bad enr.Record
	decErr := rlp.DecodeBytes(v5raw, &bad)
	fmt.Printf("\n  2. same record, id = \"v5\"\n")
	fmt.Printf("     rlp decode                  -> %v", errText(decErr))
	if decErr == nil {
		fmt.Printf("   (scheme=%q)", bad.IdentityScheme())
	}
	fmt.Println()

	// 3. verification is where it fails, and only there.
	_, verErr := enode.New(enode.ValidSchemes, &bad)
	fmt.Printf("     enode.New                   -> %v\n", errText(verErr))

	// 4. the one that matters: geth's real NODES message decoder, given a message
	//    with four records of which the LAST is "v5". The first three parsed fine.
	fmt.Println("\n  4. v5wire.DecodeMessage on a NODES message, 4 records, last one \"v5\":")

	var recs []*enr.Record
	for i := uint16(0); i < 4; i++ {
		r, _ := signedRecord(9100 + i)
		recs = append(recs, r)
	}
	body, err := rlp.EncodeToBytes(&v5wire.Nodes{
		ReqID: []byte{1, 2, 3, 4}, RespCount: 1, Nodes: recs,
	})
	if err != nil {
		panic(err)
	}

	report := func(label string, b []byte) []*enr.Record {
		pkt, err := v5wire.DecodeMessage(v5wire.NodesMsg, b)
		if err != nil {
			fmt.Printf("     %-24s -> MESSAGE REJECTED: %v\n", label, err)
			return nil
		}
		n := pkt.(*v5wire.Nodes)
		fmt.Printf("     %-24s -> decodes, %d records\n", label, len(n.Nodes))
		return n.Nodes
	}

	report("control, all v4", body)
	got := report("last record \"v5\"", toV5(body, 4))

	// 5. and then the per-record skip, which is what v5_udp.go:456-462 does with
	//    the records DecodeMessage handed back.
	if got != nil {
		fmt.Println("\n  5. verifying each record the way v5_udp.go:456-462 does:")
		kept := 0
		for i, r := range got {
			if _, err := enode.New(enode.ValidSchemes, r); err != nil {
				fmt.Printf("     record %d (%s): skipped - %v\n", i+1, r.IdentityScheme(), err)
				continue
			}
			kept++
		}
		fmt.Printf("     kept %d of %d records.\n", kept, len(got))
	}
}

func errText(err error) string {
	if err == nil {
		return "ok"
	}
	return "ERROR: " + err.Error()
}

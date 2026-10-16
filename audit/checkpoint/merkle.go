package checkpoint

import (
	"crypto/sha256"
	"crypto/subtle"
	"errors"
)

const hashBytes = sha256.Size

// LeafHash is the RFC 6962 leaf hash: SHA-256(0x00 || data).
func LeafHash(data []byte) []byte {
	h := sha256.New()
	h.Write([]byte{0x00})
	h.Write(data)
	return h.Sum(nil)
}

// NodeHash is the RFC 6962 interior node hash: SHA-256(0x01 || left || right).
func NodeHash(left, right []byte) []byte {
	h := sha256.New()
	h.Write([]byte{0x01})
	h.Write(left)
	h.Write(right)
	return h.Sum(nil)
}

// splitPoint is the largest power of two strictly less than n (n >= 2).
func splitPoint(n int) int {
	k := 1
	for k*2 < n {
		k *= 2
	}
	return k
}

func isPowerOfTwo(n int64) bool { return n > 0 && n&(n-1) == 0 }

// MerkleRoot is the Merkle tree hash over already hashed leaves. The empty
// tree is SHA-256 of the empty string.
func MerkleRoot(leaves [][]byte) []byte {
	n := len(leaves)
	if n == 0 {
		s := sha256.Sum256(nil)
		return s[:]
	}
	if n == 1 {
		return leaves[0]
	}
	k := splitPoint(n)
	return NodeHash(MerkleRoot(leaves[:k]), MerkleRoot(leaves[k:]))
}

// InclusionPath is the audit path for the leaf at index (RFC 6962 PATH).
func InclusionPath(leaves [][]byte, index int) ([][]byte, error) {
	n := len(leaves)
	if index < 0 || index >= n {
		return nil, errors.New("checkpoint: inclusion index out of range")
	}
	if n == 1 {
		return [][]byte{}, nil
	}
	k := splitPoint(n)
	if index < k {
		sub, err := InclusionPath(leaves[:k], index)
		if err != nil {
			return nil, err
		}
		return append(sub, MerkleRoot(leaves[k:])), nil
	}
	sub, err := InclusionPath(leaves[k:], index-k)
	if err != nil {
		return nil, err
	}
	return append(sub, MerkleRoot(leaves[:k])), nil
}

func subProof(m int, leaves [][]byte, complete bool) [][]byte {
	n := len(leaves)
	if m == n {
		if complete {
			return [][]byte{}
		}
		return [][]byte{MerkleRoot(leaves)}
	}
	k := splitPoint(n)
	if m <= k {
		return append(subProof(m, leaves[:k], complete), MerkleRoot(leaves[k:]))
	}
	return append(subProof(m-k, leaves[k:], false), MerkleRoot(leaves[:k]))
}

// ConsistencyPath is the proof between the tree of the first oldSize leaves and
// the tree of all leaves (RFC 6962 PROOF). Empty when oldSize is 0 or equals
// the full size.
func ConsistencyPath(leaves [][]byte, oldSize int) ([][]byte, error) {
	n := len(leaves)
	if oldSize < 0 || oldSize > n {
		return nil, errors.New("checkpoint: consistency oldSize out of range")
	}
	if oldSize == 0 || oldSize == n {
		return [][]byte{}, nil
	}
	return subProof(oldSize, leaves, true), nil
}

// RootFromInclusion recomputes the root from a leaf hash and its audit path
// (RFC 9162 section 2.1.3.2). ok is false when the path shape is wrong.
func RootFromInclusion(leafHash []byte, index, size int64, path [][]byte) (root []byte, ok bool) {
	if index < 0 || index >= size {
		return nil, false
	}
	fn, sn := index, size-1
	r := leafHash
	for _, p := range path {
		if sn == 0 {
			return nil, false
		}
		if fn&1 == 1 || fn == sn {
			r = NodeHash(p, r)
			if fn&1 == 0 {
				for fn&1 == 0 && fn != 0 {
					fn >>= 1
					sn >>= 1
				}
			}
		} else {
			r = NodeHash(r, p)
		}
		fn >>= 1
		sn >>= 1
	}
	if sn != 0 {
		return nil, false
	}
	return r, true
}

func allHashes(path [][]byte) bool {
	for _, p := range path {
		if len(p) != hashBytes {
			return false
		}
	}
	return true
}

func eq(a, b []byte) bool { return subtle.ConstantTimeCompare(a, b) == 1 }

// VerifyInclusionPath reports whether path proves the leaf at index is in the
// tree of size leaves with the given root.
func VerifyInclusionPath(leafHash []byte, index, size int64, path [][]byte, root []byte) bool {
	if len(leafHash) != hashBytes || len(root) != hashBytes || !allHashes(path) {
		return false
	}
	got, ok := RootFromInclusion(leafHash, index, size, path)
	return ok && eq(got, root)
}

// VerifyConsistencyPath reports whether path proves the tree of newSize leaves
// (root newRoot) extends the tree of oldSize leaves (root oldRoot) without
// changing any old leaf (RFC 9162 section 2.1.4.2).
func VerifyConsistencyPath(oldSize, newSize int64, oldRoot, newRoot []byte, path [][]byte) bool {
	if oldSize < 0 || oldSize > newSize {
		return false
	}
	if len(oldRoot) != hashBytes || len(newRoot) != hashBytes || !allHashes(path) {
		return false
	}
	if oldSize == newSize {
		return len(path) == 0 && eq(oldRoot, newRoot)
	}
	if oldSize == 0 {
		return len(path) == 0
	}
	var nodes [][]byte
	if isPowerOfTwo(oldSize) {
		nodes = append(nodes, oldRoot)
	}
	nodes = append(nodes, path...)
	if len(nodes) == 0 {
		return false
	}
	fn, sn := oldSize-1, newSize-1
	for fn&1 == 1 {
		fn >>= 1
		sn >>= 1
	}
	fr, sr := nodes[0], nodes[0]
	for _, c := range nodes[1:] {
		if sn == 0 {
			return false
		}
		if fn&1 == 1 || fn == sn {
			fr = NodeHash(c, fr)
			sr = NodeHash(c, sr)
			if fn&1 == 0 {
				for fn&1 == 0 && fn != 0 {
					fn >>= 1
					sn >>= 1
				}
			}
		} else {
			sr = NodeHash(sr, c)
		}
		fn >>= 1
		sn >>= 1
	}
	return sn == 0 && eq(fr, oldRoot) && eq(sr, newRoot)
}

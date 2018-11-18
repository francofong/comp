package merkletree //create merkle tree

import (
	"errors"
	"hash"
)

// return merkle tree root
// adds one leaf to the Merkle tree
// 'Root' returns the Merkle root

type Tree struct {
	// Each subtree has a height, and is the Merkle root of 2^height leaves. 
  // Head points to the smallest tree. 
  // When a new leaf is inserted, it is inserted as a subtree of height 0. 

	head *subTree
	hash hash.Hash
	currentIndex uint64
	proofIndex   uint64
	proofSet     [][]byte
	proofTree    bool
	cachedTree bool
}

package merkletree //create merkle tree

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
)


//Data that is stored and verified by the tree
type Content interface {
	CalculateHash() ([]byte, error)
	Equals(other Content) (bool, error)
}

//MerkleTree holds a pointer to the root of the tree
type MerkleTree struct {
	RootNode       *MerkleNode
	merkleRoot []byte
	Leafs      []*Node
}

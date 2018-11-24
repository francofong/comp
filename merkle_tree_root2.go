package main

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
)

type Content interface {
	CalculateHash() ([]byte, error)
	Equals(other Content) (bool, error)
}

//MerkleTree is the container for the tree. It holds a pointer to the root of the tree,
//a list of pointers to the leaf nodes, and the merkle root.
type MerkleTree struct {
	Root       *Node
	merkleRoot []byte
	Leafs      []*Node
}

//Node represents a node, root, or leaf in the tree. It stores pointers to its immediate
//relationships, a hash, the content stored if it is a leaf, and other metadata.
type Node struct {
	Parent *Node
	Left   *Node
	Right  *Node
	leaf   bool
	dup    bool
	Hash   []byte
	C      Content
}

func main() {
	// Obtain data [][] byte from os.Args
	dataString := os.Args[1:]
	var data [][]byte
	fmt.Println("input:	", dataString)
	for i := 0; i < len(dataString); i++ {
		data = append(data, []byte(dataString[i]))
	}

	// Print data
	for i := 0; i < len(dataString); i++ {
		fmt.Println("dataString[", i, "]:	", dataString[i])
	}
	for i := 0; i < len(dataString); i++ {
		fmt.Println("data[", i, "]:		", data[i])
	}

	// Print Merkel Tree Root
	fmt.Println("Merkel Tree Root:	", hex.EncodeToString(MerkelTreeRoot(dataString)))
}

//MerkelTreeRoot is used for calculation of Merkel Tree Root
func MerkelTreeRoot(content []string) (headRoot []byte) {
// Obtain data [][] byte from os.Args
	dataString := os.Args[1:]
	var data [][]byte
	fmt.Println("input:	", dataString)
	for i := 0; i < len(dataString); i++ {
		data = append(data, []byte(dataString[i]))
	}

	// Print data
	for i := 0; i < len(dataString); i++ {
		fmt.Println("dataString[", i, "]:	", dataString[i])
	}
	for i := 0; i < len(dataString); i++ {
		fmt.Println("data[", i, "]:		", data[i])
	}

	// Print Merkel Tree Root
	fmt.Println("Merkel Tree Root:	", hex.EncodeToString(MerkelTreeRoot(dataString)))
}

//MerkelTreeRoot is used for calculation of Merkel Tree Root

func (n *Node) calculateNodeHash(content []string) (headRoot []byte, error) {
	if n.leaf {
		return n.C.CalculateHash()
	}

	h := sha256.New()
	if _, err := h.Write([]byte(content[0]))
	headRoot = h.Sum(nil); err != nil {
		return nil, err
	}

	return headRoot, nil
}

func NewTree(cs []Content) (*MerkleTree, error) {
	root, leafs, err := buildWithContent(cs)
	if err != nil {
		return nil, err
	}
	t := &MerkleTree{
		Root:       root,
		merkleRoot: root.Hash,
		Leafs:      leafs,
	}
	return t, nil
}
func buildWithContent(cs []Content) (*Node, []*Node, error) {
	if len(cs) == 0 {
		return nil, nil, errors.New("error: cannot construct tree with no content")
	}
	var leafs []*Node
	for _, c := range cs {
		hash, err := c.CalculateHash()
		if err != nil {
			return nil, nil, err
		}

		leafs = append(leafs, &Node{
			Hash: hash,
			C:    c,
			leaf: true,
		})
	}
	if len(leafs)%2 == 1 {
		duplicate := &Node{
			Hash: leafs[len(leafs)-1].Hash,
			C:    leafs[len(leafs)-1].C,
			leaf: true,
			dup:  true,
		}
		leafs = append(leafs, duplicate)
	}
	root, err := buildIntermediate(leafs)
	if err != nil {
		return nil, nil, err
	}

	return root, leafs, nil
}

//buildIntermediate is a helper function that for a given list of leaf nodes, constructs
//the intermediate and root levels of the tree. Returns the resulting root node of the tree.
func buildIntermediate(nl []*Node) (*Node, error) {
	var nodes []*Node
	for i := 0; i < len(nl); i += 2 {
		h := sha256.New()
		var left, right int = i, i + 1
		if i+1 == len(nl) {
			right = i
		}
		chash := append(nl[left].Hash, nl[right].Hash...)
		if _, err := h.Write(chash); err != nil {
			return nil, err
		}
		n := &Node{
			Left:  nl[left],
			Right: nl[right],
			Hash:  h.Sum(nil),
		}
		nodes = append(nodes, n)
		nl[left].Parent = n
		nl[right].Parent = n
		if len(nl) == 2 {
			return n, nil
		}
	}
	return buildIntermediate(nodes)
}

func (m *MerkleTree) MerkleRoot() []byte {
	return m.merkleRoot
}

func (m *MerkleTree) RebuildTree() error {
	var cs []Content
	for _, c := range m.Leafs {
		cs = append(cs, c.C)
	}
	root, leafs, err := buildWithContent(cs)
	if err != nil {
		return err
	}
	m.Root = root
	m.Leafs = leafs
	m.merkleRoot = root.Hash
	return nil
}

func (m *MerkleTree) VerifyTree() (bool, error) {
	calculatedMerkleRoot, err := m.Root.verifyNode()
	if err != nil {
		return false, err
	}

	if bytes.Compare(m.merkleRoot, calculatedMerkleRoot) == 0 {
		return true, nil
	}
	return false, nil
}

func (m *MerkleTree) VerifyContent(content Content) (bool, error) {
	for _, l := range m.Leafs {
		ok, err := l.C.Equals(content)
		if err != nil {
			return false, err
		}

		if ok {
			currentParent := l.Parent
			for currentParent != nil {
				h := sha256.New()
				rightBytes, err := currentParent.Right.calculateNodeHash()
				if err != nil {
					return false, err
				}

				leftBytes, err := currentParent.Left.calculateNodeHash()
				if err != nil {
					return false, err
				}
				if currentParent.Left.leaf && currentParent.Right.leaf {
					if _, err := h.Write(append(leftBytes, rightBytes...)); err != nil {
						return false, err
					}
					if bytes.Compare(h.Sum(nil), currentParent.Hash) != 0 {
						return false, nil
					}
					currentParent = currentParent.Parent
				} else {
					if _, err := h.Write(append(leftBytes, rightBytes...)); err != nil {
						return false, err
					}
					if bytes.Compare(h.Sum(nil), currentParent.Hash) != 0 {
						return false, nil
					}
					currentParent = currentParent.Parent
				}
			}
			return true, nil
		}
	}
	return false, nil
}

//String returns a string representation of the tree. Only leaf nodes are included
//in the output.
func (m *MerkleTree) String() string {
	s := ""
	for _, l := range m.Leafs {
		s += fmt.Sprint(l)
		s += "\n"
	}
	return s
}
	// Modify below code
	h := sha256.New()
	h.Write([]byte(content[0]))
	headRoot = h.Sum(nil)
	// End

	return headRoot
}

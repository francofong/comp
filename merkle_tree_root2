package main

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
)

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

	// Modify below code
	h := sha256.New()
	h.Write([]byte(content[0]))
	headRoot = h.Sum(nil)
	// End

	return headRoot
}

package in_toto

import (
	"crypto/sha256"
	"crypto/sha512"
	"fmt"
	"hash"
)

/*
getHashMapping returns a mapping from hash algorithm to supported hash
algorithm.
*/
func getHashMapping() map[string]func() hash.Hash {
	return map[string]func() hash.Hash{
		"sha256": sha256.New,
		"sha512": sha512.New,
		"sha384": sha512.New384,
	}
}

/*
hashToHex calculates the hash over data based on hash algorithm h.
*/
func hashToHex(h hash.Hash, data []byte) string {
	h.Write(data)
	// We ned to use h.Sum(nil) here, because otherwise hash.Sum() appends
	// the hash to the passed data. So instead of having only the hash
	// we would get: "dataHASH"
	return fmt.Sprintf("%x", h.Sum(nil))
}

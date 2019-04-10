package in_toto

import (
	"crypto/md5"
	"crypto/sha256"
	"crypto/sha512"
	"fmt"
)

/*
Hash is an interface which contains a generic compute method.
This method is implemented by several functions to return the
hash for a given data.

To add hash functions which are currently not supported one
has to create a struct, write it's defination, add it's
value to the map in createMap function and add the hash
function to the list of hash functions(if required)
*/

type Hash interface {
	Compute(content []uint8) string
}

/*
Declaration of struct, one for each of the hash function.
*/
type sha_256_Hash struct{}
type sha_512_Hash struct{}
type md5_Hash struct{}

/*
Defination of compute function for each of the hash struct
declared above.
*/

func (hash *sha_256_Hash) Compute(content []uint8) string {

	hashed := sha256.Sum256(content)
	n := fmt.Sprintf("%x", hashed)
	return n
}

func (hash *sha_512_Hash) Compute(content []uint8) string {
	hashed := sha512.Sum512(content)
	n := fmt.Sprintf("%x", hashed)
	return n
}

func (hash *md5_Hash) Compute(content []uint8) string {
	hashed := md5.Sum(content)
	n := fmt.Sprintf("%x", hashed)
	return n
}

/*
This fuction returns the map containing hash function name as key and
their respective reference object as value.
*/

func createMap() map[string]interface{ Compute(content []uint8) string } {
	mapper := map[string]interface{ Compute(content []uint8) string }{
		"sha256": &sha_256_Hash{},
		"sha512": &sha_512_Hash{},
		"md5":    &md5_Hash{},
	}
	return mapper
}

/*
This function return a list a hash fuctions that we want program to use
for each of the files.
*/

func createList() []string {

	hash_func := []string{"sha256", "sha512"}
	return hash_func
}

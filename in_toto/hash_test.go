package in_toto

import (
	"reflect"
	"testing"
)

/*
This function tests if all the hashing functions listed
in the hash_func list inside hash.go file
*/

func TestHashFunctions(t *testing.T) {

	hash_func := createList()
	hashObjectMap := createMap()
	expected := map[string]interface{}{
		"sha256": "de31a0fb6adeb79b6017f39244ac52a4aea74548015c37d98f00a9e0e0914565",
		"sha512": "9ebe8a6e2b814321588c920de4de007ad911edc7a6ca5e826fa5d0a99a217b79e13ecebe11bade0f6c3775f7023ca86cd1c58745ff98d1c8c1bb3fbc9c02608e",
		"md5":    "b000762f953ddd0c704aaf0114d10556",
	}

	hashedContentsMap := make(map[string]interface{})
	for _, element := range hash_func {

		result := hashObjectMap[element].Compute([]uint8("Hashing this string to test"))
		hashedContentsMap[element] = result
	}

	if !reflect.DeepEqual(hashedContentsMap, expected) {
		t.Errorf("hashing failed")
	}
}

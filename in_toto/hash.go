package in_toto

import (

	"fmt"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/md5"

)

type Hash interface {

	Compute(content []uint8) (string)
}


type sha_256_Hash struct {}
type sha_512_Hash struct {}
type md5_Hash struct {}


func (hash *sha_256_Hash) Compute(content []uint8) (string){
	
	hashed := sha256.Sum256(content);
	n := fmt.Sprintf("%x", hashed)
	return n
}


func (hash *sha_512_Hash) Compute(content []uint8) (string){
	hashed := sha512.Sum512(content);
	n := fmt.Sprintf("%x", hashed)
	return n
}

func (hash *md5_Hash) Compute(content []uint8) (string){
	hashed := md5.Sum(content);
	n := fmt.Sprintf("%x", hashed)
	return n
}

func createMap() map[string]interface{Compute(content []uint8) (string)}{
	mapper := map[string]interface{Compute(content []uint8) (string)}{
	        "sha256"  : &sha_256_Hash{},
	        "sha512"  : &sha_512_Hash{},
	        "md5"  	  : &md5_Hash{},
		}
		return mapper
}


func createList() []string{

	hash_func := []string{"sha256"}
	return hash_func
}

package in_toto

import (
	"fmt"
	"os"
)

const LayoutPath = "demo.layout.template"
const LayoutKeyPath = "alice.pub"
const LinkDirectory = "../test/data"

func ExampleInTotoVerify() {
	// Load the layout verification key and create a map as is required by
	// InTotoVerify.  The layout represents the root of trust so it is a good
	// idea to sign it using multiple keys.
	var pubKey Key
	pubKey.LoadPublicKey(LayoutKeyPath)
	var layoutKeys = map[string]Key{
		pubKey.KeyId: pubKey,
	}

	// Perform in-toto software supply chain verification, using the provided
	// test data.
	var layoutMb Metablock
	if err := layoutMb.Load(LayoutPath); err != nil {
		fmt.Println("Unable to load layout metadata.")
	}
	_, err := InTotoVerify(layoutMb, layoutKeys, LinkDirectory)
	if err != nil {
		fmt.Println("In-toto verification succeeded!")
	}

	// During verification the inspection "untar" was executed, generating a
	// corresponding link metadata file "untar.link". You can safely remove it.
	os.Remove("untar.link")

	// Output: In-toto verification succeeded!
}

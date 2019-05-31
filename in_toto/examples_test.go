package in_toto

import (
	"fmt"
	"os"
)

/*
NOTE: The example code requires the following files to be in the current
working directory: `demo.layout.template` (root layout), `alice.pub` (layout
signature verification key), `write-code.776a00e2.link` and
`package.2f89b927.link` (link metadata files), and `foo.tar.gz` (target file of
final product). You can copy these files from
https://github.com/in-toto/in-toto-golang/tree/master/test/data.
*/

const LayoutPath = "demo.layout.template"
const LayoutKeyPath = "alice.pub"
const LinkDirectory = "."

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
		fmt.Printf("Unable to load layout metadata: %s", err)
	}
	if err := validateLayout(layoutMb.Signed.(Layout)); err != nil {
		fmt.Printf("Invalid metadata found: %s", err)
	}
	if _, err := InTotoVerify(layoutMb, layoutKeys, LinkDirectory, "",
		make(map[string]string)); err != nil {
		fmt.Printf("In-toto verification failed: %s", err)
	} else {
		fmt.Println("In-toto verification succeeded!")
	}

	// During verification the inspection "untar" was executed, generating a
	// corresponding link metadata file "untar.link". You can safely remove it.
	os.Remove("untar.link")

	// Output: In-toto verification succeeded!
}

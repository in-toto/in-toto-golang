package in_toto

import (
	"fmt"
	"os"
)

/*
NOTE: The example code requires the following files to be in the current
working directory: `demo.layout` (root layout), `alice.pub` (layout
signature verification key), `write-code.776a00e2.link` and
`package.2f89b927.link` (link metadata files), and `foo.tar.gz` (target file of
final product). You can copy these files from
https://github.com/in-toto/in-toto-golang/tree/master/test/data.
*/

const LayoutPath = "demo.layout"
const LayoutKeyPath = "alice.pub"
const LinkDirectory = "."

func ExampleInTotoVerify() {
	// Load the layout verification key and create a map as is required by
	// InTotoVerify.  The layout represents the root of trust so it is a good
	// idea to sign it using multiple keys.
	var pubKey Key
	err := pubKey.LoadKey(LayoutKeyPath, "rsassa-pss-sha256", []string{"sha256", "sha512"})
	if err != nil {
		fmt.Printf("Unable to load public key: %s", err)
	}
	var layoutKeys = map[string]Key{
		pubKey.KeyID: pubKey,
	}

	// Perform in-toto software supply chain verification, using the provided
	// test data.
	layoutMb, err := LoadMetadata(LayoutPath)
	if err != nil {
		fmt.Printf("Unable to load layout metadata: %s", err)
	}
	layout, ok := layoutMb.GetPayload().(Layout)
	if !ok {
		fmt.Printf("metadata must be layout")
		return
	}
	if err := validateLayout(layout); err != nil {
		fmt.Printf("Invalid metadata found: %s", err)
	}
	if _, err := InTotoVerify(layoutMb, layoutKeys, LinkDirectory, "",
		make(map[string]string), [][]byte{}, testOSisWindows()); err != nil {
		fmt.Printf("in-toto verification failed: %s", err)
	} else {
		fmt.Println("in-toto verification succeeded!")
	}

	// During verification the inspection "untar" was executed, generating a
	// corresponding link metadata file "untar.link". You can safely remove it.
	err = os.Remove("untar.link")
	if err != nil {
		fmt.Printf("Unable to remove untar.link: %s", err)
	}
	// Output: in-toto verification succeeded!
}

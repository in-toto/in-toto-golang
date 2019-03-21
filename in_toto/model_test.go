package in_toto

import (
	"encoding/hex"
	"fmt"
	"io/ioutil"
	"os"
	"reflect"
	"strings"
	"testing"
)

func TestMetablockLoad(t *testing.T) {
	// Create a bunch of tmp json files with invalid format and test load errors:
	// - invalid json
	// - missing signatures and signed field
	// - invalid signatures field
	// - invalid signed field
	// - invalid signed type
	// - invalid signed field for type link
	// - invalid signed field for type layout
	invalidJsonBytes := [][]byte{
		[]byte("{"),
		[]byte("{}"),
		[]byte(`{"signatures": null, "signed": {}}`),
		[]byte(`{"signatures": "string", "signed": {}}`),
		[]byte(`{"signatures": [], "signed": []}`),
		[]byte(`{"signatures": [], "signed": {"_type": "something else"}}`),
		[]byte(`{"signatures": [], "signed": {"_type": "link", "materials": "invalid", "name": "some name", "products": "invalid", "byproducts": "invalid", "command": "some command", "environment": "some list"}}`),
		[]byte(`{"signatures": [], "signed": {"_type": "layout", "steps": "invalid", "inspect": "invalid", "readme": "some readme", "keys": "some keys", "expires": "some date"}}`),
	}

	expectedErrors := []string{
		"unexpected end",
		"requires 'signed' and 'signatures' parts",
		"requires 'signed' and 'signatures' parts",
		"cannot unmarshal string into Go value of type []in_toto.Signature",
		"cannot unmarshal array into Go value of type map[string]interface {}",
		"metadata must be one of 'link' or 'layout'",
		"cannot unmarshal string into Go struct field Link.materials",
		"cannot unmarshal string into Go struct field Layout.steps",
	}

	for i := 0; i < len(invalidJsonBytes); i++ {
		fn := fmt.Sprintf("invalid-metadata-%v.tmp", i)
		ioutil.WriteFile(fn, invalidJsonBytes[i], 0644)
		var mb Metablock
		err := mb.Load(fn)
		if err == nil || !strings.Contains(err.Error(), expectedErrors[i]) {
			t.Errorf("Metablock.Load returned '%s', expected '%s' error", err,
				expectedErrors[i])
		}
		os.Remove(fn)
	}
}

func TestMetablockDump(t *testing.T) {
	// Test dump metablock errors:
	// - invalid content
	// - invalid path
	mbs := []Metablock{
		{Signed: TestMetablockDump},
		{},
	}
	paths := []string{
		"bad-metadata",
		"bad/path",
	}
	expectedErrors := []string{
		"json: unsupported type",
		"open bad/path",
	}

	for i := 0; i < len(mbs); i++ {
		err := mbs[i].Dump(paths[i])
		fmt.Println(err)
		if err == nil || !strings.Contains(err.Error(), expectedErrors[i]) {
			t.Errorf("Metablock.Dump returned '%s', expected '%s'",
				err, expectedErrors[i])
		}
	}
}

func TestMetablockLoadDumpLoad(t *testing.T) {
	// Dump, load and compare metablock, also compare with metablock loaded
	// from existing equivalent JSON file, assert that they are equal.
	mbMemory := Metablock{
		Signed: Link{
			Type: "link",
			Name: "package",
			Command: []string{
				"tar",
				"zcvf",
				"foo.tar.gz",
				"foo.py",
			},
			Materials: map[string]interface{}{
				"foo.py": map[string]interface{}{
					"sha256": "74dc3727c6e89308b39e4dfedf787e37841198b1fa165a27c013544a60502549",
				},
			},
			Products: map[string]interface{}{
				"foo.tar.gz": map[string]interface{}{
					"sha256": "52947cb78b91ad01fe81cd6aef42d1f6817e92b9e6936c1e5aabb7c98514f355",
				},
			},
			ByProducts: map[string]interface{}{
				"return-value": float64(0),
				"stderr":       "a foo.py\n",
				"stdout":       "",
			},
			Environment: map[string]interface{}{},
		},
		Signatures: []Signature{
			{
				KeyId: "2f89b9272acfc8f4a0a0f094d789fdb0ba798b0fe41f2f5f417c12f0085ff498",
				Sig: "66365d379d66a2e76d39a1f048847826393127572ba43bead96419499b0256" +
					"1a08e1cb06cf91f2addd87c30a01f776a8ccc599574bc9a2bd519558351f56cff" +
					"a61ac4f994d0d491204ff54707937e15f9abfa97c5bda1ec1ae2a2afea63f8086" +
					"13f4fb343b85a5a455b668b95fa3a11cb9b34219d4d6af2dd4e80a9af01023954" +
					"a8813b510a6ff6041c3af52056d021fabbc975211b0d8ee7a429a6c22efde583d" +
					"8ac0719fd657b398a3e02cc711897acbe8cadf32d54f47012aa44621728ede42c" +
					"3bc95c662f9c1211df4e18da8e0f6b2de358700cea5db1e76fc61ef5a90bcebcc" +
					"883eed2272e5ca1c8cbb09b868613b839266cd3ae346ce88439bdb5bb4c69dcb7" +
					"398f4373f2b051adb3d44d11ef1b70c7189aa5c0e6906bf7be1228dc553390024" +
					"c9c796316067fda7d63cf60bfac86ef2e13bbd8e4c3575683673f7cdf4639c3a5" +
					"dc225fc0c040dbd9962a6ff51913b240544939ce2d32a5e84792c0acfa94ee07e" +
					"88e474bf4937558d107c6ecdef5b5b3a7f3a44a657662bbc1046df3a",
			},
		},
	}

	fnExisting := "package.2f89b927.link"
	fnTmp := fnExisting + ".tmp"
	mbMemory.Dump(fnTmp)
	for _, fn := range []string{fnExisting, fnTmp} {
		var mbFile Metablock
		mbFile.Load(fn)
		if !reflect.DeepEqual(mbMemory, mbFile) {
			t.Errorf("Dumped and Loaded Metablocks are not equal: \n%s\n\n\n%s\n",
				mbMemory, mbFile)
		}
	}
	// Remove temporary metablock file (keep other for remaining tests)
	os.Remove(fnTmp)
}

func TestMetablockGetSignableRepresentation(t *testing.T) {
	// Test successful metadata canonicalization with encoding corner cases
	// (unicode, escapes, non-string types, ...) and compare with reference
	var mb Metablock
	mb.Load("canonical-test.link")
	// Use hex representation for unambiguous assignment
	referenceHex := "7b225f74797065223a226c696e6b222" +
		"c22627970726f6475637473223a7b7d2c22636f6d6d616e64223a5b5d2" +
		"c22656e7669726f6e6d656e74223a7b2261223a22575446222c2262223" +
		"a747275652c2263223a66616c73652c2264223a6e756c6c2c2265223a3" +
		"12c2266223a221befbfbf465c5c6e5c22227d2c226d6174657269616c7" +
		"3223a7b7d2c226e616d65223a2274657374222c2270726f64756374732" +
		"23a7b7d7d"

	canonical, _ := mb.GetSignableRepresentation()
	if fmt.Sprintf("%x", canonical) != referenceHex {
		// Convert hex representation back to string for better error message
		src := []byte(referenceHex)
		reference := make([]byte, hex.DecodedLen(len(src)))
		n, _ := hex.Decode(reference, src)
		t.Errorf("Metablock.GetSignableRepresentation returned '%s', expected '%s'",
			canonical, reference[:n])
	}
}

func TestMetablockVerifySignature(t *testing.T) {
	// Test metablock signature verification errors:
	// - no signature found
	// - wrong signature for key
	// - invalid metadata (can't canonicalize)
	var key Key
	key.LoadPublicKey("alice.pub")
	// Test missing key, bad signature and bad metadata
	mbs := []Metablock{
		{},
		{
			Signatures: []Signature{{KeyId: key.KeyId, Sig: "bad sig"}},
		},
		{
			Signatures: []Signature{{KeyId: key.KeyId}},
			Signed:     TestMetablockVerifySignature,
		},
	}
	expectedErrors := []string{
		"No signature found",
		"verification error",
		"json: unsupported type",
	}
	for i := 0; i < len(mbs); i++ {
		err := mbs[i].VerifySignature(key)
		if err == nil || !strings.Contains(err.Error(), expectedErrors[i]) {
			t.Errorf("Metablock.VerifySignature returned '%s', expected '%s'",
				err, expectedErrors[i])
		}
	}

	// Test successful metablock signature verification
	var mb Metablock
	mb.Load("demo.layout.template")
	err := mb.VerifySignature(key)
	if err != nil {
		t.Errorf("Metablock.VerifySignature returned '%s', expected nil", err)
	}
}

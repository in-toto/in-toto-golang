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
		[]byte(`{"signatures": [], "signed": {"_type": "link",
			"materials": "invalid", "name": "some name", "products": "invalid",
			"byproducts": "invalid", "command": "some command",
			"environment": "some list"}}`),
		[]byte(`{"signatures": [], "signed": {"_type": "layout",
			"steps": "invalid", "inspect": "invalid", "readme": "some readme",
			"keys": "some keys", "expires": "some date"}}`),
		[]byte(`{"signatures": [], "signed": {"_type": "layout",
			"inspect": "invalid", "readme": "some readme", "keys": "some keys",
			"expires": "some date"}}`),
		[]byte(`{"signatures": [], "signed": {"_type": "layout",
			"steps": "invalid", "readme": "some readme", "keys": "some keys",
			"expires": "some date"}}`),
		[]byte(`{"signatures": [], "signed": {"_type": "layout",
			"steps": "invalid", "inspect": "invalid", "readme": "some readme",
			"expires": "some date"}}`),
		[]byte(`{"signatures": [], "signed": {"_type": "layout",
			"steps": "invalid", "inspect": "invalid", "readme": "some readme",
			"keys": "some keys"}}`),
		[]byte(`{"signatures": [], "signed": {"_type": "layout",
			"steps": "invalid", "inspect": "invalid",
			"keys": "some keys", "expires": "some date"}}`),
		[]byte(`{"signatures": [], "signed": {"_type": "layout", "steps": [],
			"inspect": [], "readme": "some readme", "keys": {},
			"expires": "some date", "foo": "bar"}}`),
		[]byte(`{"signatures": [], "signed": {"_type": "link",
			"materials": "invalid", "products": "invalid",
			"byproducts": "invalid", "command": "some command",
			"environment": "some list"}}`),
		[]byte(`{"signatures": [], "signed": {"_type": "link",
			"name": "some name", "products": "invalid",
			"byproducts": "invalid", "command": "some command",
			"environment": "some list"}}`),
		[]byte(`{"signatures": [], "signed": {"_type": "link",
			"materials": "invalid", "name": "some name",
			"byproducts": "invalid", "command": "some command",
			"environment": "some list"}}`),
		[]byte(`{"signatures": [], "signed": {"_type": "link",
			"materials": "invalid", "name": "some name", "products": "invalid",
			"command": "some command",
			"environment": "some list"}}`),
		[]byte(`{"signatures": [], "signed": {"_type": "link",
			"materials": "invalid", "name": "some name", "products": "invalid",
			"byproducts": "invalid", "environment": "some list"}}`),
		[]byte(`{"signatures": [], "signed": {"_type": "link",
			"materials": "invalid", "name": "some name", "products": "invalid",
			"byproducts": "invalid", "command": "some command"}}`),
		[]byte(`{"signatures": [], "signed": {"_type": "link", "materials": {},
			"name": "some name", "products": {}, "byproducts": {},
			"command": [], "environment": {}, "foo": "bar"}}`),
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
		"required field steps missing",
		"required field inspect missing",
		"required field keys missing",
		"required field expires missing",
		"required field readme missing",
		"json: unknown field \"foo\"",
		"required field name missing",
		"required field materials missing",
		"required field products missing",
		"required field byproducts missing",
		"required field command missing",
		"required field environment missing",
		"json: unknown field \"foo\"",
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

func TestValidateLink(t *testing.T) {
	var mb Metablock
	if err := mb.Load("package.2f89b927.link"); err != nil {
		t.Errorf("Metablock load returned '%s'", err)
	}
	if err := validateLink(mb.Signed.(Link)); err != nil {
		t.Errorf("Link metadata validation failed, returned '%s'", err)
	}

	testMb := Metablock{
		Signed: Link{
			Type: "invalid",
			Name: "test_type",
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
	}

	err := validateLink(testMb.Signed.(Link))
	if err.Error() != "invalid type for link: should be 'link'" {
		t.Error("validateLink error - incorrect type not detected")
	}

	testMb = Metablock{
		Signed: Link{
			Type: "link",
			Name: "test_material_hash",
			Command: []string{
				"tar",
				"zcvf",
				"foo.tar.gz",
				"foo.py",
			},
			Materials: map[string]interface{}{
				"foo.py": map[string]interface{}{
					"sha256": "!@#$%",
				},
			},
			Products: map[string]interface{}{
				"foo.tar.gz": map[string]interface{}{
					"sha256": "52947cb78b91ad01fe81cd6aef42d1f6817e92b9e69" +
						"36c1e5aabb7c98514f355",
				},
			},
			ByProducts: map[string]interface{}{
				"return-value": float64(0),
				"stderr":       "a foo.py\n",
				"stdout":       "",
			},
			Environment: map[string]interface{}{},
		},
	}

	err = validateLink(testMb.Signed.(Link))
	if err.Error() != "hash value has invalid format, got: !@#$%" {
		t.Error("validateLink error - invalid hashes not detected")
	}

	testMb = Metablock{
		Signed: Link{
			Type: "link",
			Name: "test_product_hash",
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
					"sha256": "!@#$%",
				},
			},
			ByProducts: map[string]interface{}{
				"return-value": float64(0),
				"stderr":       "a foo.py\n",
				"stdout":       "",
			},
			Environment: map[string]interface{}{},
		},
	}

	err = validateLink(testMb.Signed.(Link))
	if err.Error() != "hash value has invalid format, got: !@#$%" {
		t.Error("validateLink error - invalid hashes not detected")
	}
}

func TestValidateLayout(t *testing.T) {
	var mb Metablock
	if err := mb.Load("demo.layout.template"); err != nil {
		t.Errorf("Metablock load returned '%s'", err)
	}
	if err := validateLayout(mb.Signed.(Layout)); err != nil {
		t.Errorf("Layout metadata validation failed, returned '%s'", err)
	}

	testMb := Metablock{
		Signed: Layout{
			Type:    "invalid",
			Expires: "2020-11-18T16:06:36Z",
			Readme:  "some readme text",
			Steps:   []Step{},
			Inspect: []Inspection{},
			Keys:    map[string]Key{},
		},
	}

	err := validateLayout(testMb.Signed.(Layout))
	if err.Error() != "invalid Type value for layout: should be 'layout'" {
		t.Error("validateLayout error - invalid type not detected")
	}

	testMb = Metablock{
		Signed: Layout{
			Type:    "layout",
			Expires: "2020-02-31T18:03:43Z",
			Readme:  "some readme text",
			Steps:   []Step{},
			Inspect: []Inspection{},
			Keys:    map[string]Key{},
		},
	}

	err = validateLayout(testMb.Signed.(Layout))
	if err.Error() != "expiry time parsed incorrectly - date either invalid "+
		"or of incorrect format" {
		t.Error("validateLayout error - invalid date not detected")
	}

	testMb = Metablock{
		Signed: Layout{
			Type:    "layout",
			Expires: "2020-02-27T18:03:43Zinvalid",
			Readme:  "some readme text",
			Steps:   []Step{},
			Inspect: []Inspection{},
			Keys:    map[string]Key{},
		},
	}

	err = validateLayout(testMb.Signed.(Layout))
	if err.Error() != "expiry time parsed incorrectly - date either invalid "+
		"or of incorrect format" {
		t.Error("validateLayout error - invalid date not detected")
	}

	testMb = Metablock{
		Signed: Layout{
			Type:    "layout",
			Expires: "2020-02-27T18:03:43Z",
			Readme:  "some readme text",
			Steps: []Step{
				{
					Type: "step",
					SupplyChainItem: SupplyChainItem{
						Name: "foo",
					},
				},
				{
					Type: "step",
					SupplyChainItem: SupplyChainItem{
						Name: "foo",
					},
				},
			},
			Inspect: []Inspection{},
			Keys:    map[string]Key{},
		},
	}

	err = validateLayout(testMb.Signed.(Layout))
	if err.Error() != "non unique step or inspection name found" {
		t.Error("validateLayout error - duplicate step/inspection name not " +
			"detected")
	}

	testMb = Metablock{
		Signed: Layout{
			Type:    "layout",
			Expires: "2020-02-27T18:03:43Z",
			Readme:  "some readme text",
			Steps: []Step{
				{
					Type: "step",
					SupplyChainItem: SupplyChainItem{
						Name: "foo",
					},
				},
			},
			Inspect: []Inspection{
				{
					Type: "inspection",
					SupplyChainItem: SupplyChainItem{
						Name: "foo",
					},
				},
			},
			Keys: map[string]Key{},
		},
	}

	err = validateLayout(testMb.Signed.(Layout))
	if err.Error() != "non unique step or inspection name found" {
		t.Error("validateLayout error - duplicate step/inspection name not " +
			"detected")
	}

	testMb = Metablock{
		Signed: Layout{
			Type:    "layout",
			Expires: "2020-02-27T18:03:43Z",
			Readme:  "some readme text",
			Steps:   []Step{},
			Inspect: []Inspection{
				{
					Type: "inspection",
					SupplyChainItem: SupplyChainItem{
						Name: "foo",
					},
				},
				{
					Type: "inspection",
					SupplyChainItem: SupplyChainItem{
						Name: "foo",
					},
				},
			},
			Keys: map[string]Key{},
		},
	}

	err = validateLayout(testMb.Signed.(Layout))
	if err.Error() != "non unique step or inspection name found" {
		t.Error("validateLayout error - duplicate step/inspection name not " +
			"detected")
	}

	testMb = Metablock{
		Signed: Layout{
			Type:    "layout",
			Expires: "2020-02-27T18:03:43Z",
			Readme:  "some readme text",
			Steps: []Step{
				{
					Type: "invalid",
					SupplyChainItem: SupplyChainItem{
						Name: "foo",
					},
				},
			},
			Inspect: []Inspection{},
			Keys:    map[string]Key{},
		},
	}

	err = validateLayout(testMb.Signed.(Layout))
	if err.Error() != "invalid Type value for step: should be 'step'" {
		t.Error("validateLayout - validateStep error - invalid step type not" +
			"detected")
	}
}

func TestValidateStep(t *testing.T) {
	testStep := Step{
		Type: "invalid",
		SupplyChainItem: SupplyChainItem{
			Name: "foo",
		},
	}
	err := validateStep(testStep)
	if err.Error() != "invalid Type value for step: should be 'step'" {
		t.Error("validateStep error - invalid type not detected")
	}

	testStep = Step{
		Type: "step",
		PubKeys: []string{"776a00e29f3559e0141b3b096f696abc6cfb0c657ab40f4Z" +
			"41132b345b08453f5"},
		SupplyChainItem: SupplyChainItem{
			Name: "foo",
		},
	}
	err = validateStep(testStep)
	if err.Error() != "keyid must be a lower case hex string, got: "+
		testStep.PubKeys[0] {
		t.Error("validateStep - validateHexSchema error - invalid key ID not " +
			"detected")
	}
}

func TestValidateHexSchema(t *testing.T) {
	testStr := "776a00e29f3559e0141b3b096f696abc6cfb0c657ab40f441132b345b" +
		"08453f5"
	if !validateHexSchema(testStr) {
		t.Errorf("validateHexSchema error - valid key ID flagged")
	}

	testStr = "Z776a00e29f3559e0141b3b096f696abc6cfb0c657ab40f441132b345b" +
		"08453f5"
	if validateHexSchema(testStr) {
		t.Errorf("validateHexSchema error - invalid key ID not detected")
	}
}

func TestValidatePubKey(t *testing.T) {
	testKey := Key{
		KeyId:   "776a00e29f3559e0141b3b096f696abc6cfb0c657ab40f441132b345b08453f5",
		KeyType: "rsa",
		KeyVal: KeyVal{
			Private: "",
			Public: "-----BEGIN PUBLIC KEY-----\nMIIBojANBgkqhkiG9w0BAQEFAAO" +
				"CAY8AMIIBigKCAYEAzgLBsMFSgwBiWTBmVsyW\n5KbJwLFSodAzdUhU2Bq6" +
				"SdRz/W6UOBGdojZXibxupjRtAaEQW/eXDe+1CbKg6ENZ\nGt2D9HGFCQZgQ" +
				"S8ONgNDQGiNxgApMA0T21AaUhru0vEofzdN1DfEF4CAGv5AkcgK\nsalhTy" +
				"ONervFIjFEdXGelFZ7dVMV3Pp5WkZPG0jFQWjnmDZhUrtSxEtqbVghc3kK" +
				"\nAUj9Ll/3jyi2wS92Z1j5ueN8X62hWX2xBqQ6nViOMzdujkoiYCRSwuMLR" +
				"qzW2CbT\nL8hF1+S5KWKFzxl5sCVfpPe7V5HkgEHjwCILXTbCn2fCMKlaSb" +
				"J/MG2lW7qSY2Ro\nwVXWkp1wDrsJ6Ii9f2dErv9vJeOVZeO9DsooQ5EuzLC" +
				"fQLEU5mn7ul7bU7rFsb8J\nxYOeudkNBatnNCgVMAkmDPiNA7E33bmL5ARR" +
				"wU0iZicsqLQR32pmwdap8PjofxqQ\nk7Gtvz/iYzaLrZv33cFWWTsEOqK1g" +
				"KqigSqgW9T26wO9AgMBAAE=\n-----END PUBLIC KEY-----",
		},
		Scheme: "rsassa-pss-sha256",
	}

	if err := validatePubKey(testKey); err != nil {
		t.Errorf("error validating public key: %s", err)
	}

	testKey = Key{
		KeyId:   "Z776a00e29f3559e0141b3b096f696abc6cfb0c657ab40f441132b345b08453f5",
		KeyType: "rsa",
		KeyVal: KeyVal{
			Private: "",
			Public: "-----BEGIN PUBLIC KEY-----\nMIIBojANBgkqhkiG9w0BAQEFAAO" +
				"CAY8AMIIBigKCAYEAzgLBsMFSgwBiWTBmVsyW\n5KbJwLFSodAzdUhU2Bq6" +
				"SdRz/W6UOBGdojZXibxupjRtAaEQW/eXDe+1CbKg6ENZ\nGt2D9HGFCQZgQ" +
				"S8ONgNDQGiNxgApMA0T21AaUhru0vEofzdN1DfEF4CAGv5AkcgK\nsalhTy" +
				"ONervFIjFEdXGelFZ7dVMV3Pp5WkZPG0jFQWjnmDZhUrtSxEtqbVghc3kK" +
				"\nAUj9Ll/3jyi2wS92Z1j5ueN8X62hWX2xBqQ6nViOMzdujkoiYCRSwuMLR" +
				"qzW2CbT\nL8hF1+S5KWKFzxl5sCVfpPe7V5HkgEHjwCILXTbCn2fCMKlaSb" +
				"J/MG2lW7qSY2Ro\nwVXWkp1wDrsJ6Ii9f2dErv9vJeOVZeO9DsooQ5EuzLC" +
				"fQLEU5mn7ul7bU7rFsb8J\nxYOeudkNBatnNCgVMAkmDPiNA7E33bmL5ARR" +
				"wU0iZicsqLQR32pmwdap8PjofxqQ\nk7Gtvz/iYzaLrZv33cFWWTsEOqK1g" +
				"KqigSqgW9T26wO9AgMBAAE=\n-----END PUBLIC KEY-----",
		},
		Scheme: "rsassa-pss-sha256",
	}

	err := validatePubKey(testKey)
	if err.Error() != "keyid must be a lower case hex string, got: "+
		testKey.KeyId {
		t.Error("validatePubKey error - invalid key ID not detected")
	}

	testKey = Key{
		KeyId:   "776a00e29f3559e0141b3b096f696abc6cfb0c657ab40f441132b345b08453f5",
		KeyType: "rsa",
		KeyVal: KeyVal{
			Private: "invalid",
			Public: "-----BEGIN PUBLIC KEY-----\nMIIBojANBgkqhkiG9w0BAQEFAAO" +
				"CAY8AMIIBigKCAYEAzgLBsMFSgwBiWTBmVsyW\n5KbJwLFSodAzdUhU2Bq6" +
				"SdRz/W6UOBGdojZXibxupjRtAaEQW/eXDe+1CbKg6ENZ\nGt2D9HGFCQZgQ" +
				"S8ONgNDQGiNxgApMA0T21AaUhru0vEofzdN1DfEF4CAGv5AkcgK\nsalhTy" +
				"ONervFIjFEdXGelFZ7dVMV3Pp5WkZPG0jFQWjnmDZhUrtSxEtqbVghc3kK" +
				"\nAUj9Ll/3jyi2wS92Z1j5ueN8X62hWX2xBqQ6nViOMzdujkoiYCRSwuMLR" +
				"qzW2CbT\nL8hF1+S5KWKFzxl5sCVfpPe7V5HkgEHjwCILXTbCn2fCMKlaSb" +
				"J/MG2lW7qSY2Ro\nwVXWkp1wDrsJ6Ii9f2dErv9vJeOVZeO9DsooQ5EuzLC" +
				"fQLEU5mn7ul7bU7rFsb8J\nxYOeudkNBatnNCgVMAkmDPiNA7E33bmL5ARR" +
				"wU0iZicsqLQR32pmwdap8PjofxqQ\nk7Gtvz/iYzaLrZv33cFWWTsEOqK1g" +
				"KqigSqgW9T26wO9AgMBAAE=\n-----END PUBLIC KEY-----",
		},
		Scheme: "rsassa-pss-sha256",
	}

	err = validatePubKey(testKey)
	if err.Error() != "private key found" {
		t.Error("validatePubKey error - private key not detected")
	}

	testKey = Key{
		KeyId:   "776a00e29f3559e0141b3b096f696abc6cfb0c657ab40f441132b345b08453f5",
		KeyType: "rsa",
		KeyVal: KeyVal{
			Private: "",
			Public:  "",
		},
		Scheme: "rsassa-pss-sha256",
	}

	err = validatePubKey(testKey)
	if err.Error() != "public key cannot be empty" {
		t.Error("validatePubKey error - private key not detected")
	}
}

func TestValidateMetablock(t *testing.T) {
	testMetablock := Metablock{
		Signatures: []Signature{
			{
				KeyId: "556caebdc0877eed53d419b60eddb1e57fa773e4e31d70698b58" +
					"8f3e9cc48b35",
				Sig: "02813858670c66647c17802d84f06453589f41850013a544609e9d" +
					"33ba21fa19280e8371701f8274fb0c56bd95ff4f34c418456b002af" +
					"9836ca218b584f51eb0eaacbb1c9bb57448101b07d058dec04d5255" +
					"51d157f6ae5e3679701735b1b8f52430f9b771d5476db1a2053cd93" +
					"e2354f20061178a01705f2fa9ac82c7aeca4dd830e2672eb2271271" +
					"78d52328747ac819e50ec8ff52c662d7a4c58f5040d8f655fe59580" +
					"4f3e47c4fc98434c44e914445f7cb773439ebf813de8849dd1b5339" +
					"58f99f671d4e023d34c110d4b169cc02c12a3755ebe537147ff2479" +
					"d244daaf719e24cf6b2fa6f47d0410d52d67217bcf4d4d4c2c7c0b9" +
					"2cd2bcd321edc69bc1430f78a188e712b8cb1fff0c14550cd01c41d" +
					"ae377256f31211fd249c5031bfee86e638bce6aa36aca349b787cef" +
					"48255b0ef04bd0a21adb37b2a3da888d1530ca6ddeae5261e6fd65a" +
					"a626d5caebbfae2986f842bd2ce94bcefe5dd0ae9c5b2028a15bd63" +
					"bbea61be732207f0f5b58d056f118c830981747cb2b245d1377e17",
			},
		},
		Signed: Layout{
			Type:    "layout",
			Expires: "2020-11-18T16:06:36Z",
			Readme:  "some readme text",
			Steps:   []Step{},
			Inspect: []Inspection{},
			Keys:    map[string]Key{},
		},
	}

	if err := validateMetablock(testMetablock); err != nil {
		t.Error("validateMetablock error: valid metablock failed")
	}

	testMetablock = Metablock{
		Signatures: []Signature{
			{
				KeyId: "556caebdc0877eed53d419b60eddb1e57fa773e4e31d70698b58" +
					"8f3e9cc48b35",
				Sig: "02813858670c66647c17802d84f06453589f41850013a544609e9d" +
					"33ba21fa19280e8371701f8274fb0c56bd95ff4f34c418456b002af" +
					"9836ca218b584f51eb0eaacbb1c9bb57448101b07d058dec04d5255" +
					"51d157f6ae5e3679701735b1b8f52430f9b771d5476db1a2053cd93" +
					"e2354f20061178a01705f2fa9ac82c7aeca4dd830e2672eb2271271" +
					"78d52328747ac819e50ec8ff52c662d7a4c58f5040d8f655fe59580" +
					"4f3e47c4fc98434c44e914445f7cb773439ebf813de8849dd1b5339" +
					"58f99f671d4e023d34c110d4b169cc02c12a3755ebe537147ff2479" +
					"d244daaf719e24cf6b2fa6f47d0410d52d67217bcf4d4d4c2c7c0b9" +
					"2cd2bcd321edc69bc1430f78a188e712b8cb1fff0c14550cd01c41d" +
					"ae377256f31211fd249c5031bfee86e638bce6aa36aca349b787cef" +
					"48255b0ef04bd0a21adb37b2a3da888d1530ca6ddeae5261e6fd65a" +
					"a626d5caebbfae2986f842bd2ce94bcefe5dd0ae9c5b2028a15bd63" +
					"bbea61be732207f0f5b58d056f118c830981747cb2b245d1377e17",
			},
		},
		Signed: Link{
			Type: "link",
			Name: "test_type",
			Command: []string{
				"tar",
				"zcvf",
				"foo.tar.gz",
				"foo.py",
			},
			Materials: map[string]interface{}{
				"foo.py": map[string]interface{}{
					"sha256": "74dc3727c6e89308b39e4dfedf787e37841198b1fa165a" +
						"27c013544a60502549",
				},
			},
			Products: map[string]interface{}{
				"foo.tar.gz": map[string]interface{}{
					"sha256": "52947cb78b91ad01fe81cd6aef42d1f6817e92b9e6936c" +
						"1e5aabb7c98514f355",
				},
			},
			ByProducts: map[string]interface{}{
				"return-value": float64(0),
				"stderr":       "a foo.py\n",
				"stdout":       "",
			},
			Environment: map[string]interface{}{},
		},
	}

	if err := validateMetablock(testMetablock); err != nil {
		t.Error("validateMetablock error: valid metablock failed")
	}

	testMetablock = Metablock{
		Signatures: []Signature{
			{
				KeyId: "556caebdc0877eed53d419b60eddb1e57fa773e4e31d70698b58" +
					"8f3e9cc48b35",
				Sig: "02813858670c66647c17802d84f06453589f41850013a544609e9d" +
					"33ba21fa19280e8371701f8274fb0c56bd95ff4f34c418456b002af" +
					"9836ca218b584f51eb0eaacbb1c9bb57448101b07d058dec04d5255" +
					"51d157f6ae5e3679701735b1b8f52430f9b771d5476db1a2053cd93" +
					"e2354f20061178a01705f2fa9ac82c7aeca4dd830e2672eb2271271" +
					"78d52328747ac819e50ec8ff52c662d7a4c58f5040d8f655fe59580" +
					"4f3e47c4fc98434c44e914445f7cb773439ebf813de8849dd1b5339" +
					"58f99f671d4e023d34c110d4b169cc02c12a3755ebe537147ff2479" +
					"d244daaf719e24cf6b2fa6f47d0410d52d67217bcf4d4d4c2c7c0b9" +
					"2cd2bcd321edc69bc1430f78a188e712b8cb1fff0c14550cd01c41d" +
					"ae377256f31211fd249c5031bfee86e638bce6aa36aca349b787cef" +
					"48255b0ef04bd0a21adb37b2a3da888d1530ca6ddeae5261e6fd65a" +
					"a626d5caebbfae2986f842bd2ce94bcefe5dd0ae9c5b2028a15bd63" +
					"bbea61be732207f0f5b58d056f118c830981747cb2b245d1377e17",
			},
		},
		Signed: Layout{
			Type:    "invalid",
			Expires: "2020-11-18T16:06:36Z",
			Readme:  "some readme text",
			Steps:   []Step{},
			Inspect: []Inspection{},
			Keys:    map[string]Key{},
		},
	}

	if err := validateMetablock(testMetablock); err.Error() !=
		"invalid Type value for layout: should be 'layout'" {
		t.Error("validateMetablock Error: invalid Type not detected")
	}

	testMetablock = Metablock{
		Signatures: []Signature{
			{
				KeyId: "556caebdc0877eed53d419b60eddb1e57fa773e4e31d70698b58" +
					"8f3e9cc48b35",
				Sig: "02813858670c66647c17802d84f06453589f41850013a544609e9d" +
					"33ba21fa19280e8371701f8274fb0c56bd95ff4f34c418456b002af" +
					"9836ca218b584f51eb0eaacbb1c9bb57448101b07d058dec04d5255" +
					"51d157f6ae5e3679701735b1b8f52430f9b771d5476db1a2053cd93" +
					"e2354f20061178a01705f2fa9ac82c7aeca4dd830e2672eb2271271" +
					"78d52328747ac819e50ec8ff52c662d7a4c58f5040d8f655fe59580" +
					"4f3e47c4fc98434c44e914445f7cb773439ebf813de8849dd1b5339" +
					"58f99f671d4e023d34c110d4b169cc02c12a3755ebe537147ff2479" +
					"d244daaf719e24cf6b2fa6f47d0410d52d67217bcf4d4d4c2c7c0b9" +
					"2cd2bcd321edc69bc1430f78a188e712b8cb1fff0c14550cd01c41d" +
					"ae377256f31211fd249c5031bfee86e638bce6aa36aca349b787cef" +
					"48255b0ef04bd0a21adb37b2a3da888d1530ca6ddeae5261e6fd65a" +
					"a626d5caebbfae2986f842bd2ce94bcefe5dd0ae9c5b2028a15bd63" +
					"bbea61be732207f0f5b58d056f118c830981747cb2b245d1377e17",
			},
		},
		Signed: Link{
			Type: "invalid",
			Name: "test_type",
			Command: []string{
				"tar",
				"zcvf",
				"foo.tar.gz",
				"foo.py",
			},
			Materials: map[string]interface{}{
				"foo.py": map[string]interface{}{
					"sha256": "74dc3727c6e89308b39e4dfedf787e37841198b1fa165a" +
						"27c013544a60502549",
				},
			},
			Products: map[string]interface{}{
				"foo.tar.gz": map[string]interface{}{
					"sha256": "52947cb78b91ad01fe81cd6aef42d1f6817e92b9e6936c" +
						"1e5aabb7c98514f355",
				},
			},
			ByProducts: map[string]interface{}{
				"return-value": float64(0),
				"stderr":       "a foo.py\n",
				"stdout":       "",
			},
			Environment: map[string]interface{}{},
		},
	}

	if err := validateMetablock(testMetablock); err.Error() !=
		"invalid type for link: should be 'link'" {
		t.Error("validateMetablock Error: invalid Type not detected")
	}

	testMetablock = Metablock{
		Signatures: []Signature{
			{
				KeyId: "Z556caebdc0877eed53d419b60eddb1e57fa773e4e31d70698b5" +
					"8f3e9cc48b35",
				Sig: "02813858670c66647c17802d84f06453589f41850013a544609e9d" +
					"33ba21fa19280e8371701f8274fb0c56bd95ff4f34c418456b002af" +
					"9836ca218b584f51eb0eaacbb1c9bb57448101b07d058dec04d5255" +
					"51d157f6ae5e3679701735b1b8f52430f9b771d5476db1a2053cd93" +
					"e2354f20061178a01705f2fa9ac82c7aeca4dd830e2672eb2271271" +
					"78d52328747ac819e50ec8ff52c662d7a4c58f5040d8f655fe59580" +
					"4f3e47c4fc98434c44e914445f7cb773439ebf813de8849dd1b5339" +
					"58f99f671d4e023d34c110d4b169cc02c12a3755ebe537147ff2479" +
					"d244daaf719e24cf6b2fa6f47d0410d52d67217bcf4d4d4c2c7c0b9" +
					"2cd2bcd321edc69bc1430f78a188e712b8cb1fff0c14550cd01c41d" +
					"ae377256f31211fd249c5031bfee86e638bce6aa36aca349b787cef" +
					"48255b0ef04bd0a21adb37b2a3da888d1530ca6ddeae5261e6fd65a" +
					"a626d5caebbfae2986f842bd2ce94bcefe5dd0ae9c5b2028a15bd63" +
					"bbea61be732207f0f5b58d056f118c830981747cb2b245d1377e17",
			},
		},
		Signed: Layout{
			Type:    "layout",
			Expires: "2020-11-18T16:06:36Z",
			Readme:  "some readme text",
			Steps:   []Step{},
			Inspect: []Inspection{},
			Keys:    map[string]Key{},
		},
	}

	if err := validateMetablock(testMetablock); err.Error() !=
		"keyid must be a lower case hex string, got: Z556caebdc0877eed53d419"+
			"b60eddb1e57fa773e4e31d70698b58f3e9cc48b35" {
		t.Error("validateMetablock Error: invalid key ID not detected")
	}

	testMetablock = Metablock{
		Signatures: []Signature{
			{
				KeyId: "556caebdc0877eed53d419b60eddb1e57fa773e4e31d70698b58" +
					"8f3e9cc48b35",
				Sig: "02813858670c66647c17802d84f06453589f41850013a544609e9z" +
					"33ba21fa19280e8371701f8274fb0c56bd95ff4f34c418456b002af" +
					"9836ca218b584f51eb0eaacbb1c9bb57448101b07d058dec04d5255" +
					"51d157f6ae5e3679701735b1b8f52430f9b771d5476db1a2053cd93" +
					"e2354f20061178a01705f2fa9ac82c7aeca4dd830e2672eb2271271" +
					"78d52328747ac819e50ec8ff52c662d7a4c58f5040d8f655fe59580" +
					"4f3e47c4fc98434c44e914445f7cb773439ebf813de8849dd1b5339" +
					"58f99f671d4e023d34c110d4b169cc02c12a3755ebe537147ff2479" +
					"d244daaf719e24cf6b2fa6f47d0410d52d67217bcf4d4d4c2c7c0b9" +
					"2cd2bcd321edc69bc1430f78a188e712b8cb1fff0c14550cd01c41d" +
					"ae377256f31211fd249c5031bfee86e638bce6aa36aca349b787cef" +
					"48255b0ef04bd0a21adb37b2a3da888d1530ca6ddeae5261e6fd65a" +
					"a626d5caebbfae2986f842bd2ce94bcefe5dd0ae9c5b2028a15bd63" +
					"bbea61be732207f0f5b58d056f118c830981747cb2b245d1377e17",
			},
		},
		Signed: Layout{
			Type:    "layout",
			Expires: "2020-11-18T16:06:36Z",
			Readme:  "some readme text",
			Steps:   []Step{},
			Inspect: []Inspection{},
			Keys:    map[string]Key{},
		},
	}

	if err := validateMetablock(testMetablock); err.Error() !=
		"signature must be a lower case hex string, got: 02813858670c66647c17"+
			"802d84f06453589f41850013a544609e9z33ba21fa19280e8371701f8274fb0c"+
			"56bd95ff4f34c418456b002af9836ca218b584f51eb0eaacbb1c9bb57448101b"+
			"07d058dec04d525551d157f6ae5e3679701735b1b8f52430f9b771d5476db1a2"+
			"053cd93e2354f20061178a01705f2fa9ac82c7aeca4dd830e2672eb227127178"+
			"d52328747ac819e50ec8ff52c662d7a4c58f5040d8f655fe595804f3e47c4fc9"+
			"8434c44e914445f7cb773439ebf813de8849dd1b533958f99f671d4e023d34c1"+
			"10d4b169cc02c12a3755ebe537147ff2479d244daaf719e24cf6b2fa6f47d041"+
			"0d52d67217bcf4d4d4c2c7c0b92cd2bcd321edc69bc1430f78a188e712b8cb1f"+
			"ff0c14550cd01c41dae377256f31211fd249c5031bfee86e638bce6aa36aca34"+
			"9b787cef48255b0ef04bd0a21adb37b2a3da888d1530ca6ddeae5261e6fd65aa"+
			"626d5caebbfae2986f842bd2ce94bcefe5dd0ae9c5b2028a15bd63bbea61be73"+
			"2207f0f5b58d056f118c830981747cb2b245d1377e17" {
		t.Error("validateMetablock error: invalid signature not detected")
	}
}

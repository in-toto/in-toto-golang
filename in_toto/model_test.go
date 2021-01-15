package in_toto

import (
	"encoding/hex"
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"reflect"
	"strings"
	"testing"
)

func TestMatchEcdsaScheme(t *testing.T) {
	curveSize := 224
	scheme := "ecdsa-sha2-nistp512"
	if err := matchEcdsaScheme(curveSize, scheme); err == nil {
		t.Errorf("matchEcdsaScheme should have failed with curveSize: %d and scheme: %s", curveSize, scheme)
	}
}

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
      "keys": "some keys", "expires": "some date", "cacerts": []}}`),
		[]byte(`{"signatures": [], "signed": {"_type": "layout",
			"inspect": "invalid", "readme": "some readme", "keys": "some keys",
      "expires": "some date", "cacerts": []}}`),
		[]byte(`{"signatures": [], "signed": {"_type": "layout",
			"steps": "invalid", "readme": "some readme", "keys": "some keys",
      "expires": "some date", "cacerts": []}}`),
		[]byte(`{"signatures": [], "signed": {"_type": "layout",
			"steps": "invalid", "inspect": "invalid", "readme": "some readme",
      "expires": "some date", "cacerts": []}}`),
		[]byte(`{"signatures": [], "signed": {"_type": "layout",
			"steps": "invalid", "inspect": "invalid", "readme": "some readme",
      "keys": "some keys", "cacerts": []}}`),
		[]byte(`{"signatures": [], "signed": {"_type": "layout",
			"steps": "invalid", "inspect": "invalid",
      "keys": "some keys", "expires": "some date", "cacerts": []}}`),
		[]byte(`{"signatures": [], "signed": {"_type": "layout", "steps": [],
			"inspect": [], "readme": "some readme", "keys": {},
      "expires": "some date", "foo": "bar", "cacerts": []}}`),
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
		if err := ioutil.WriteFile(fn, invalidJsonBytes[i], 0644); err != nil {
			fmt.Printf("Could not write file: %s", err)
		}
		var mb Metablock
		err := mb.Load(fn)
		if err == nil || !strings.Contains(err.Error(), expectedErrors[i]) {
			t.Errorf("Metablock.Load returned '%s', expected '%s' error", err,
				expectedErrors[i])
		}
		if err := os.Remove(fn); err != nil {
			t.Errorf("Unable to remove directory %s: %s", fn, err)
		}
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
	if err := mbMemory.Dump(fnTmp); err != nil {
		t.Errorf("JSON serialization failed: %s", err)
	}
	for _, fn := range []string{fnExisting, fnTmp} {
		var mbFile Metablock
		if err := mbFile.Load(fn); err != nil {
			t.Errorf("Could not parse Metablock: %s", err)
		}
		if !reflect.DeepEqual(mbMemory, mbFile) {
			t.Errorf("Dumped and Loaded Metablocks are not equal: \n%s\n\n\n%s\n",
				mbMemory, mbFile)
		}
	}
	// Remove temporary metablock file (keep other for remaining tests)
	if err := os.Remove(fnTmp); err != nil {
		t.Errorf("Unable to remove directory %s: %s", fnTmp, err)
	}
}

func TestMetablockGetSignableRepresentation(t *testing.T) {
	// Test successful metadata canonicalization with encoding corner cases
	// (unicode, escapes, non-string types, ...) and compare with reference
	var mb Metablock
	if err := mb.Load("canonical-test.link"); err != nil {
		t.Errorf("Cannot parse link file: %s", err)
	}
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
	if err := key.LoadKey("alice.pub", "rsassa-pss-sha256", []string{"sha256", "sha512"}); err != nil {
		t.Errorf("Cannot load public key file: %s", err)
	}
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
		"encoding/hex: invalid byte: U+0020 ' '",
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
	if err := mb.Load("demo.layout"); err != nil {
		t.Errorf("Cannot parse template file: %s", err)
	}
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
	if err.Error() != "invalid type for link 'test_type': should be 'link'" {
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
	if err.Error() != "in materials of link 'test_material_hash': in artifact"+
		" 'foo.py', sha256 hash value: invalid hex string: !@#$%" {
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
	if err.Error() != "in products of link 'test_product_hash': in artifact "+
		"'foo.tar.gz', sha256 hash value: invalid hex string: !@#$%" {
		t.Error("validateLink error - invalid hashes not detected")
	}
}

func TestValidateLayout(t *testing.T) {
	var mb Metablock
	if err := mb.Load("demo.layout"); err != nil {
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
	if err.Error() != "invalid Type value for step 'foo': should be 'step'" {
		t.Error("validateLayout - validateStep error - invalid step type not " +
			"detected")
	}

	cases := map[string]struct {
		Arg      Layout
		Expected string
	}{
		"invalid key map": {
			Layout{
				Type:    "layout",
				Expires: "2020-02-27T18:03:43Z",
				Keys: map[string]Key{
					"deadbeef": Key{KeyId: "livebeef"},
				},
			},
			"invalid key found",
		},
		"invalid rsa key": {
			Layout{
				Type:    "layout",
				Expires: "2020-02-27T18:03:43Z",
				Keys: map[string]Key{
					"deadbeef": Key{KeyId: "deadbeef"},
				},
			},
			"empty field in key: keytype",
		},
	}

	for name, tc := range cases {
		err := validateLayout(tc.Arg)
		if err == nil || !strings.Contains(err.Error(), tc.Expected) {
			t.Errorf("%s: '%s' not in '%s'", name, tc.Expected, err)
		}
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
	if err.Error() != "invalid Type value for step 'foo': should be 'step'" {
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
	if !errors.Is(err, ErrInvalidHexString) {
		t.Error("validateStep - validateHexString error - invalid key ID not " +
			"detected")
	}

	testStep = Step{
		Type: "step",
		SupplyChainItem: SupplyChainItem{
			Name: "",
		},
	}
	err = validateStep(testStep)
	if err.Error() != "step name cannot be empty" {
		t.Error("validateStep error - empty name not detected")
	}
}

func TestValidateInspection(t *testing.T) {
	testInspection := Inspection{
		Type: "invalid",
		SupplyChainItem: SupplyChainItem{
			Name: "foo",
		},
	}
	err := validateInspection(testInspection)
	if err.Error() != "invalid Type value for inspection 'foo': should be "+
		"'inspection'" {
		t.Error("validateInspection error - invalid type not detected")
	}
	testInspection = Inspection{
		Type: "inspection",
		SupplyChainItem: SupplyChainItem{
			Name: "",
		},
	}
	err = validateInspection(testInspection)
	if err.Error() != "inspection name cannot be empty" {
		t.Error("validateInspection error - empty name not detected")
	}

	testInspection = Inspection{
		Type: "inspection",
		SupplyChainItem: SupplyChainItem{
			Name: "inspect",
		},
	}
	err = validateInspection(testInspection)
	if err != nil {
		t.Error("validateInspection should successfully validate an inspection")
	}
}

func TestValidateHexSchema(t *testing.T) {
	testStr := "776a00e29f3559e0141b3b096f696abc6cfb0c657ab40f441132b345b" +
		"08453f5"
	if err := validateHexString(testStr); err != nil {
		t.Errorf("validateHexString error - valid key ID flagged")
	}

	testStr = "Z776a00e29f3559e0141b3b096f696abc6cfb0c657ab40f441132b345b" +
		"08453f5"
	if err := validateHexString(testStr); err == nil {
		t.Errorf("validateHexString error - invalid key ID not detected")
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

	err := validatePublicKey(testKey)
	if !errors.Is(err, nil) {
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

	err = validateKey(testKey)
	if !errors.Is(err, ErrInvalidHexString) {
		t.Error("validateKey error - invalid key ID not detected")
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

	err = validatePublicKey(testKey)
	if !errors.Is(err, ErrNoPublicKey) {
		t.Error("validateKey error - private key not detected")
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

	err = validateKey(testKey)
	if !errors.Is(err, ErrEmptyKeyField) {
		t.Error("validateKey error - empty public key not detected")
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
		"invalid type for link 'test_type': should be 'link'" {
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

	err := validateMetablock(testMetablock)
	if !errors.Is(err, ErrInvalidHexString) {
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

	err = validateMetablock(testMetablock)
	if !errors.Is(err, ErrInvalidHexString) {
		t.Error("validateMetablock error: invalid signature not detected")
	}

	cases := map[string]struct {
		Arg      Metablock
		Expected string
	}{
		"invalid type": {
			Metablock{Signed: "invalid"},
			"unknown type 'invalid', should be 'layout' or 'link'",
		},
	}
	for name, tc := range cases {
		err := validateMetablock(tc.Arg)
		if err == nil || !strings.Contains(err.Error(), tc.Expected) {
			t.Errorf("%s: '%s' not in '%s'", name, tc.Expected, err)
		}
	}
}

func TestValidateSupplyChainItem(t *testing.T) {
	cases := map[string]struct {
		Arg      SupplyChainItem
		Expected string
	}{
		"empty name": {SupplyChainItem{Name: ""}, "name cannot be empty"},
		"material rule": {
			SupplyChainItem{
				Name:              "test",
				ExpectedMaterials: [][]string{{"invalid"}}},
			"invalid material rule"},
		"product rule": {
			SupplyChainItem{
				Name:             "test",
				ExpectedProducts: [][]string{{"invalid"}}},
			"invalid product rule"},
	}

	for name, tc := range cases {
		err := validateSupplyChainItem(tc.Arg)
		if err == nil || !strings.Contains(err.Error(), tc.Expected) {
			t.Errorf("%s: '%s' not in '%s'", name, tc.Expected, err)
		}
	}
}

func TestMetablockSignWithRSA(t *testing.T) {
	var mb Metablock
	if err := mb.Load("demo.layout"); err != nil {
		t.Errorf("Cannot parse template file: %s", err)
	}
	invalidKey := Key{
		KeyId:               "test",
		KeyIdHashAlgorithms: nil,
		KeyType:             "rsa",
		KeyVal:              KeyVal{},
		Scheme:              "rsassa-pss-sha256",
	}

	if err := mb.Sign(invalidKey); err == nil {
		t.Errorf("signing with an invalid RSA key should fail")
	}
}

func TestMetablockSignWithEd25519(t *testing.T) {
	var mb Metablock
	if err := mb.Load("demo.layout"); err != nil {
		t.Errorf("Cannot parse template file: %s", err)
	}
	invalidKey := Key{
		KeyId:               "invalid",
		KeyIdHashAlgorithms: nil,
		KeyType:             "ed25519",
		KeyVal: KeyVal{
			Private: "BAD",
			Public:  "BAD",
		},
		Scheme: "ed25519",
	}

	if err := mb.Sign(invalidKey); err == nil {
		t.Errorf("signing with an invalid ed25519 key should fail")
	}
}

func TestMetaBlockSignWithEcdsa(t *testing.T) {
	var mb Metablock
	if err := mb.Load("demo.layout"); err != nil {
		t.Errorf("Cannot parse template file: %s", err)
	}
	invalidKey := Key{
		KeyId:               "invalid",
		KeyIdHashAlgorithms: nil,
		KeyType:             "ecdsa",
		KeyVal: KeyVal{
			Private: "BAD",
			Public:  "BAD",
		},
		Scheme: "ecdsa",
	}
	if err := mb.Sign(invalidKey); err == nil {
		t.Errorf("signing with an invalid ecdsa key should fail")
	}
}

func TestValidateKeyErrors(t *testing.T) {
	invalidTables := []struct {
		name string
		key  Key
		err  error
	}{
		{"empty key", Key{
			KeyId:               "",
			KeyIdHashAlgorithms: nil,
			KeyType:             "",
			KeyVal:              KeyVal{},
			Scheme:              "",
		}, ErrInvalidHexString},
		{"keytype missing", Key{
			KeyId:               "bad",
			KeyIdHashAlgorithms: []string{"sha256"},
			KeyType:             "",
			KeyVal: KeyVal{
				Private: "",
				Public:  "",
			},
			Scheme: "rsassa-psa-sha256",
		}, ErrEmptyKeyField},
		{"key scheme missing", Key{
			KeyId:               "bad",
			KeyIdHashAlgorithms: []string{"sha256"},
			KeyType:             "ed25519",
			KeyVal: KeyVal{
				Private: "bad",
				Public:  "bad",
			},
			Scheme: "",
		}, ErrEmptyKeyField},
		{
			name: "invalid key type",
			key: Key{
				KeyId:               "bad",
				KeyIdHashAlgorithms: []string{"sha256"},
				KeyType:             "invalid",
				KeyVal: KeyVal{
					Private: "invalid",
					Public:  "393e671b200f964c49083d34a867f5d989ec1c69df7b66758fe471c8591b139c",
				},
				Scheme: "ed25519",
			},
			err: ErrUnsupportedKeyType,
		},
		{
			name: "keytype scheme mismatch",
			key: Key{
				KeyId:               "be6371bc627318218191ce0780fd3183cce6c36da02938a477d2e4dfae1804a6",
				KeyIdHashAlgorithms: []string{"sha256"},
				KeyType:             "ed25519",
				KeyVal: KeyVal{
					Private: "29ad59693fe94c9d623afbb66554b4f6bb248c47761689ada4875ebda94840ae393e671b200f964c49083d34a867f5d989ec1c69df7b66758fe471c8591b139c",
					Public:  "393e671b200f964c49083d34a867f5d989ec1c69df7b66758fe471c8591b139c",
				},
				Scheme: "rsassa-pss-sha256",
			},
			err: ErrSchemeKeyTypeMismatch,
		},
		{
			name: "unsupported KeyIdHashAlgorithms",
			key: Key{
				KeyId:               "be6371bc627318218191ce0780fd3183cce6c36da02938a477d2e4dfae1804a6",
				KeyIdHashAlgorithms: []string{"sha128"},
				KeyType:             "ed25519",
				KeyVal: KeyVal{
					Private: "29ad59693fe94c9d623afbb66554b4f6bb248c47761689ada4875ebda94840ae393e671b200f964c49083d34a867f5d989ec1c69df7b66758fe471c8591b139c",
					Public:  "393e671b200f964c49083d34a867f5d989ec1c69df7b66758fe471c8591b139c",
				},
				Scheme: "ed25519",
			},
			err: ErrUnsupportedKeyIdHashAlgorithms,
		},
	}

	for _, table := range invalidTables {
		err := validateKey(table.key)
		if !errors.Is(err, table.err) {
			t.Errorf("test '%s' failed, expected error: '%s', got '%s'", table.name, table.err, err)
		}
	}
}

func TestValidateKeyVal(t *testing.T) {
	tables := []struct {
		name string
		key  Key
		err  error
	}{
		{
			name: "invalid rsa private key",
			key: Key{
				KeyId:               "bad",
				KeyIdHashAlgorithms: []string{"sha256"},
				KeyType:             "rsa",
				KeyVal: KeyVal{
					Private: "invalid",
					Public:  "-----BEGIN PUBLIC KEY-----\nMIIBojANBgkqhkiG9w0BAQEFAAOCAY8AMIIBigKCAYEAxPX3kFs/z645x4UOC3KF\nY3V80YQtKrp6YS3qU+Jlvx/XzK53lb4sCDRU9jqBBx3We45TmFUibroMd8tQXCUS\ne8gYCBUBqBmmz0dEHJYbW0tYF7IoapMIxhRYn76YqNdl1JoRTcmzIaOJ7QrHxQrS\nGpivvTm6kQ9WLeApG1GLYJ3C3Wl4bnsI1bKSv55Zi45/JawHzTzYUAIXX9qCd3Io\nHzDucz9IAj9Ookw0va/q9FjoPGrRB80IReVxLVnbo6pYJfu/O37jvEobHFa8ckHd\nYxUIg8wvkIOy1O3M74lBDm6CVI0ZO25xPlDB/4nHAE1PbA3aF3lw8JGuxLDsetxm\nfzgAleVt4vXLQiCrZaLf+0cM97JcT7wdHcbIvRLsij9LNP+2tWZgeZ/hIAOEdaDq\ncYANPDIAxfTvbe9I0sXrCtrLer1SS7GqUmdFCdkdun8erXdNF0ls9Rp4cbYhjdf3\nyMxdI/24LUOOQ71cHW3ITIDImm6I8KmrXFM2NewTARKfAgMBAAE=\n-----END PUBLIC KEY-----",
				},
				Scheme: "rsassa-pss-sha256",
			},
			err: ErrNoPEMBlock,
		},
		{
			name: "invalid rsa pub key",
			key: Key{
				KeyId:               "bad",
				KeyIdHashAlgorithms: []string{"sha256"},
				KeyType:             "rsa",
				KeyVal: KeyVal{
					Private: "",
					Public:  "invalid",
				},
				Scheme: "rsassa-pss-sha256",
			},
			err: ErrNoPEMBlock,
		},
		{
			name: "invalid ed25519 public key",
			key: Key{
				KeyId:               "bad",
				KeyIdHashAlgorithms: []string{"sha256"},
				KeyType:             "ed25519",
				KeyVal: KeyVal{
					Private: "invalid",
					Public:  "invalid",
				},
				Scheme: "ed25519",
			},
			err: ErrInvalidHexString,
		},
		{
			name: "invalid ed25519 private key",
			key: Key{
				KeyId:               "bad",
				KeyIdHashAlgorithms: []string{"sha256"},
				KeyType:             "ed25519",
				KeyVal: KeyVal{
					Private: "invalid",
					Public:  "393e671b200f964c49083d34a867f5d989ec1c69df7b66758fe471c8591b139c",
				},
				Scheme: "ed25519",
			},
			err: ErrInvalidHexString,
		},
		{
			name: "valid rsa public, but bad private key",
			key: Key{
				KeyId:               "b7d643dec0a051096ee5d87221b5d91a33daa658699d30903e1cefb90c418401",
				KeyIdHashAlgorithms: []string{"sha256"},
				KeyType:             "rsa",
				KeyVal: KeyVal{
					Private: "-----BEGIN PRIVATE KEY-----\nMIHuAgEAMBAGByqGSM49AgEGBSuBBAAjBIHWMIHTAgEBBEIB6fQnV71xKx6kFgJv\nYTMq0ytvWi2mDlYu6aNm1761c1OSInbBxBNb0ligpM65KyaeeRce6JR9eQW6TB6R\n+5pNzvOhgYkDgYYABAFy0CeDAyV/2mY1NqxLLgqEXSxaqM3fM8gYn/ZWzrLnO+1h\nK2QAanID3JuPff1NdhehhL/U1prXdyyaItA5X4ChkQHMTsiS/3HkWRuLR8L22SGs\nB+7KqOeO5ELkqHO5tsy4kvsNrmersCGRQGY6A5V/0JFhP1u1JUvAVVhfRbdQXuu3\nrw==\n-----END PRIVATE KEY-----\n",
					Public:  "-----BEGIN PUBLIC KEY-----\nMIIBojANBgkqhkiG9w0BAQEFAAOCAY8AMIIBigKCAYEAyCTik98953hKl6+B6n5l\n8DVIDwDnvrJfpasbJ3+Rw66YcawOZinRpMxPTqWBKs7sRop7jqsQNcslUoIZLrXP\nr3foPHF455TlrqPVfCZiFQ+O4CafxWOB4mL1NddvpFXTEjmUiwFrrL7PcvQKMbYz\neUHH4tH9MNzqKWbbJoekBsDpCDIxp1NbgivGBKwjRGa281sClKgpd0Q0ebl+RTcT\nvpfZVDbXazQ7VqZkidt7geWq2BidOXZp/cjoXyVneKx/gYiOUv8x94svQMzSEhw2\nLFMQ04A1KnGn1jxO35/fd6/OW32njyWs96RKu9UQVacYHsQfsACPWwmVqgnX/sp5\nujlvSDjyfZu7c5yUQ2asYfQPLvnjG+u7QcBukGf8hAfVgsezzX9QPiK35BKDgBU/\nVk43riJs165TJGYGVuLUhIEhHgiQtwo8pUTJS5npEe5XMDuZoighNdzoWY2nfsBf\np8348k6vJtDMB093/t6V9sTGYQcSbgKPyEQo5Pk6Wd4ZAgMBAAE=\n-----END PUBLIC KEY-----",
				},
				Scheme: "rsassa-pss-sha256",
			},
			err: ErrKeyKeyTypeMismatch,
		},
		{
			name: "valid ecdsa public key, but invalid ecdsa private key",
			key: Key{
				KeyId:               "b7d643dec0a051096ee5d87221b5d91a33daa658699d30903e1cefb90c418401",
				KeyIdHashAlgorithms: []string{"sha256"},
				KeyType:             "ecdsa",
				KeyVal: KeyVal{
					Private: "-----BEGIN RSA PRIVATE KEY-----\n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\n-----END RSA PRIVATE KEY-----",
					Public:  "-----BEGIN PUBLIC KEY-----\nMIGbMBAGByqGSM49AgEGBSuBBAAjA4GGAAQBctAngwMlf9pmNTasSy4KhF0sWqjN\n3zPIGJ/2Vs6y5zvtYStkAGpyA9ybj339TXYXoYS/1Naa13csmiLQOV+AoZEBzE7I\nkv9x5Fkbi0fC9tkhrAfuyqjnjuRC5KhzubbMuJL7Da5nq7AhkUBmOgOVf9CRYT9b\ntSVLwFVYX0W3UF7rt68=\n-----END PUBLIC KEY-----\n",
				},
				Scheme: "ecdsa",
			},
			err: ErrKeyKeyTypeMismatch,
		},
		{
			name: "rsa key, but with ed25519 private key",
			key: Key{
				KeyId:               "b7d643dec0a051096ee5d87221b5d91a33daa658699d30903e1cefb90c418401",
				KeyIdHashAlgorithms: []string{"sha256"},
				KeyType:             "rsa",
				KeyVal: KeyVal{
					Private: "-----BEGIN PRIVATE KEY-----\nMC4CAQAwBQYDK2VwBCIEICmtWWk/6UydYjr7tmVUtPa7JIxHdhaJraSHXr2pSECu\n-----END PRIVATE KEY-----\n",
					Public:  "-----BEGIN PUBLIC KEY-----\nMIIBojANBgkqhkiG9w0BAQEFAAOCAY8AMIIBigKCAYEAyCTik98953hKl6+B6n5l\n8DVIDwDnvrJfpasbJ3+Rw66YcawOZinRpMxPTqWBKs7sRop7jqsQNcslUoIZLrXP\nr3foPHF455TlrqPVfCZiFQ+O4CafxWOB4mL1NddvpFXTEjmUiwFrrL7PcvQKMbYz\neUHH4tH9MNzqKWbbJoekBsDpCDIxp1NbgivGBKwjRGa281sClKgpd0Q0ebl+RTcT\nvpfZVDbXazQ7VqZkidt7geWq2BidOXZp/cjoXyVneKx/gYiOUv8x94svQMzSEhw2\nLFMQ04A1KnGn1jxO35/fd6/OW32njyWs96RKu9UQVacYHsQfsACPWwmVqgnX/sp5\nujlvSDjyfZu7c5yUQ2asYfQPLvnjG+u7QcBukGf8hAfVgsezzX9QPiK35BKDgBU/\nVk43riJs165TJGYGVuLUhIEhHgiQtwo8pUTJS5npEe5XMDuZoighNdzoWY2nfsBf\np8348k6vJtDMB093/t6V9sTGYQcSbgKPyEQo5Pk6Wd4ZAgMBAAE=\n-----END PUBLIC KEY-----",
				},
				Scheme: "rsassa-pss-sha256",
			},
			err: ErrInvalidKey,
		},
		{
			name: "unsupported key type",
			key: Key{
				KeyId:               "",
				KeyIdHashAlgorithms: nil,
				KeyType:             "invalid",
				KeyVal:              KeyVal{},
				Scheme:              "",
			},
			err: ErrUnsupportedKeyType,
		},
		{
			name: "rsa key type, but ed25519 key",
			key: Key{
				KeyId:               "b7d643dec0a051096ee5d87221b5d91a33daa658699d30903e1cefb90c418401",
				KeyIdHashAlgorithms: []string{"sha256"},
				KeyType:             "rsa",
				KeyVal: KeyVal{
					Private: "-----BEGIN PRIVATE KEY-----\nMC4CAQAwBQYDK2VwBCIEICmtWWk/6UydYjr7tmVUtPa7JIxHdhaJraSHXr2pSECu\n-----END PRIVATE KEY-----\n",
					Public:  "-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEAOT5nGyAPlkxJCD00qGf12YnsHGnfe2Z1j+RxyFkbE5w=\n-----END PUBLIC KEY-----\n",
				},
				Scheme: "rsassa-pss-sha256",
			},
			err: ErrInvalidKey,
		},
		{
			name: "rsa key, but not ecdsa key type",
			key: Key{
				KeyId:               "b7d643dec0a051096ee5d87221b5d91a33daa658699d30903e1cefb90c418401",
				KeyIdHashAlgorithms: []string{"sha256"},
				KeyType:             "ecdsa",
				KeyVal: KeyVal{
					Private: "",
					Public:  "-----BEGIN PUBLIC KEY-----\nMIIBojANBgkqhkiG9w0BAQEFAAOCAY8AMIIBigKCAYEAyCTik98953hKl6+B6n5l\n8DVIDwDnvrJfpasbJ3+Rw66YcawOZinRpMxPTqWBKs7sRop7jqsQNcslUoIZLrXP\nr3foPHF455TlrqPVfCZiFQ+O4CafxWOB4mL1NddvpFXTEjmUiwFrrL7PcvQKMbYz\neUHH4tH9MNzqKWbbJoekBsDpCDIxp1NbgivGBKwjRGa281sClKgpd0Q0ebl+RTcT\nvpfZVDbXazQ7VqZkidt7geWq2BidOXZp/cjoXyVneKx/gYiOUv8x94svQMzSEhw2\nLFMQ04A1KnGn1jxO35/fd6/OW32njyWs96RKu9UQVacYHsQfsACPWwmVqgnX/sp5\nujlvSDjyfZu7c5yUQ2asYfQPLvnjG+u7QcBukGf8hAfVgsezzX9QPiK35BKDgBU/\nVk43riJs165TJGYGVuLUhIEhHgiQtwo8pUTJS5npEe5XMDuZoighNdzoWY2nfsBf\np8348k6vJtDMB093/t6V9sTGYQcSbgKPyEQo5Pk6Wd4ZAgMBAAE=\n-----END PUBLIC KEY-----",
				},
				Scheme: "ecdsa",
			},
			err: ErrKeyKeyTypeMismatch,
		},
		{
			name: "ecdsa key, but rsa key type",
			key: Key{
				KeyId:               "b7d643dec0a051096ee5d87221b5d91a33daa658699d30903e1cefb90c418401",
				KeyIdHashAlgorithms: []string{"sha256"},
				KeyType:             "rsa",
				KeyVal: KeyVal{
					Private: "-----BEGIN PRIVATE KEY-----\nMIHuAgEAMBAGByqGSM49AgEGBSuBBAAjBIHWMIHTAgEBBEIB6fQnV71xKx6kFgJv\nYTMq0ytvWi2mDlYu6aNm1761c1OSInbBxBNb0ligpM65KyaeeRce6JR9eQW6TB6R\n+5pNzvOhgYkDgYYABAFy0CeDAyV/2mY1NqxLLgqEXSxaqM3fM8gYn/ZWzrLnO+1h\nK2QAanID3JuPff1NdhehhL/U1prXdyyaItA5X4ChkQHMTsiS/3HkWRuLR8L22SGs\nB+7KqOeO5ELkqHO5tsy4kvsNrmersCGRQGY6A5V/0JFhP1u1JUvAVVhfRbdQXuu3\nrw==\n-----END PRIVATE KEY-----\n",
					Public:  "-----BEGIN PUBLIC KEY-----\nMIGbMBAGByqGSM49AgEGBSuBBAAjA4GGAAQBctAngwMlf9pmNTasSy4KhF0sWqjN\n3zPIGJ/2Vs6y5zvtYStkAGpyA9ybj339TXYXoYS/1Naa13csmiLQOV+AoZEBzE7I\nkv9x5Fkbi0fC9tkhrAfuyqjnjuRC5KhzubbMuJL7Da5nq7AhkUBmOgOVf9CRYT9b\ntSVLwFVYX0W3UF7rt68=\n-----END PUBLIC KEY-----\n",
				},
				Scheme: "rsassa-pss-sha256",
			},
			err: ErrKeyKeyTypeMismatch,
		},
		{
			name: "ecdsa key, but rsa key type",
			key: Key{
				KeyId:               "b7d643dec0a051096ee5d87221b5d91a33daa658699d30903e1cefb90c418401",
				KeyIdHashAlgorithms: []string{"sha256"},
				KeyType:             "ecdsa",
				KeyVal: KeyVal{
					Private: "-----BEGIN PRIVATE KEY-----\nMIHuAgEAMBAGByqGSM49AgEGBSuBBAAjBIHWMIHTAgEBBEIB6fQnV71xKx6kFgJv\nYTMq0ytvWi2mDlYu6aNm1761c1OSInbBxBNb0ligpM65KyaeeRce6JR9eQW6TB6R\n+5pNzvOhgYkDgYYABAFy0CeDAyV/2mY1NqxLLgqEXSxaqM3fM8gYn/ZWzrLnO+1h\nK2QAanID3JuPff1NdhehhL/U1prXdyyaItA5X4ChkQHMTsiS/3HkWRuLR8L22SGs\nB+7KqOeO5ELkqHO5tsy4kvsNrmersCGRQGY6A5V/0JFhP1u1JUvAVVhfRbdQXuu3\nrw==\n-----END PRIVATE KEY-----\n",
					Public:  "-----BEGIN PUBLIC KEY-----\nMIGbMBAGByqGSM49AgEGBSuBBAAjA4GGAAQBctAngwMlf9pmNTasSy4KhF0sWqjN\n3zPIGJ/2Vs6y5zvtYStkAGpyA9ybj339TXYXoYS/1Naa13csmiLQOV+AoZEBzE7I\nkv9x5Fkbi0fC9tkhrAfuyqjnjuRC5KhzubbMuJL7Da5nq7AhkUBmOgOVf9CRYT9b\ntSVLwFVYX0W3UF7rt68=\n-----END PUBLIC KEY-----\n",
				},
				Scheme: "ecdsa",
			},
			err: nil,
		},
	}
	for _, table := range tables {
		err := validateKeyVal(table.key)
		if !errors.Is(err, table.err) {
			t.Errorf("test '%s' failed, expected error: '%s', got '%s'", table.name, table.err, err)
		}
	}
}

func TestMatchKeyTypeScheme(t *testing.T) {
	tables := []struct {
		name string
		key  Key
		err  error
	}{
		{name: "test for unsupported key type",
			key: Key{
				KeyId:               "",
				KeyIdHashAlgorithms: nil,
				KeyType:             "invalid",
				KeyVal:              KeyVal{},
				Scheme:              "",
			},
			err: ErrUnsupportedKeyType,
		},
		{
			name: "test for scheme key type mismatch",
			key: Key{
				KeyId:               "",
				KeyIdHashAlgorithms: nil,
				KeyType:             "rsa",
				KeyVal:              KeyVal{},
				Scheme:              "ed25519",
			},
			err: ErrSchemeKeyTypeMismatch,
		},
	}
	for _, table := range tables {
		err := matchKeyTypeScheme(table.key)
		if !errors.Is(err, table.err) {
			t.Errorf("%s returned wrong error. We got: %s, we should have got: %s", table.name, err, table.err)
		}
	}
}

func TestValidatePublicKey(t *testing.T) {
	validTables := []struct {
		name string
		key  Key
	}{
		{
			name: "test with valid key",
			key: Key{
				KeyId:               "be6371bc627318218191ce0780fd3183cce6c36da02938a477d2e4dfae1804a6",
				KeyIdHashAlgorithms: []string{"sha512"},
				KeyType:             "ed25519",
				KeyVal: KeyVal{
					Private: "",
					Public:  "-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEAOT5nGyAPlkxJCD00qGf12YnsHGnfe2Z1j+RxyFkbE5w=\n-----END PUBLIC KEY-----\n",
				},
				Scheme: "ed25519",
			},
		},
	}
	for _, table := range validTables {
		err := validatePublicKey(table.key)
		if err != nil {
			t.Errorf("%s returned error %s, instead of nil", table.name, err)
		}
	}

	invalidTables := []struct {
		name string
		key  Key
		err  error
	}{
		{
			name: "test with valid key",
			key: Key{
				KeyId:               "be6371bc627318218191ce0780fd3183cce6c36da02938a477d2e4dfae1804a6",
				KeyIdHashAlgorithms: []string{"sha512"},
				KeyType:             "ed25519",
				KeyVal: KeyVal{
					Private: "-----BEGIN PRIVATE KEY-----\nMC4CAQAwBQYDK2VwBCIEICmtWWk/6UydYjr7tmVUtPa7JIxHdhaJraSHXr2pSECu\n-----END PRIVATE KEY-----\n",
					Public:  "-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEAOT5nGyAPlkxJCD00qGf12YnsHGnfe2Z1j+RxyFkbE5w=\n-----END PUBLIC KEY-----\n",
				},
				Scheme: "ed25519",
			},
			err: ErrNoPublicKey,
		},
	}
	for _, table := range invalidTables {
		err := validatePublicKey(table.key)
		if err != table.err {
			t.Errorf("%s returned unexpected error %s, we should got: %s", table.name, err, table.err)
		}
	}
}

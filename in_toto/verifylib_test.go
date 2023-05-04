package in_toto

import (
	"bytes"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestInTotoVerifyPass(t *testing.T) {
	t.Run("metablock layout", func(t *testing.T) {
		layoutPath := "demo.layout"
		pubKeyPath := "alice.pub"
		linkDir := "."

		layoutMb, err := LoadMetadata(layoutPath)
		if err != nil {
			t.Fatal(err)
		}

		var pubKey Key
		if err := pubKey.LoadKey(pubKeyPath, "rsassa-pss-sha256", []string{"sha256", "sha512"}); err != nil {
			t.Error(err)
		}

		var layoutKeys = map[string]Key{
			pubKey.KeyID: pubKey,
		}

		// No error should occur
		if _, err := InTotoVerify(layoutMb, layoutKeys, linkDir, "",
			make(map[string]string), [][]byte{}, testOSisWindows()); err != nil {
			t.Error(err)
		}
	})

	t.Run("DSSE layout", func(t *testing.T) {
		layoutPath := "demo.dsse.layout" // This layout is identical to demo.layout minus the signature wrapper
		pubKeyPath := "alice.pub"
		linkDir := "."

		layoutEnv, err := LoadMetadata(layoutPath)
		if err != nil {
			t.Fatal(err)
		}

		var pubKey Key
		if err := pubKey.LoadKey(pubKeyPath, "rsassa-pss-sha256", []string{"sha256", "sha512"}); err != nil {
			t.Error(err)
		}

		var layoutKeys = map[string]Key{
			pubKey.KeyID: pubKey,
		}

		// No error should occur, verification is using a DSSE layout and Metablock links
		if _, err := InTotoVerify(layoutEnv, layoutKeys, linkDir, "",
			make(map[string]string), [][]byte{}, testOSisWindows()); err != nil {
			t.Error(err)
		}
	})

	t.Run("verifying with only DSSE metadata", func(t *testing.T) {
		layoutPath := "dsse-only.root.layout" // This layout is from in-toto/demo but skips the inspection
		pubKeyPath := "alice.pub"
		linkDir := "."

		layoutEnv, err := LoadMetadata(layoutPath)
		if err != nil {
			t.Fatal(err)
		}

		var pubKey Key
		if err := pubKey.LoadKey(pubKeyPath, "rsassa-pss-sha256", []string{"sha256", "sha512"}); err != nil {
			t.Error(err)
		}

		var layoutKeys = map[string]Key{
			pubKey.KeyID: pubKey,
		}

		// No error should occur, verification is using a DSSE layout and links
		if _, err := InTotoVerify(layoutEnv, layoutKeys, linkDir, "",
			make(map[string]string), [][]byte{}, testOSisWindows()); err != nil {
			t.Error(err)
		}
	})
}

func TestGetSummaryLink(t *testing.T) {
	demoLayout, err := LoadMetadata("demo.layout")
	if err != nil {
		t.Fatal(err)
	}
	codeLink, err := LoadMetadata("write-code.b7d643de.link")
	if err != nil {
		t.Error(err)
	}
	packageLink, err := LoadMetadata("package.d3ffd108.link")
	if err != nil {
		t.Error(err)
	}
	demoLink := make(map[string]Metadata)
	demoLink["write-code"] = codeLink
	demoLink["package"] = packageLink

	var summaryLink Metadata
	if summaryLink, err = GetSummaryLink(demoLayout.GetPayload().(Layout),
		demoLink, "", false); err != nil {
		t.Error(err)
	}
	if summaryLink.GetPayload().(Link).Type != codeLink.GetPayload().(Link).Type {
		t.Errorf("summary Link isn't of type Link")
	}
	if summaryLink.GetPayload().(Link).Name != "" {
		t.Errorf("summary Link name doesn't match. Expected '%s', returned "+
			"'%s", codeLink.GetPayload().(Link).Name, summaryLink.GetPayload().(Link).Name)
	}
	if !reflect.DeepEqual(summaryLink.GetPayload().(Link).Materials,
		codeLink.GetPayload().(Link).Materials) {
		t.Errorf("summary Link materials don't match. Expected '%s', "+
			"returned '%s", codeLink.GetPayload().(Link).Materials,
			summaryLink.GetPayload().(Link).Materials)
	}

	if !reflect.DeepEqual(summaryLink.GetPayload().(Link).Products,
		packageLink.GetPayload().(Link).Products) {
		t.Errorf("summary Link products don't match. Expected '%s', "+
			"returned '%s", packageLink.GetPayload().(Link).Products,
			summaryLink.GetPayload().(Link).Products)
	}
	if !reflect.DeepEqual(summaryLink.GetPayload().(Link).Command,
		packageLink.GetPayload().(Link).Command) {
		t.Errorf("summary Link command doesn't match. Expected '%s', "+
			"returned '%s", packageLink.GetPayload().(Link).Command,
			summaryLink.GetPayload().(Link).Command)
	}
	if !reflect.DeepEqual(summaryLink.GetPayload().(Link).ByProducts,
		packageLink.GetPayload().(Link).ByProducts) {
		t.Errorf("summary Link by-products don't match. Expected '%s', "+
			"returned '%s", packageLink.GetPayload().(Link).ByProducts,
			summaryLink.GetPayload().(Link).ByProducts)
	}
}

func TestVerifySublayouts(t *testing.T) {
	sublayoutName := "sub_layout"
	var aliceKey Key
	if err := aliceKey.LoadKey("alice.pub", "rsassa-pss-sha256", []string{"sha256", "sha512"}); err != nil {
		t.Errorf("unable to load Alice's public key")
	}
	sublayoutDirectory := fmt.Sprintf(SublayoutLinkDirFormat, sublayoutName,
		aliceKey.KeyID)
	defer func(sublayoutDirectory string) {
		if err := os.RemoveAll(sublayoutDirectory); err != nil {
			t.Errorf("unable to remove directory %s: %s", sublayoutDirectory, err)
		}
	}(sublayoutDirectory)

	if err := os.Mkdir(sublayoutDirectory, 0700); err != nil {
		t.Errorf("unable to create sublayout directory")
	}
	writeCodePath := path.Join(sublayoutDirectory, "write-code.b7d643de.link")
	if err := os.Link("write-code.b7d643de.link", writeCodePath); err != nil {
		t.Errorf("unable to link write-code metadata.")
	}
	packagePath := path.Join(sublayoutDirectory, "package.d3ffd108.link")
	if err := os.Link("package.d3ffd108.link", packagePath); err != nil {
		t.Errorf("unable to link package metadata")
	}

	superLayoutMb, err := LoadMetadata("super.layout")
	if err != nil {
		t.Errorf("unable to load super layout")
	}

	stepsMetadata, err := LoadLinksForLayout(superLayoutMb.GetPayload().(Layout), ".")
	if err != nil {
		t.Errorf("unable to load link metadata for super layout")
	}

	rootCertPool, intermediateCertPool, err := LoadLayoutCertificates(superLayoutMb.GetPayload().(Layout), [][]byte{})
	if err != nil {
		t.Errorf("unable to load layout certificates")
	}

	stepsMetadataVerified, err := VerifyLinkSignatureThesholds(
		superLayoutMb.GetPayload().(Layout), stepsMetadata, rootCertPool, intermediateCertPool)
	if err != nil {
		t.Errorf("unable to verify link threshold values: %v", err)
	}

	result, err := VerifySublayouts(superLayoutMb.GetPayload().(Layout),
		stepsMetadataVerified, ".", [][]byte{}, testOSisWindows())
	if err != nil {
		t.Errorf("unable to verify sublayouts: %v", err)
	}

	for _, stepData := range result {
		for _, metadata := range stepData {
			if _, ok := metadata.GetPayload().(Link); !ok {
				t.Errorf("sublayout expansion error: found non link")
			}
		}
	}
}

func TestRunInspections(t *testing.T) {
	// Load layout template used as basis for all tests
	mb, err := LoadMetadata("demo.layout")
	if err != nil {
		t.Errorf("unable to parse template file: %s", err)
	}
	layout := mb.GetPayload().(Layout)

	// Test 1
	// Successfully run two inspections foo and bar, testing that each generates
	// a link file and they record the correct materials and products.
	layout.Inspect = []Inspection{
		{
			SupplyChainItem: SupplyChainItem{Name: "foo"},
			Run:             []string{"sh", "-c", "true"},
		},
		{
			SupplyChainItem: SupplyChainItem{Name: "bar"},
			Run:             []string{"sh", "-c", "true"},
		},
	}

	// Make a list of files in current dir (all must be recorded as artifacts)
	availableFiles, _ := filepath.Glob("*")
	result, err := RunInspections(layout, "", testOSisWindows(), false)

	// Error must be nil
	if err != nil {
		t.Errorf("RunInspections returned %s as error, expected nil.",
			err)
	}

	// Assert contents of inspection link metadata for both inspections
	for _, inspectionName := range []string{"foo", "bar"} {
		// Available files must be sorted after each inspection because the link
		// file is added below
		sort.Strings(availableFiles)
		// Compare material and products (only file names) to files that were
		// in the directory before calling RunInspections
		materialNames := InterfaceKeyStrings(result[inspectionName].GetPayload().(Link).Materials)
		productNames := InterfaceKeyStrings(result[inspectionName].GetPayload().(Link).Products)
		sort.Strings(materialNames)
		sort.Strings(productNames)
		if !reflect.DeepEqual(materialNames, availableFiles) ||
			!reflect.DeepEqual(productNames, availableFiles) {
			t.Errorf("RunInspections recorded materials and products '%s' and %s'"+
				" for insepction '%s', expected '%s' and '%s'.", materialNames,
				productNames, inspectionName, availableFiles, availableFiles)
		}
		linkName := inspectionName + ".link"
		// Append link created by an inspection to available files because it
		// is recorded by succeeding inspections
		availableFiles = append(availableFiles, linkName)

		// Remove generated inspection link
		err = os.Remove(linkName)
		if os.IsNotExist(err) {
			t.Errorf("RunInspections didn't generate expected '%s'", linkName)
		}
	}

	// Test 2
	// Fail RunInspections due to inexistent command
	layout.Inspect = []Inspection{
		{
			SupplyChainItem: SupplyChainItem{Name: "foo"},
			Run:             []string{"command-does-not-exist"},
		},
	}

	result, err = RunInspections(layout, "", testOSisWindows(), false)
	if result != nil || err == nil {
		t.Errorf("RunInspections returned '(%s, %s)', expected"+
			" '(nil, *exec.Error)'", result, err)
	}

	// Test 2
	// Fail RunInspections due to non-zero exiting command
	layout.Inspect = []Inspection{
		{
			SupplyChainItem: SupplyChainItem{Name: "foo"},
			Run:             []string{"sh", "-c", "false"},
		},
	}
	result, err = RunInspections(layout, "", testOSisWindows(), false)
	if result != nil || err == nil {
		t.Errorf("RunInspections returned '(%s, %s)', expected"+
			" '(nil, *exec.Error)'", result, err)
	}
}

func TestVerifyArtifact(t *testing.T) {
	var testCases = []struct {
		name      string
		item      []interface{}
		metadata  map[string]Metadata
		expectErr string
	}{
		{
			name: "Verify artifacts",
			item: []interface{}{
				Step{
					SupplyChainItem: SupplyChainItem{
						Name: "foo",
						ExpectedMaterials: [][]string{
							{"DELETE", "foo-delete"},
							{"MODIFY", "foo-modify"},
							{"MATCH", "foo-match", "WITH", "MATERIALS", "FROM", "foo"}, // not-modify
							{"ALLOW", "foo-allow"},
							{"DISALLOW", "*"},
						},
						ExpectedProducts: [][]string{
							{"CREATE", "foo-create"},
							{"MODIFY", "foo-modify"},
							{"MATCH", "foo-match", "WITH", "MATERIALS", "FROM", "foo"}, // not-modify
							{"REQUIRE", "foo-allow"},
							{"ALLOW", "foo-allow"},
							{"DISALLOW", "*"},
						},
					},
				},
			},
			metadata: map[string]Metadata{
				"foo": &Metablock{
					Signed: Link{
						Name: "foo",
						Materials: map[string]interface{}{
							"foo-delete": map[string]interface{}{"sha265": "abc"},
							"foo-modify": map[string]interface{}{"sha265": "abc"},
							"foo-match":  map[string]interface{}{"sha265": "abc"},
							"foo-allow":  map[string]interface{}{"sha265": "abc"},
						},
						Products: map[string]interface{}{
							"foo-create": map[string]interface{}{"sha265": "abc"},
							"foo-modify": map[string]interface{}{"sha265": "abcdef"},
							"foo-match":  map[string]interface{}{"sha265": "abc"},
							"foo-allow":  map[string]interface{}{"sha265": "abc"},
						},
					},
				},
			},
			expectErr: "",
		},
		{
			name: "Verify match with relative paths",
			item: []interface{}{
				Step{
					SupplyChainItem: SupplyChainItem{
						Name: "foo",
						ExpectedMaterials: [][]string{
							{"MATCH", "*", "WITH", "PRODUCTS", "FROM", "bar"},
							{"DISALLOW", "*"},
						},
					},
				},
			},
			metadata: map[string]Metadata{
				"foo": &Metablock{
					Signed: Link{
						Name: "foo",
						Materials: map[string]interface{}{
							"./foo.d/foo.py": map[string]interface{}{"sha265": "abc"},
							"bar.d/bar.py":   map[string]interface{}{"sha265": "abc"},
						},
					},
				},
				"bar": &Metablock{
					Signed: Link{
						Name: "bar",
						Products: map[string]interface{}{
							"foo.d/foo.py":          map[string]interface{}{"sha265": "abc"},
							"./baz/../bar.d/bar.py": map[string]interface{}{"sha265": "abc"},
						},
					},
				},
			},
			expectErr: "",
		},
		{
			name: "Verify match detection of hash mismatch",
			item: []interface{}{
				Step{
					SupplyChainItem: SupplyChainItem{
						Name: "foo",
						ExpectedMaterials: [][]string{
							{"MATCH", "*", "WITH", "PRODUCTS", "FROM", "bar"},
							{"DISALLOW", "*"},
						},
					},
				},
			},
			metadata: map[string]Metadata{
				"foo": &Metablock{
					Signed: Link{
						Name: "foo",
						Materials: map[string]interface{}{
							"foo.d/foo.py": map[string]interface{}{"sha265": "abc"},
							"bar.d/bar.py": map[string]interface{}{"sha265": "def"}, // modified by mitm
						},
					},
				},
				"bar": &Metablock{
					Signed: Link{
						Name: "bar",
						Products: map[string]interface{}{
							"foo.d/foo.py": map[string]interface{}{"sha265": "abc"},
							"bar.d/bar.py": map[string]interface{}{"sha265": "abc"},
						},
					},
				},
			},
			expectErr: "materials [bar.d/bar.py] disallowed by rule",
		},
		{
			name:      "Item must be one of step or inspection",
			item:      []interface{}{nil},
			metadata:  map[string]Metadata{},
			expectErr: "item of invalid type",
		},
		{
			name:      "Can't find link metadata for step",
			item:      []interface{}{Step{SupplyChainItem: SupplyChainItem{Name: "foo"}}},
			metadata:  map[string]Metadata{},
			expectErr: "could not find metadata",
		},
		{
			name:      "Can't find link metadata for inspection",
			item:      []interface{}{Inspection{SupplyChainItem: SupplyChainItem{Name: "foo"}}},
			metadata:  map[string]Metadata{},
			expectErr: "could not find metadata",
		},
		{
			name:      "Wrong step expected material",
			item:      []interface{}{Step{SupplyChainItem: SupplyChainItem{Name: "foo", ExpectedMaterials: [][]string{{"INVALID", "rule"}}}}},
			metadata:  map[string]Metadata{"foo": &Metablock{Signed: Link{Name: "foo"}}},
			expectErr: "rule format",
		},
		{
			name:      "Wrong step expected product",
			item:      []interface{}{Step{SupplyChainItem: SupplyChainItem{Name: "foo", ExpectedProducts: [][]string{{"INVALID", "rule"}}}}},
			metadata:  map[string]Metadata{"foo": &Metablock{Signed: Link{Name: "foo"}}},
			expectErr: "rule format",
		},
		{
			name:      "Wrong inspection expected material",
			item:      []interface{}{Inspection{SupplyChainItem: SupplyChainItem{Name: "foo", ExpectedMaterials: [][]string{{"INVALID", "rule"}}}}},
			metadata:  map[string]Metadata{"foo": &Metablock{Signed: Link{Name: "foo"}}},
			expectErr: "rule format",
		},
		{
			name:      "Wrong inspection expected product",
			item:      []interface{}{Inspection{SupplyChainItem: SupplyChainItem{Name: "foo", ExpectedProducts: [][]string{{"INVALID", "rule"}}}}},
			metadata:  map[string]Metadata{"foo": &Metablock{Signed: Link{Name: "foo"}}},
			expectErr: "rule format",
		},
		{
			name:      "Disallowed material in step",
			item:      []interface{}{Step{SupplyChainItem: SupplyChainItem{Name: "foo", ExpectedMaterials: [][]string{{"DISALLOW", "*"}}}}},
			metadata:  map[string]Metadata{"foo": &Metablock{Signed: Link{Name: "foo", Materials: map[string]interface{}{"foo.py": map[string]interface{}{"sha265": "abc"}}}}},
			expectErr: "materials [foo.py] disallowed by rule",
		},
		{
			name:      "Disallowed product in step",
			item:      []interface{}{Step{SupplyChainItem: SupplyChainItem{Name: "foo", ExpectedProducts: [][]string{{"DISALLOW", "*"}}}}},
			metadata:  map[string]Metadata{"foo": &Metablock{Signed: Link{Name: "foo", Products: map[string]interface{}{"foo.py": map[string]interface{}{"sha265": "abc"}}}}},
			expectErr: "products [foo.py] disallowed by rule",
		},
		{
			name:      "Disallowed material in inspection",
			item:      []interface{}{Inspection{SupplyChainItem: SupplyChainItem{Name: "foo", ExpectedMaterials: [][]string{{"DISALLOW", "*"}}}}},
			metadata:  map[string]Metadata{"foo": &Metablock{Signed: Link{Name: "foo", Materials: map[string]interface{}{"foo.py": map[string]interface{}{"sha265": "abc"}}}}},
			expectErr: "materials [foo.py] disallowed by rule",
		},
		{
			name:      "Disallowed product in inspection",
			item:      []interface{}{Inspection{SupplyChainItem: SupplyChainItem{Name: "foo", ExpectedProducts: [][]string{{"DISALLOW", "*"}}}}},
			metadata:  map[string]Metadata{"foo": &Metablock{Signed: Link{Name: "foo", Products: map[string]interface{}{"foo.py": map[string]interface{}{"sha265": "abc"}}}}},
			expectErr: "products [foo.py] disallowed by rule",
		},
		{
			name:      "Required but missing material in step",
			item:      []interface{}{Step{SupplyChainItem: SupplyChainItem{Name: "foo", ExpectedMaterials: [][]string{{"REQUIRE", "foo"}}}}},
			metadata:  map[string]Metadata{"foo": &Metablock{Signed: Link{Name: "foo", Materials: map[string]interface{}{"foo.py": map[string]interface{}{"sha265": "abc"}}}}},
			expectErr: "materials in REQUIRE 'foo'",
		},
		{
			name:      "Required but missing product in step",
			item:      []interface{}{Step{SupplyChainItem: SupplyChainItem{Name: "foo", ExpectedProducts: [][]string{{"REQUIRE", "foo"}}}}},
			metadata:  map[string]Metadata{"foo": &Metablock{Signed: Link{Name: "foo", Products: map[string]interface{}{"foo.py": map[string]interface{}{"sha265": "abc"}}}}},
			expectErr: "products in REQUIRE 'foo'",
		},
		{
			name:      "Required but missing material in inspection",
			item:      []interface{}{Inspection{SupplyChainItem: SupplyChainItem{Name: "foo", ExpectedMaterials: [][]string{{"REQUIRE", "foo"}}}}},
			metadata:  map[string]Metadata{"foo": &Metablock{Signed: Link{Name: "foo", Materials: map[string]interface{}{"foo.py": map[string]interface{}{"sha265": "abc"}}}}},
			expectErr: "materials in REQUIRE 'foo'",
		},
		{
			name:      "Required but missing product in inspection",
			item:      []interface{}{Inspection{SupplyChainItem: SupplyChainItem{Name: "foo", ExpectedProducts: [][]string{{"REQUIRE", "foo"}}}}},
			metadata:  map[string]Metadata{"foo": &Metablock{Signed: Link{Name: "foo", Products: map[string]interface{}{"foo.py": map[string]interface{}{"sha265": "abc"}}}}},
			expectErr: "products in REQUIRE 'foo'",
		},
		{
			name:      "Disallowed subdirectory material in step",
			item:      []interface{}{Step{SupplyChainItem: SupplyChainItem{Name: "foo", ExpectedMaterials: [][]string{{"DISALLOW", "*"}}}}},
			metadata:  map[string]Metadata{"foo": &Metablock{Signed: Link{Name: "foo", Materials: map[string]interface{}{"dir/foo.py": map[string]interface{}{"sha265": "abc"}}}}},
			expectErr: "materials [dir/foo.py] disallowed by rule",
		},
		{
			name:      "Disallowed subdirectory product in step",
			item:      []interface{}{Step{SupplyChainItem: SupplyChainItem{Name: "foo", ExpectedProducts: [][]string{{"DISALLOW", "*"}}}}},
			metadata:  map[string]Metadata{"foo": &Metablock{Signed: Link{Name: "foo", Products: map[string]interface{}{"dir/foo.py": map[string]interface{}{"sha265": "abc"}}}}},
			expectErr: "products [dir/foo.py] disallowed by rule",
		},
		{
			name:      "Disallowed subdirectory material in inspection",
			item:      []interface{}{Inspection{SupplyChainItem: SupplyChainItem{Name: "foo", ExpectedMaterials: [][]string{{"DISALLOW", "*"}}}}},
			metadata:  map[string]Metadata{"foo": &Metablock{Signed: Link{Name: "foo", Materials: map[string]interface{}{"dir/foo.py": map[string]interface{}{"sha265": "abc"}}}}},
			expectErr: "materials [dir/foo.py] disallowed by rule",
		},
		{
			name:      "Disallowed subdirectory product in inspection",
			item:      []interface{}{Inspection{SupplyChainItem: SupplyChainItem{Name: "foo", ExpectedProducts: [][]string{{"DISALLOW", "*"}}}}},
			metadata:  map[string]Metadata{"foo": &Metablock{Signed: Link{Name: "foo", Products: map[string]interface{}{"dir/foo.py": map[string]interface{}{"sha265": "abc"}}}}},
			expectErr: "products [dir/foo.py] disallowed by rule",
		},
		{
			name:      "Consuming filename material in step",
			item:      []interface{}{Step{SupplyChainItem: SupplyChainItem{Name: "foo", ExpectedMaterials: [][]string{{"ALLOW", "foo.py"}, {"DISALLOW", "*"}}}}},
			metadata:  map[string]Metadata{"foo": &Metablock{Signed: Link{Name: "foo", Materials: map[string]interface{}{"./bar/..//foo.py": map[string]interface{}{"sha265": "abc"}}}}},
			expectErr: "",
		},
		{
			name:      "Consuming filename product in step",
			item:      []interface{}{Step{SupplyChainItem: SupplyChainItem{Name: "foo", ExpectedProducts: [][]string{{"ALLOW", "foo.py"}, {"DISALLOW", "*"}}}}},
			metadata:  map[string]Metadata{"foo": &Metablock{Signed: Link{Name: "foo", Products: map[string]interface{}{"./bar/..//foo.py": map[string]interface{}{"sha265": "abc"}}}}},
			expectErr: "",
		},
		{
			name:      "Consuming filename material in inspection",
			item:      []interface{}{Inspection{SupplyChainItem: SupplyChainItem{Name: "foo", ExpectedMaterials: [][]string{{"ALLOW", "foo.py"}, {"DISALLOW", "*"}}}}},
			metadata:  map[string]Metadata{"foo": &Metablock{Signed: Link{Name: "foo", Materials: map[string]interface{}{"./bar/..//foo.py": map[string]interface{}{"sha265": "abc"}}}}},
			expectErr: "",
		},
		{
			name:      "Consuming filename product in inspection",
			item:      []interface{}{Inspection{SupplyChainItem: SupplyChainItem{Name: "foo", ExpectedProducts: [][]string{{"ALLOW", "foo.py"}, {"DISALLOW", "*"}}}}},
			metadata:  map[string]Metadata{"foo": &Metablock{Signed: Link{Name: "foo", Products: map[string]interface{}{"./bar/..//foo.py": map[string]interface{}{"sha265": "abc"}}}}},
			expectErr: "",
		},
	}

	for _, tt := range testCases {
		t.Run(tt.name, func(t *testing.T) {
			err := VerifyArtifacts(tt.item, tt.metadata)
			if (err == nil && tt.expectErr != "") ||
				(err != nil && tt.expectErr == "") ||
				(err != nil && !strings.Contains(err.Error(), tt.expectErr)) {
				t.Errorf("VerifyArtifacts returned '%s', expected '%s' error",
					err, tt.expectErr)
			}
		})
	}
}

func TestVerifyMatchRule(t *testing.T) {
	var testCases = []struct {
		name        string
		rule        map[string]string
		srcArtifact map[string]interface{}
		item        map[string]Metadata
		expectSet   Set
	}{
		{
			name:        "Can't find destination link (invalid rule)",
			rule:        map[string]string{},
			srcArtifact: map[string]interface{}{},
			item:        map[string]Metadata{},
			expectSet:   NewSet(),
		},
		{
			name:        "Can't find destination link (empty metadata map)",
			rule:        map[string]string{"pattern": "*", "dstName": "foo", "dstType": "materials"},
			srcArtifact: map[string]interface{}{"foo.py": map[string]interface{}{"sha265": "abc"}},
			item:        map[string]Metadata{},
			expectSet:   NewSet(),
		},
		{
			name:        "Match material foo.py",
			rule:        map[string]string{"pattern": "*", "dstName": "foo", "dstType": "materials"},
			srcArtifact: map[string]interface{}{"foo.py": map[string]interface{}{"sha265": "abc"}},
			item:        map[string]Metadata{"foo": &Metablock{Signed: Link{Name: "foo", Materials: map[string]interface{}{"foo.py": map[string]interface{}{"sha265": "abc"}}}}},
			expectSet:   NewSet("foo.py"),
		},
		{
			name:        "Match material foo.py with foo.d/foo.py",
			rule:        map[string]string{"pattern": "*", "dstName": "foo", "dstType": "materials", "dstPrefix": "foo.d"},
			srcArtifact: map[string]interface{}{"foo.py": map[string]interface{}{"sha265": "abc"}},
			item:        map[string]Metadata{"foo": &Metablock{Signed: Link{Name: "foo", Materials: map[string]interface{}{"foo.d/foo.py": map[string]interface{}{"sha265": "abc"}}}}},
			expectSet:   NewSet("foo.py"),
		},
		{
			name:        "Match material foo.d/foo.py with foo.py",
			rule:        map[string]string{"pattern": "*", "dstName": "foo", "dstType": "materials", "srcPrefix": "foo.d"},
			srcArtifact: map[string]interface{}{"foo.d/foo.py": map[string]interface{}{"sha265": "abc"}},
			item:        map[string]Metadata{"foo": &Metablock{Signed: Link{Name: "foo", Materials: map[string]interface{}{"foo.py": map[string]interface{}{"sha265": "abc"}}}}},
			expectSet:   NewSet("foo.d/foo.py"),
		},
		{
			name:        "Don't match material (different name)",
			rule:        map[string]string{"pattern": "*", "dstName": "foo", "dstType": "materials"},
			srcArtifact: map[string]interface{}{"bar.py": map[string]interface{}{"sha265": "abc"}},
			item:        map[string]Metadata{"foo": &Metablock{Signed: Link{Name: "foo", Materials: map[string]interface{}{"foo.py": map[string]interface{}{"sha265": "abc"}}}}},
			expectSet:   NewSet(),
		},
		{
			name:        "Don't match material (different hash)",
			rule:        map[string]string{"pattern": "*", "dstName": "foo", "dstType": "materials"},
			srcArtifact: map[string]interface{}{"foo.py": map[string]interface{}{"sha265": "dead"}},
			item:        map[string]Metadata{"foo": &Metablock{Signed: Link{Name: "foo", Materials: map[string]interface{}{"foo.py": map[string]interface{}{"sha265": "abc"}}}}},
			expectSet:   NewSet(),
		},
		{
			name:        "Match material in sub-directories dir/foo.py",
			rule:        map[string]string{"pattern": "*", "dstName": "foo", "dstType": "materials"},
			srcArtifact: map[string]interface{}{"bar/foo.py": map[string]interface{}{"sha265": "abc"}},
			item:        map[string]Metadata{"foo": &Metablock{Signed: Link{Name: "foo", Materials: map[string]interface{}{"bar/foo.py": map[string]interface{}{"sha265": "abc"}}}}},
			expectSet:   NewSet("bar/foo.py"),
		},
	}

	for _, tt := range testCases {
		t.Run(tt.name, func(t *testing.T) {
			queue := NewSet(InterfaceKeyStrings(tt.srcArtifact)...)
			result := verifyMatchRule(tt.rule, tt.srcArtifact, queue, tt.item)
			if !reflect.DeepEqual(result, tt.expectSet) {
				t.Errorf("verifyMatchRule returned '%s', expected '%s'", result, tt.expectSet)
			}
		})
	}
}

func TestReduceStepsMetadata(t *testing.T) {
	mb, err := LoadMetadata("demo.layout")
	if err != nil {
		t.Errorf("unable to parse template file: %s", err)
	}
	layout := mb.GetPayload().(Layout)
	layout.Steps = []Step{{SupplyChainItem: SupplyChainItem{Name: "foo"}}}

	// Test 1: Successful reduction of multiple links for one step (foo)
	stepsMetadata := map[string]map[string]Metadata{
		"foo": {
			"a": &Metablock{Signed: Link{
				Type:      "link",
				Name:      "foo",
				Materials: map[string]interface{}{"foo.py": map[string]interface{}{"sha265": "abc"}},
				Products:  map[string]interface{}{"bar.py": map[string]interface{}{"sha265": "cde"}},
			}},
			"b": &Metablock{Signed: Link{
				Type:      "link",
				Name:      "foo",
				Materials: map[string]interface{}{"foo.py": map[string]interface{}{"sha265": "abc"}},
				Products:  map[string]interface{}{"bar.py": map[string]interface{}{"sha265": "cde"}},
			}},
		},
	}

	result, err := ReduceStepsMetadata(layout, stepsMetadata)
	if !reflect.DeepEqual(result["foo"], stepsMetadata["foo"]["a"]) || err != nil {
		t.Errorf("ReduceStepsMetadata returned (%s, %s), expected (%s, nil)"+
			" and a 'different artifacts' error", result, err, stepsMetadata["foo"]["a"])
	}

	// Test 2: Test different error scenarios when creating one link out of
	// multiple links for the same step:
	// - Different materials (hash)
	// - Different materials (name)
	// - Different products (hash)
	// - Different products (name)
	stepsMetadataList := []map[string]map[string]Metadata{
		{"foo": {
			"a": &Metablock{Signed: Link{Materials: map[string]interface{}{"foo.py": map[string]interface{}{"sha265": "abc"}}}},
			"b": &Metablock{Signed: Link{Materials: map[string]interface{}{"foo.py": map[string]interface{}{"sha265": "def"}}}},
		}},
		{"foo": {
			"a": &Metablock{Signed: Link{Materials: map[string]interface{}{"foo.py": map[string]interface{}{"sha265": "abc"}}}},
			"b": &Metablock{Signed: Link{Materials: map[string]interface{}{"bar.py": map[string]interface{}{"sha265": "abc"}}}},
		}},
		{"foo": {
			"a": &Metablock{Signed: Link{Products: map[string]interface{}{"foo.py": map[string]interface{}{"sha265": "abc"}}}},
			"b": &Metablock{Signed: Link{Products: map[string]interface{}{"foo.py": map[string]interface{}{"sha265": "def"}}}},
		}},
		{"foo": {
			"a": &Metablock{Signed: Link{Products: map[string]interface{}{"foo.py": map[string]interface{}{"sha265": "abc"}}}},
			"b": &Metablock{Signed: Link{Products: map[string]interface{}{"bar.py": map[string]interface{}{"sha265": "abc"}}}},
		}},
	}

	for i := 0; i < len(stepsMetadataList); i++ {
		result, err := ReduceStepsMetadata(layout, stepsMetadataList[i])
		if err == nil || !strings.Contains(err.Error(), "different artifacts") {
			t.Errorf("ReduceStepsMetadata returned (%s, %s), expected an empty map"+
				" and a 'different artifacts' error", result, err)
		}
	}

	// Panic due to missing link metadata for step (final product verification
	// should gracefully error earlier)
	defer func() {
		if r := recover(); r == nil {
			t.Errorf("ReduceStepsMetadata should have panicked due to missing link" +
				" metadata")
		}
	}()
	if _, err := ReduceStepsMetadata(layout, nil); err != nil {
		t.Errorf("error while calling ReduceStepsMetadata: %s", err)
	}
	//NOTE: This test won't get any further because of panic
}

func TestVerifyStepCommandAlignment(t *testing.T) {
	mb, err := LoadMetadata("demo.layout")
	if err != nil {
		t.Errorf("unable to load template file: %s", err)
	}
	layout := mb.GetPayload().(Layout)
	layout.Steps = []Step{
		{
			SupplyChainItem: SupplyChainItem{Name: "foo"},
			ExpectedCommand: []string{"rm", "-rf", "."},
		},
	}

	stepsMetadata := map[string]map[string]Metadata{
		"foo": {"a": &Metablock{Signed: Link{Command: []string{"rm", "-rf", "/"}}}},
	}
	// Test warning due to non-aligning commands
	// FIXME: Assert warning?
	fmt.Printf("[begin test warning output]\n")
	VerifyStepCommandAlignment(layout, stepsMetadata)
	fmt.Printf("[end test warning output]\n")

	// Panic due to missing link metadata for step (final product verification
	// should gracefully error earlier)
	defer func() {
		if r := recover(); r == nil {
			t.Errorf("ReduceStepsMetadata should have panicked due to missing link" +
				" metadata")
		}
	}()
	VerifyStepCommandAlignment(layout, nil)
	//NOTE: This test won't get any further because of panic
}

func TestVerifyLinkSignatureThesholds(t *testing.T) {
	keyID1 := "b7d643dec0a051096ee5d87221b5d91a33daa658699d30903e1cefb90c418401"
	keyID2 := "d3ffd1086938b3698618adf088bf14b13db4c8ae19e4e78d73da49ee88492710"
	keyID3 := "abcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabca"

	mb, err := LoadMetadata("demo.layout")
	if err != nil {
		t.Errorf("unable to load template file: %s", err)
	}
	layout := mb.GetPayload().(Layout)

	layout.Steps = []Step{{SupplyChainItem: SupplyChainItem{
		Name: "foo"},
		Threshold: 2,
		PubKeys:   []string{keyID1, keyID2, keyID3}}}

	mbLink1, err := LoadMetadata("foo.b7d643de.link")
	if err != nil {
		t.Errorf("unable to load link file: %s", err)
	}
	mbLink2, err := LoadMetadata("foo.d3ffd108.link")
	if err != nil {
		t.Errorf("unable to load link file: %s", err)
	}
	mbLinkBroken, err := LoadMetadata("foo.d3ffd108.link")
	if err != nil {
		t.Errorf("unable to load link file: %s", err)
	}
	mbLinkBroken.Sigs()[0].Sig = "breaksignature"

	// Test less then threshold distinct valid links errors:
	// - Missing step name in step metadata map
	// - Missing links for step
	// - Less than threshold links for step
	// - Less than threshold distinct links for step
	// - Less than threshold validly signed links for step
	stepsMetadata := []map[string]map[string]Metadata{
		{"bar": nil},
		{"foo": nil},
		{"foo": {keyID1: mbLink1}},
		{"foo": {keyID1: mbLink1, keyID2: mbLink1}},
		{"foo": {keyID1: mbLink1, keyID2: mbLinkBroken}},
	}
	for i := 0; i < len(stepsMetadata); i++ {
		result, err := VerifyLinkSignatureThesholds(layout, stepsMetadata[i], x509.NewCertPool(), x509.NewCertPool())
		if err == nil {
			t.Errorf("VerifyLinkSignatureThesholds returned (%s, %s), expected"+
				" 'not enough distinct valid links' error.", result, err)
		}
	}

	// Test successfully return threshold distinct valid links:
	// - Threshold 2, two valid links
	// - Threshold 2, two valid links, one invalid link ignored
	stepsMetadata = []map[string]map[string]Metadata{
		{"foo": {keyID1: mbLink1, keyID2: mbLink2}},
		{"foo": {keyID1: mbLink1, keyID2: mbLink2, keyID3: mbLinkBroken}},
	}
	for i := 0; i < len(stepsMetadata); i++ {
		result, err := VerifyLinkSignatureThesholds(layout, stepsMetadata[i], x509.NewCertPool(), x509.NewCertPool())
		validLinks, ok := result["foo"]
		if !ok || len(validLinks) != 2 {
			t.Errorf("VerifyLinkSignatureThesholds returned (%s, %s), expected"+
				" a map of two valid foo links.", result, err)
		}
	}
}

func TestLoadLinksForLayout(t *testing.T) {
	keyID1 := "d3ffd1086938b3698618adf088bf14b13db4c8ae19e4e78d73da49ee88492710"
	keyID2 := "b7d643dec0a051096ee5d87221b5d91a33daa658699d30903e1cefb90c418401"
	mb, err := LoadMetadata("demo.layout")
	if err != nil {
		t.Errorf("unable to load template file: %s", err)
	}
	layout := mb.GetPayload().(Layout)

	layout.Steps = []Step{{SupplyChainItem: SupplyChainItem{
		Name: "foo"},
		Threshold: 2,
		PubKeys:   []string{keyID1, keyID2}}}

	// Test successfully load two links for layout (one step foo, threshold 2)
	result, err := LoadLinksForLayout(layout, ".")
	links, ok := result["foo"]
	if !ok || len(links) != 2 {
		t.Errorf("VerifyLoadLinksForLayout returned (%s, %s), expected"+
			" a map of two foo links.", result, err)
	}

	// Test threshold error, can't find enough links for step
	keyID3 := "abcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabca"
	layout.Steps = []Step{{SupplyChainItem: SupplyChainItem{
		Name: "foo"},
		Threshold: 3,
		PubKeys:   []string{keyID1, keyID2, keyID3}}}
	result, err = LoadLinksForLayout(layout, ".")
	if err == nil {
		t.Errorf("VerifyLoadLinksForLayout returned (%s, %s), expected"+
			" 'not enough links' error.", result, err)
	}
}

func TestVerifyLayoutExpiration(t *testing.T) {
	mb, err := LoadMetadata("demo.layout")
	if err != nil {
		t.Errorf("unable to load template file: %s", err)
	}
	layout := mb.GetPayload().(Layout)

	// Test layout expiration check failure:
	// - invalid date
	// - expired date
	expirationDates := []string{"bad date", "1970-01-01T00:00:00Z"}
	expectedErrors := []string{"cannot parse", "has expired"}

	for i := 0; i < len(expirationDates); i++ {
		layout.Expires = expirationDates[i]
		err := VerifyLayoutExpiration(layout)
		if err == nil || !strings.Contains(err.Error(), expectedErrors[i]) {
			t.Errorf("VerifyLayoutExpiration returned '%s', expected '%s' error",
				err, expectedErrors[i])
		}
	}

	// Test not (yet) expired layout :)
	layout.Expires = "3000-01-01T00:00:00Z"
	err = VerifyLayoutExpiration(layout)
	if err != nil {
		t.Errorf("VerifyLayoutExpiration returned '%s', expected nil", err)
	}
}

func TestVerifyLayoutSignatures(t *testing.T) {
	mbLayout, err := LoadMetadata("demo.layout")
	if err != nil {
		t.Errorf("unable to load template file: %s", err)
	}
	var layoutKey Key
	if err := layoutKey.LoadKey("alice.pub", "rsassa-pss-sha256", []string{"sha256", "sha512"}); err != nil {
		t.Errorf("unable to load public key file: %s", err)
	}

	// Test layout signature verification errors:
	// - Not verification keys (must be at least one)
	// - No signature found for verification key
	layoutKeysList := []map[string]Key{{}, {layoutKey.KeyID: Key{}}}
	expectedErrors := []string{"at least one key", "no signature found for key"}

	for i := 0; i < len(layoutKeysList); i++ {
		err := VerifyLayoutSignatures(mbLayout, layoutKeysList[i])
		if err == nil || !strings.Contains(err.Error(), expectedErrors[i]) {
			t.Errorf("VerifyLayoutSignatures returned '%s', expected '%s' error",
				err, expectedErrors[i])
		}
	}

	// Test successful layout signature verification
	err = VerifyLayoutSignatures(mbLayout, map[string]Key{layoutKey.KeyID: layoutKey})
	if err != nil {
		t.Errorf("VerifyLayoutSignatures returned '%s', expected nil",
			err)
	}
}

func TestSubstituteParamaters(t *testing.T) {
	parameterDictionary := map[string]string{
		"EDITOR":       "vim",
		"NEW_THING":    "new_thing",
		"SOURCE_STEP":  "source_step",
		"SOURCE_THING": "source_thing",
		"UNTAR":        "tar",
	}

	layout := Layout{
		Type: "_layout",
		Inspect: []Inspection{
			{
				SupplyChainItem: SupplyChainItem{
					Name: "verify-the-thing",
					ExpectedMaterials: [][]string{{"MATCH", "{SOURCE_THING}",
						"WITH", "MATERIALS", "FROM", "{SOURCE_STEP}"}},
					ExpectedProducts: [][]string{{"CREATE", "{NEW_THING}"}},
				},
				Run: []string{"{UNTAR}", "xzf", "foo.tar.gz"},
			},
		},
		Steps: []Step{
			{
				SupplyChainItem: SupplyChainItem{
					Name: "run-command",
					ExpectedMaterials: [][]string{{"MATCH", "{SOURCE_THING}",
						"WITH", "MATERIALS", "FROM", "{SOURCE_STEP}"}},
					ExpectedProducts: [][]string{{"CREATE", "{NEW_THING}"}},
				},
				ExpectedCommand: []string{"{EDITOR}"},
			},
		},
	}

	newLayout, err := SubstituteParameters(layout, parameterDictionary)
	if err != nil {
		t.Errorf("parameter substitution error: got %s", err)
	}

	if newLayout.Steps[0].ExpectedCommand[0] != "vim" {
		t.Errorf("parameter substitution failed - expected 'vim', got %s",
			newLayout.Steps[0].ExpectedCommand[0])
	}

	if newLayout.Steps[0].ExpectedProducts[0][1] != "new_thing" {
		t.Errorf("parameter substitution failed - expected 'new_thing',"+
			" got %s", newLayout.Steps[0].ExpectedProducts[0][1])
	}

	if newLayout.Steps[0].ExpectedMaterials[0][1] != "source_thing" {
		t.Errorf("parameter substitution failed - expected 'source_thing', "+
			"got %s", newLayout.Steps[0].ExpectedMaterials[0][1])
	}

	if newLayout.Steps[0].ExpectedMaterials[0][5] != "source_step" {
		t.Errorf("parameter substitution failed - expected 'source_step', "+
			"got %s", newLayout.Steps[0].ExpectedMaterials[0][5])
	}

	if newLayout.Inspect[0].Run[0] != "tar" {
		t.Errorf("parameter substitution failed - expected 'tar', got %s",
			newLayout.Inspect[0].Run[0])
	}

	if newLayout.Inspect[0].ExpectedProducts[0][1] != "new_thing" {
		t.Errorf("parameter substitution failed - expected 'new_thing',"+
			" got %s", newLayout.Inspect[0].ExpectedProducts[0][1])
	}

	if newLayout.Inspect[0].ExpectedMaterials[0][1] != "source_thing" {
		t.Errorf("parameter substitution failed - expected 'source_thing', "+
			"got %s", newLayout.Inspect[0].ExpectedMaterials[0][1])
	}

	if newLayout.Inspect[0].ExpectedMaterials[0][5] != "source_step" {
		t.Errorf("parameter substitution failed - expected 'source_step', "+
			"got %s", newLayout.Inspect[0].ExpectedMaterials[0][5])
	}

	parameterDictionary = map[string]string{
		"invalid$": "some_replacement",
	}

	_, err = SubstituteParameters(layout, parameterDictionary)
	if err.Error() != "invalid format for parameter" {
		t.Errorf("invalid parameter format not detected")
	}
}

func TestInTotoVerifyWithDirectory(t *testing.T) {
	layoutPath := "demo.layout"
	pubKeyPath := "alice.pub"
	linkDir := "."

	layoutMb, err := LoadMetadata(layoutPath)
	if err != nil {
		t.Error(err)
	}

	var pubKey Key
	if err := pubKey.LoadKey(pubKeyPath, "rsassa-pss-sha256", []string{"sha256", "sha512"}); err != nil {
		t.Error(err)
	}

	var layouKeys = map[string]Key{
		pubKey.KeyID: pubKey,
	}

	// No error should occur
	if _, err := InTotoVerifyWithDirectory(layoutMb, layouKeys, linkDir, ".", "",
		make(map[string]string), [][]byte{}, testOSisWindows()); err != nil {
		t.Error(err)
	}
}

func TestLoadLayoutCertificates(t *testing.T) {
	certTemplate := &x509.Certificate{
		Subject: pkix.Name{
			CommonName:   "step1.example.com",
			Organization: []string{"example"},
		},
	}

	_, intermediate, root, err := createTestCert(certTemplate, x509.Ed25519, time.Hour)
	assert.Nil(t, err, "unexpected error when creating test cert")
	rootKey := Key{}
	err = rootKey.LoadKeyReader(bytes.NewReader(generatePEMBlock(root.Raw, "CERTIFICATE")), "ed25519", []string{"sha512"})
	assert.Nil(t, err, "unexpected error loading Key for root")
	intermediateKey := Key{}
	intermediatePem := generatePEMBlock(intermediate.Raw, "CERTIFICATE")
	err = intermediateKey.LoadKeyReader(bytes.NewReader(intermediatePem), "ed25519", []string{"sha512"})
	assert.Nil(t, err, "unexpected error loading Key for intermediate")
	testLayout := Layout{
		RootCas: map[string]Key{
			rootKey.KeyID: rootKey,
		},
		IntermediateCas: map[string]Key{
			intermediateKey.KeyID: intermediateKey,
		},
	}

	_, _, err = LoadLayoutCertificates(testLayout, [][]byte{intermediatePem})
	assert.Nil(t, err, "unexpected error loading layout's certificates")

	// Test with an invalid root in the layout and valid intermediate
	invalidRootKey := rootKey
	invalidRootKey.KeyVal.Certificate = "123123123"
	testLayout.RootCas[rootKey.KeyID] = invalidRootKey
	_, _, err = LoadLayoutCertificates(testLayout, [][]byte{intermediatePem})
	assert.NotNil(t, err, "expected error with invalid root key")

	// Test with a valid root but invalid intermediate in the layout
	testLayout.RootCas[rootKey.KeyID] = rootKey
	invalidIntermediateKey := intermediateKey
	invalidIntermediateKey.KeyVal.Certificate = "123123123"
	testLayout.IntermediateCas[intermediateKey.KeyID] = invalidIntermediateKey
	_, _, err = LoadLayoutCertificates(testLayout, [][]byte{})
	assert.NotNil(t, err, "expected error with invalid intermediate key")

	// Now test failure with an invalid extra intermediate
	testLayout.IntermediateCas[intermediateKey.KeyID] = intermediateKey
	_, _, err = LoadLayoutCertificates(testLayout, [][]byte{[]byte("123123123")})
	assert.NotNil(t, err, "expected error with invalid extra intermediates")
}

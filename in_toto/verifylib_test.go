package in_toto

import (
	"crypto/x509"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"
)

func TestInTotoVerifyPass(t *testing.T) {
	layoutPath := "demo.layout"
	pubKeyPath := "alice.pub"
	linkDir := "."

	var layoutMb Metablock
	if err := layoutMb.Load(layoutPath); err != nil {
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
	if _, err := InTotoVerify(layoutMb, layouKeys, linkDir, "",
		make(map[string]string)); err != nil {
		t.Error(err)
	}
}

func TestGetSummaryLink(t *testing.T) {
	var demoLayout Metablock
	if err := demoLayout.Load("demo.layout"); err != nil {
		t.Error(err)
	}
	var codeLink Metablock
	if err := codeLink.Load("write-code.776a00e2.link"); err != nil {
		t.Error(err)
	}
	var packageLink Metablock
	if err := packageLink.Load("package.2f89b927.link"); err != nil {
		t.Error(err)
	}
	demoLink := make(map[string]Metablock)
	demoLink["write-code"] = codeLink
	demoLink["package"] = packageLink

	var summaryLink Metablock
	var err error
	if summaryLink, err = GetSummaryLink(demoLayout.Signed.(Layout),
		demoLink, ""); err != nil {
		t.Error(err)
	}
	if summaryLink.Signed.(Link).Type != codeLink.Signed.(Link).Type {
		t.Errorf("Summary Link isn't of type Link")
	}
	if summaryLink.Signed.(Link).Name != "" {
		t.Errorf("Summary Link name doesn't match. Expected '%s', returned "+
			"'%s", codeLink.Signed.(Link).Name, summaryLink.Signed.(Link).Name)
	}
	if !reflect.DeepEqual(summaryLink.Signed.(Link).Materials,
		codeLink.Signed.(Link).Materials) {
		t.Errorf("Summary Link materials don't match. Expected '%s', "+
			"returned '%s", codeLink.Signed.(Link).Materials,
			summaryLink.Signed.(Link).Materials)
	}

	if !reflect.DeepEqual(summaryLink.Signed.(Link).Products,
		packageLink.Signed.(Link).Products) {
		t.Errorf("Summary Link products don't match. Expected '%s', "+
			"returned '%s", packageLink.Signed.(Link).Products,
			summaryLink.Signed.(Link).Products)
	}
	if !reflect.DeepEqual(summaryLink.Signed.(Link).Command,
		packageLink.Signed.(Link).Command) {
		t.Errorf("Summary Link command doesn't match. Expected '%s', "+
			"returned '%s", packageLink.Signed.(Link).Command,
			summaryLink.Signed.(Link).Command)
	}
	if !reflect.DeepEqual(summaryLink.Signed.(Link).ByProducts,
		packageLink.Signed.(Link).ByProducts) {
		t.Errorf("Summary Link by-products don't match. Expected '%s', "+
			"returned '%s", packageLink.Signed.(Link).ByProducts,
			summaryLink.Signed.(Link).ByProducts)
	}
}

func TestVerifySublayouts(t *testing.T) {
	sublayoutName := "sub_layout"
	var aliceKey Key
	if err := aliceKey.LoadKey("alice.pub", "rsassa-pss-sha256", []string{"sha256", "sha512"}); err != nil {
		t.Errorf("Unable to load Alice's public key")
	}
	sublayoutDirectory := fmt.Sprintf(SublayoutLinkDirFormat, sublayoutName,
		aliceKey.KeyID)
	defer func(sublayoutDirectory string) {
		if err := os.RemoveAll(sublayoutDirectory); err != nil {
			t.Errorf("Unable to remove directory %s: %s", sublayoutDirectory, err)
		}
	}(sublayoutDirectory)

	if err := os.Mkdir(sublayoutDirectory, 0700); err != nil {
		t.Errorf("Unable to create sublayout directory")
	}
	writeCodePath := path.Join(sublayoutDirectory, "write-code.776a00e2.link")
	if err := os.Link("write-code.776a00e2.link", writeCodePath); err != nil {
		t.Errorf("Unable to link write-code metadata.")
	}
	packagePath := path.Join(sublayoutDirectory, "package.2f89b927.link")
	if err := os.Link("package.2f89b927.link", packagePath); err != nil {
		t.Errorf("Unable to link package metadata")
	}

	var superLayoutMb Metablock
	if err := superLayoutMb.Load("super.layout"); err != nil {
		t.Errorf("Unable to load super layout")
	}

	stepsMetadata := make(map[string]map[string]Metablock)
	var err error
	if stepsMetadata, err = LoadLinksForLayout(superLayoutMb.Signed.(Layout),
		"."); err != nil {
		t.Errorf("Unable to load link metadata for super layout")
	}

	stepsMetadataVerified := make(map[string]map[string]Metablock)
	if stepsMetadataVerified, err = VerifyLinkSignatureThesholds(
		superLayoutMb.Signed.(Layout), stepsMetadata, x509.NewCertPool()); err != nil {
			t.Errorf("Unable to verify link threshold values: %v", err)
	}

	result, err := VerifySublayouts(superLayoutMb.Signed.(Layout),
		stepsMetadataVerified, ".")
	if err != nil {
		t.Errorf("Unable to verify sublayouts")
	}

	for _, stepData := range result {
		for _, metadata := range stepData {
			if _, ok := metadata.Signed.(Link); !ok {
				t.Errorf("Sublayout expansion error: found non link")
			}
		}
	}
}

func TestRunInspections(t *testing.T) {
	// Load layout template used as basis for all tests
	var mb Metablock
	if err := mb.Load("demo.layout"); err != nil {
		t.Errorf("Unable to parse template file: %s", err)
	}
	layout := mb.Signed.(Layout)

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
	result, err := RunInspections(layout)

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
		materialNames := InterfaceKeyStrings(result[inspectionName].Signed.(Link).Materials)
		productNames := InterfaceKeyStrings(result[inspectionName].Signed.(Link).Products)
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

	result, err = RunInspections(layout)
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
	result, err = RunInspections(layout)
	if result != nil || err == nil {
		t.Errorf("RunInspections returned '(%s, %s)', expected"+
			" '(nil, *exec.Error)'", result, err)
	}
}

func TestVerifyArtifacts(t *testing.T) {
	items := []interface{}{
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
	}

	itemsMetadata := map[string]Metablock{
		"foo": {
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
	}

	err := VerifyArtifacts(items, itemsMetadata)
	if err != nil {
		t.Errorf("VerifyArtifacts returned '%s', expected no error", err)
	}
}

func TestVerifyArtifactErrors(t *testing.T) {
	// Test error cases for combinations of Step and Inspection items and
	// material and product rules:
	// - Item must be one of step or inspection
	// - Can't find link metadata for step
	// - Can't find link metadata for inspection
	// - Wrong step expected material
	// - Wrong step expected product
	// - Wrong inspection expected material
	// - Wrong inspection expected product
	// - Disallowed material in step
	// - Disallowed product in step
	// - Disallowed material in inspection
	// - Disallowed product in inspection
	// - Required but missing material in step
	// - Required but missing product in step
	// - Required but missing material in inspection
	// - Required but missing product in inspection
	items := [][]interface{}{
		{nil},
		{Step{SupplyChainItem: SupplyChainItem{Name: "foo"}}},
		{Inspection{SupplyChainItem: SupplyChainItem{Name: "foo"}}},
		{Step{SupplyChainItem: SupplyChainItem{Name: "foo", ExpectedMaterials: [][]string{{"INVALID", "rule"}}}}},
		{Step{SupplyChainItem: SupplyChainItem{Name: "foo", ExpectedProducts: [][]string{{"INVALID", "rule"}}}}},
		{Inspection{SupplyChainItem: SupplyChainItem{Name: "foo", ExpectedMaterials: [][]string{{"INVALID", "rule"}}}}},
		{Inspection{SupplyChainItem: SupplyChainItem{Name: "foo", ExpectedProducts: [][]string{{"INVALID", "rule"}}}}},
		{Step{SupplyChainItem: SupplyChainItem{Name: "foo", ExpectedMaterials: [][]string{{"DISALLOW", "*"}}}}},
		{Step{SupplyChainItem: SupplyChainItem{Name: "foo", ExpectedProducts: [][]string{{"DISALLOW", "*"}}}}},
		{Inspection{SupplyChainItem: SupplyChainItem{Name: "foo", ExpectedMaterials: [][]string{{"DISALLOW", "*"}}}}},
		{Inspection{SupplyChainItem: SupplyChainItem{Name: "foo", ExpectedProducts: [][]string{{"DISALLOW", "*"}}}}},
		{Step{SupplyChainItem: SupplyChainItem{Name: "foo", ExpectedMaterials: [][]string{{"REQUIRE", "foo"}}}}},
		{Step{SupplyChainItem: SupplyChainItem{Name: "foo", ExpectedProducts: [][]string{{"REQUIRE", "foo"}}}}},
		{Inspection{SupplyChainItem: SupplyChainItem{Name: "foo", ExpectedMaterials: [][]string{{"REQUIRE", "foo"}}}}},
		{Inspection{SupplyChainItem: SupplyChainItem{Name: "foo", ExpectedProducts: [][]string{{"REQUIRE", "foo"}}}}},
	}
	itemsMetadata := []map[string]Metablock{
		{},
		{},
		{},
		{"foo": {Signed: Link{Name: "foo"}}},
		{"foo": {Signed: Link{Name: "foo"}}},
		{"foo": {Signed: Link{Name: "foo"}}},
		{"foo": {Signed: Link{Name: "foo"}}},
		{"foo": {Signed: Link{Name: "foo", Materials: map[string]interface{}{"foo.py": map[string]interface{}{"sha265": "abc"}}}}},
		{"foo": {Signed: Link{Name: "foo", Products: map[string]interface{}{"foo.py": map[string]interface{}{"sha265": "abc"}}}}},
		{"foo": {Signed: Link{Name: "foo", Materials: map[string]interface{}{"foo.py": map[string]interface{}{"sha265": "abc"}}}}},
		{"foo": {Signed: Link{Name: "foo", Products: map[string]interface{}{"foo.py": map[string]interface{}{"sha265": "abc"}}}}},
		{"foo": {Signed: Link{Name: "foo", Materials: map[string]interface{}{"foo.py": map[string]interface{}{"sha265": "abc"}}}}},
		{"foo": {Signed: Link{Name: "foo", Products: map[string]interface{}{"foo.py": map[string]interface{}{"sha265": "abc"}}}}},
		{"foo": {Signed: Link{Name: "foo", Materials: map[string]interface{}{"foo.py": map[string]interface{}{"sha265": "abc"}}}}},
		{"foo": {Signed: Link{Name: "foo", Products: map[string]interface{}{"foo.py": map[string]interface{}{"sha265": "abc"}}}}},
	}
	errorPart := []string{
		"item of invalid type",
		"could not find metadata",
		"could not find metadata",
		"rule format",
		"rule format",
		"rule format",
		"rule format",
		"materials [foo.py] disallowed by rule",
		"products [foo.py] disallowed by rule",
		"materials [foo.py] disallowed by rule",
		"products [foo.py] disallowed by rule",
		"materials in REQUIRE 'foo'",
		"products in REQUIRE 'foo'",
		"materials in REQUIRE 'foo'",
		"products in REQUIRE 'foo'",
	}

	for i := 0; i < len(items); i++ {
		err := VerifyArtifacts(items[i], itemsMetadata[i])
		if err == nil || !strings.Contains(err.Error(), errorPart[i]) {
			t.Errorf("VerifyArtifacts returned '%s', expected '%s' error",
				err, errorPart[i])
		}
	}
}

func TestVerifyMatchRule(t *testing.T) {
	// Test MatchRule queue processing:
	// - Can't find destination link (invalid rule) -> queue unmodified (empty)
	// - Can't find destination link (empty metadata map) -> queue unmodified
	// - Match material foo.py -> remove from queue
	// - Match material foo.py with foo.d/foo.py -> remove from queue
	// - Match material foo.d/foo.py with foo.py -> remove from queue
	// - Don't match material (different name) -> queue unmodified
	// - Don't match material (different hash) -> queue unmodified
	ruleData := []map[string]string{
		{},
		{"pattern": "*", "dstName": "foo", "dstType": "materials"},
		{"pattern": "*", "dstName": "foo", "dstType": "materials"},
		{"pattern": "*", "dstName": "foo", "dstType": "materials", "dstPrefix": "foo.d"},
		{"pattern": "*", "dstName": "foo", "dstType": "materials", "srcPrefix": "foo.d"},
		{"pattern": "*", "dstName": "foo", "dstType": "materials"},
		{"pattern": "*", "dstName": "foo", "dstType": "materials"},
	}
	srcArtifacts := []map[string]interface{}{
		{},
		{"foo.py": map[string]interface{}{"sha265": "abc"}},
		{"foo.py": map[string]interface{}{"sha265": "abc"}},
		{"foo.py": map[string]interface{}{"sha265": "abc"}},
		{"foo.d/foo.py": map[string]interface{}{"sha265": "abc"}},
		{"foo.py": map[string]interface{}{"sha265": "dead"}},
		{"bar.py": map[string]interface{}{"sha265": "abc"}},
	}
	// queue[i] = InterfaceKeyStrings(srcArtifacts[i])
	itemsMetadata := []map[string]Metablock{
		{},
		{},
		{"foo": {Signed: Link{Name: "foo", Materials: map[string]interface{}{"foo.py": map[string]interface{}{"sha265": "abc"}}}}},
		{"foo": {Signed: Link{Name: "foo", Materials: map[string]interface{}{"foo.d/foo.py": map[string]interface{}{"sha265": "abc"}}}}},
		{"foo": {Signed: Link{Name: "foo", Materials: map[string]interface{}{"foo.py": map[string]interface{}{"sha265": "abc"}}}}},
		{"foo": {Signed: Link{Name: "foo", Materials: map[string]interface{}{"foo.py": map[string]interface{}{"sha265": "abc"}}}}},
		{"foo": {Signed: Link{Name: "foo", Materials: map[string]interface{}{"foo.py": map[string]interface{}{"sha265": "abc"}}}}},
	}
	expected := []Set{
		NewSet(),
		NewSet(),
		NewSet("foo.py"),
		NewSet("foo.py"),
		NewSet("foo.d/foo.py"),
		NewSet(),
		NewSet(),
	}

	for i := 0; i < len(ruleData); i++ {

		queue := NewSet(InterfaceKeyStrings(srcArtifacts[i])...)
		result := verifyMatchRule(ruleData[i], srcArtifacts[i], queue,
			itemsMetadata[i])
		if !reflect.DeepEqual(result, expected[i]) {
			t.Errorf("verifyMatchRule returned '%s', expected '%s'", result,
				expected[i])
		}
	}
}

func TestReduceStepsMetadata(t *testing.T) {
	var mb Metablock
	if err := mb.Load("demo.layout"); err != nil {
		t.Errorf("Unable to parse template file: %s", err)
	}
	layout := mb.Signed.(Layout)
	layout.Steps = []Step{{SupplyChainItem: SupplyChainItem{Name: "foo"}}}

	// Test 1: Successful reduction of multiple links for one step (foo)
	stepsMetadata := map[string]map[string]Metablock{
		"foo": {
			"a": Metablock{Signed: Link{
				Type:      "link",
				Name:      "foo",
				Materials: map[string]interface{}{"foo.py": map[string]interface{}{"sha265": "abc"}},
				Products:  map[string]interface{}{"bar.py": map[string]interface{}{"sha265": "cde"}},
			}},
			"b": Metablock{Signed: Link{
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
	stepsMetadataList := []map[string]map[string]Metablock{
		{"foo": {
			"a": Metablock{Signed: Link{Materials: map[string]interface{}{"foo.py": map[string]interface{}{"sha265": "abc"}}}},
			"b": Metablock{Signed: Link{Materials: map[string]interface{}{"foo.py": map[string]interface{}{"sha265": "def"}}}},
		}},
		{"foo": {
			"a": Metablock{Signed: Link{Materials: map[string]interface{}{"foo.py": map[string]interface{}{"sha265": "abc"}}}},
			"b": Metablock{Signed: Link{Materials: map[string]interface{}{"bar.py": map[string]interface{}{"sha265": "abc"}}}},
		}},
		{"foo": {
			"a": Metablock{Signed: Link{Products: map[string]interface{}{"foo.py": map[string]interface{}{"sha265": "abc"}}}},
			"b": Metablock{Signed: Link{Products: map[string]interface{}{"foo.py": map[string]interface{}{"sha265": "def"}}}},
		}},
		{"foo": {
			"a": Metablock{Signed: Link{Products: map[string]interface{}{"foo.py": map[string]interface{}{"sha265": "abc"}}}},
			"b": Metablock{Signed: Link{Products: map[string]interface{}{"bar.py": map[string]interface{}{"sha265": "abc"}}}},
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
		t.Errorf("Error while calling ReduceStepsMetadata: %s", err)
	}
	//NOTE: This test won't get any further because of panic
}

func TestVerifyStepCommandAlignment(t *testing.T) {
	var mb Metablock
	if err := mb.Load("demo.layout"); err != nil {
		t.Errorf("Unable to load template file: %s", err)
	}
	layout := mb.Signed.(Layout)
	layout.Steps = []Step{
		{
			SupplyChainItem: SupplyChainItem{Name: "foo"},
			ExpectedCommand: []string{"rm", "-rf", "."},
		},
	}

	stepsMetadata := map[string]map[string]Metablock{
		"foo": {"a": Metablock{Signed: Link{Command: []string{"rm", "-rf", "/"}}}},
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
	keyID1 := "2f89b9272acfc8f4a0a0f094d789fdb0ba798b0fe41f2f5f417c12f0085ff498"
	keyID2 := "776a00e29f3559e0141b3b096f696abc6cfb0c657ab40f441132b345b08453f5"
	keyID3 := "abcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabca"

	var mb Metablock
	if err := mb.Load("demo.layout"); err != nil {
		t.Errorf("Unable to load template file: %s", err)
	}
	layout := mb.Signed.(Layout)

	layout.Steps = []Step{{SupplyChainItem: SupplyChainItem{
		Name: "foo"},
		Threshold: 2,
		PubKeys:   []string{keyID1, keyID2, keyID3}}}

	var mbLink1 Metablock
	if err := mbLink1.Load("foo.2f89b927.link"); err != nil {
		t.Errorf("Unable to load link file: %s", err)
	}
	var mbLink2 Metablock
	if err := mbLink2.Load("foo.776a00e2.link"); err != nil {
		t.Errorf("Unable to load link file: %s", err)
	}
	var mbLinkBroken Metablock
	if err := mbLinkBroken.Load("foo.776a00e2.link"); err != nil {
		t.Errorf("Unable to load link file: %s", err)
	}
	mbLinkBroken.Signatures[0].Sig = "breaksignature"

	// Test less then threshold distinct valid links errors:
	// - Missing step name in step metadata map
	// - Missing links for step
	// - Less than threshold links for step
	// - Less than threshold distinct links for step
	// - Less than threshold validly signed links for step
	stepsMetadata := []map[string]map[string]Metablock{
		{"bar": nil},
		{"foo": nil},
		{"foo": {keyID1: mbLink1}},
		{"foo": {keyID1: mbLink1, keyID2: mbLink1}},
		{"foo": {keyID1: mbLink1, keyID2: mbLinkBroken}},
	}
	for i := 0; i < len(stepsMetadata); i++ {
		result, err := VerifyLinkSignatureThesholds(layout, stepsMetadata[i], x509.NewCertPool())
		if err == nil {
			t.Errorf("VerifyLinkSignatureThesholds returned (%s, %s), expected"+
				" 'not enough distinct valid links' error.", result, err)
		}
	}

	// Test successfully return threshold distinct valid links:
	// - Threshold 2, two valid links
	// - Threshold 2, two valid links, one invalid link ignored
	stepsMetadata = []map[string]map[string]Metablock{
		{"foo": {keyID1: mbLink1, keyID2: mbLink2}},
		{"foo": {keyID1: mbLink1, keyID2: mbLink2, keyID3: mbLinkBroken}},
	}
	for i := 0; i < len(stepsMetadata); i++ {
		result, err := VerifyLinkSignatureThesholds(layout, stepsMetadata[i], x509.NewCertPool())
		validLinks, ok := result["foo"]
		if !ok || len(validLinks) != 2 {
			t.Errorf("VerifyLinkSignatureThesholds returned (%s, %s), expected"+
				" a map of two valid foo links.", result, err)
		}
	}
}

func TestLoadLinksForLayout(t *testing.T) {
	keyID1 := "2f89b9272acfc8f4a0a0f094d789fdb0ba798b0fe41f2f5f417c12f0085ff498"
	keyID2 := "776a00e29f3559e0141b3b096f696abc6cfb0c657ab40f441132b345b08453f5"
	var mb Metablock
	if err := mb.Load("demo.layout"); err != nil {
		t.Errorf("Unable to load template file: %s", err)
	}
	layout := mb.Signed.(Layout)

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
	var mb Metablock
	if err := mb.Load("demo.layout"); err != nil {
		t.Errorf("Unable to load template file: %s", err)
	}
	layout := mb.Signed.(Layout)

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
	err := VerifyLayoutExpiration(layout)
	if err != nil {
		t.Errorf("VerifyLayoutExpiration returned '%s', expected nil", err)
	}
}

func TestVerifyLayoutSignatures(t *testing.T) {
	var mbLayout Metablock
	if err := mbLayout.Load("demo.layout"); err != nil {
		t.Errorf("Unable to load template file: %s", err)
	}
	var layoutKey Key
	if err := layoutKey.LoadKey("alice.pub", "rsassa-pss-sha256", []string{"sha256", "sha512"}); err != nil {
		t.Errorf("Unable to load public key file: %s", err)
	}

	// Test layout signature verification errors:
	// - Not verification keys (must be at least one)
	// - No signature found for verification key
	layoutKeysList := []map[string]Key{{}, {layoutKey.KeyID: Key{}}}
	expectedErrors := []string{"at least one key", "No signature found for key"}

	for i := 0; i < len(layoutKeysList); i++ {
		err := VerifyLayoutSignatures(mbLayout, layoutKeysList[i])
		if err == nil || !strings.Contains(err.Error(), expectedErrors[i]) {
			t.Errorf("VerifyLayoutSignatures returned '%s', expected '%s' error",
				err, expectedErrors[i])
		}
	}

	// Test successful layout signature verification
	err := VerifyLayoutSignatures(mbLayout, map[string]Key{layoutKey.KeyID: layoutKey})
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

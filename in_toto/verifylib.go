/*
Package in_toto implements types and routines to verify a software supply chain
according to the in-toto specification.
See https://github.com/in-toto/docs/blob/master/in-toto-spec.md
*/
package in_toto

import (
	"fmt"
	osPath "path"
	"path/filepath"
	"reflect"
	"strings"
	"time"
)

/*
RunInspections iteratively executes the command in the Run field of all
inspections of the passed layout, creating unsigned link metadata that records
all files found in the current working directory as materials (before command
execution) and products (after command execution).  A map with inspection names
as keys and Metablocks containing the generated link metadata as values is
returned.  The format is:
  {
    <inspection name> : Metablock,
    <inspection name> : Metablock,
    ...
  }
If executing the inspection command fails, or if the executed command has a
non-zero exit code, the first return value is nil and the second return value
is the error.
*/
func RunInspections(layout Layout) (map[string]Metablock, error) {
	inspectionMetadata := make(map[string]Metablock)

	for _, inspection := range layout.Inspect {

		linkMb, err := InTotoRun(inspection.Name, []string{"."}, []string{"."},
			inspection.Run)
		if err != nil {
			return nil, err
		}

		retVal := linkMb.Signed.(Link).ByProducts["return-value"]
		if retVal != 0 {
			return nil, fmt.Errorf("Inspection command '%s' of inspection '%s'"+
				" returned a non-zero value: %d", inspection.Run, inspection.Name,
				retVal)
		}

		// Dump inspection link to cwd using the short link name format
		linkName := fmt.Sprintf(LinkNameFormatShort, inspection.Name)
		linkMb.Dump(linkName)

		inspectionMetadata[inspection.Name] = linkMb
	}
	return inspectionMetadata, nil
}

// Subtract is a helper function that performs set subtraction
// TODO: This function has O(n**2), consider using maps (in linear-time)
// https://siongui.github.io/2018/03/14/go-set-difference-of-two-arrays/, or
// find a proper set library.
func Subtract(a []string, b []string) []string {
	var result []string
	for _, valA := range a {
		valInB := false
		for _, valB := range b {
			if valA == valB {
				valInB = true
				break
			}
		}
		if !valInB {
			result = append(result, valA)
		}
	}
	return result
}

// FnFilter is a helper function that mimics fnmatch.filter from the Python
// standard library using Go Match from the path/filepath package.
func FnFilter(pattern string, names []string) []string {
	var namesFiltered []string
	for _, name := range names {
		matched, err := filepath.Match(pattern, name)
		if err != nil {
			// The pattern was invalid. We treat it as no match.
			// TODO: Maybe we should inform the caller at least with a warning?
			continue
		}
		if matched {
			namesFiltered = append(namesFiltered, name)
		}
	}
	return namesFiltered
}

/*
VerifyArtifacts iteratively applies the material and product rules of the
passed items (step or inspection) to enforce and authorize artifacts (materials
or products) reported by the corresponding link and to guarantee that
artifacts are linked together across links.  In the beginning all artifacts are
placed in a queue according to their type.  If an artifact gets consumed by a
rule it is removed from the queue.  An artifact can only be consumed once by
one set of rules.

Rules of type MATCH, ALLOW and DISALLOW are supported.

MATCH and ALLOW remove artifacts from the corresponding queues on success, and
leave the queue unchanged on failure.  Hence, it is left to a subsequent
DISALLOW rule to fail overall verification, if artifacts are left in the queue
that should have been consumed by preceding rules.
*/
func VerifyArtifacts(items []interface{},
	itemsMetadata map[string]Metablock) error {
	// Verify artifact rules for each item in the layout
	for _, itemI := range items {
		// The layout item (interface) must be a Link or an Inspection we are only
		// interested in the name and the expected materials and products
		var itemName string
		var expected_materials [][]string
		var expected_products [][]string

		switch item := itemI.(type) {
		case Step:
			itemName = item.Name
			expected_materials = item.ExpectedMaterials
			expected_products = item.ExpectedProducts

		case Inspection:
			itemName = item.Name
			expected_materials = item.ExpectedMaterials
			expected_products = item.ExpectedProducts

		default: // Something's wrong
			return fmt.Errorf("VerifyArtifact received an item of invalid type,"+
				" elements of passed slice 'items' must be one of 'Step' or"+
				" 'Inspection', got: '%s'", reflect.TypeOf(item))
		}
		srcLinkMb := itemsMetadata[itemName]

		verificationDataList := []map[string]interface{}{
			map[string]interface{}{
				"rules":     expected_materials,
				"artifacts": srcLinkMb.Signed.(Link).Materials,
			},
			map[string]interface{}{
				"rules":     expected_products,
				"artifacts": srcLinkMb.Signed.(Link).Products,
			},
		}

		// Process all material rules using the corresponding materials
		// and all product rules using the corresponding products
		for _, verificationData := range verificationDataList {

			rules := verificationData["rules"].([][]string)
			artifacts := verificationData["artifacts"].(map[string]interface{})

			// Create a queue of artifact names (paths).  Each rule only operates on
			// artifacts in that queue.  If a rule consumes an artifact (i.e. can be
			// applied successfully), the artifact is removed from the queue.  By
			// applying a DISALLOW rule eventually, verification may return an error,
			// if the rule matches any artifacts in the queue that should have been
			// consumed earlier.
			var queue []string
			for name, _ := range artifacts {
				queue = append(queue, name)
			}

			// Verify rules sequentially
			for _, rule := range rules {
				// Parse rule
				ruleData, err := UnpackRule(rule)
				if err != nil {
					return err
				}

				// Process rules according to rule type
				// TODO: Currently we only process rules of type "match", "allow" or
				// "disallow"
				switch ruleData["type"] {
				case "match":
					// Get destination link metadata
					dstLinkMb, exists := itemsMetadata[ruleData["dstName"]]
					if !exists {
						// Destination link does not exist, rule can't consume any
						// artifacts
						continue
					}

					// Get artifacts from destination link metadata
					var dstArtifacts map[string]interface{}
					switch ruleData["dstType"] {
					case "materials":
						dstArtifacts = dstLinkMb.Signed.(Link).Materials

					case "products":
						dstArtifacts = dstLinkMb.Signed.(Link).Products
					}

					// Normalize optional source and destination prefixes, i.e. if
					// there is a prefix, then add a trailing slash if not there yet
					for _, prefix := range []string{"srcPrefix", "dstPrefix"} {
						if ruleData[prefix] != "" &&
							!strings.HasSuffix(ruleData[prefix], "/") {
							ruleData[prefix] += "/"
						}
					}
					// Iterate over queue and mark consumed artifacts
					var consumed []string
					for _, srcPath := range queue {
						// Remove optional source prefix from source artifact path
						// Noop if prefix is empty, or artifact does not have it
						srcBasePath := strings.TrimPrefix(srcPath, ruleData["srcPrefix"])

						// Ignore artifacts not matched by rule pattern
						matched, err := filepath.Match(ruleData["pattern"], srcBasePath)
						if err != nil || !matched {
							continue
						}

						// Construct corresponding destination artifact path, i.e.
						// an optional destination prefix plus the source base path
						dstPath := osPath.Join(ruleData["dstPrefix"], srcBasePath)

						// Try to find the corresponding destination artifact
						dstArtifact, exists := dstArtifacts[dstPath]
						// Ignore artifacts without corresponding destination artifact
						if !exists {
							continue
						}

						// Ignore artifact pairs with no matching hashes
						if !reflect.DeepEqual(artifacts[srcPath], dstArtifact) {
							continue
						}

						// Only if a source and destination artifact pair was found and
						// their hashes are equal, will we mark the source artifact as
						// successfully consumed, i.e. it will be removed from the queue
						consumed = append(consumed, srcPath)
					}
					queue = Subtract(queue, consumed)

				case "allow":
					consumed := FnFilter(ruleData["pattern"], queue)
					queue = Subtract(queue, consumed)

				case "disallow":
					disallowed := FnFilter(ruleData["pattern"], queue)
					if len(disallowed) > 0 {
						return fmt.Errorf("Artifact verification failed for %s '%s'."+
							" Artifact(s) %s disallowed by rule %s.",
							reflect.TypeOf(itemI), itemName, disallowed, rule)
					}

				// TODO: Support create, modify, delete rules
				default:
					return fmt.Errorf("Cannot process artifact rule '%s'. We"+
						" don't support rules of type '%s'", rule,
						strings.ToUpper(ruleData["type"]))
				}
			}
		}
	}
	return nil
}

/*
ReduceStepsMetadata merges for each step of the passed Layout all the passed
per-functionary links into a single link, asserting that the reported Materials
and Products are equal across links for a given step.  This function may be
used at a time during the overall verification, where link threshold's have
been verified and subsequent verification only needs one exemplary link per
step.  The function returns a map with one Metablock (link) per step:
  {
    <step name> : Metablock,
    <step name> : Metablock,
    ...
  }
If links corresponding to the same step report different Materials or different
Products, the first return value is nil and the second return value is the
error.
*/
func ReduceStepsMetadata(layout Layout,
	stepsMetadata map[string]map[string]Metablock) (map[string]Metablock,
	error) {
	stepsMetadataReduced := make(map[string]Metablock)

	for _, step := range layout.Steps {
		linksPerStep, ok := stepsMetadata[step.Name]
		// We should never get here, layout verification must fail earlier
		if !ok || len(linksPerStep) < 1 {
			panic("Could not reduce metadata for step '" + step.Name +
				"', no link metadata found.")
		}

		// Get the first link (could be any link) for the current step, which will
		// serve as reference link for below comparisons
		var referenceKeyID string
		var referenceLinkMb Metablock
		for keyID, linkMb := range linksPerStep {
			referenceLinkMb = linkMb
			referenceKeyID = keyID
			break
		}

		// Only one link, nothing to reduce, take the reference link
		if len(linksPerStep) == 1 {
			stepsMetadataReduced[step.Name] = referenceLinkMb

			// Multiple links, reduce but first check
		} else {
			// Artifact maps must be equal for each type among all links
			// TODO: What should we do if there are more links, than the
			// threshold requires, but not all of them are equal? Right now we would
			// also error.
			for keyID, linkMb := range linksPerStep {
				if !reflect.DeepEqual(linkMb.Signed.(Link).Materials,
					referenceLinkMb.Signed.(Link).Materials) ||
					!reflect.DeepEqual(linkMb.Signed.(Link).Products,
						referenceLinkMb.Signed.(Link).Products) {
					return nil, fmt.Errorf("Link '%s' and '%s' have different"+
						" artifacts.",
						fmt.Sprintf(LinkNameFormat, step.Name, referenceKeyID),
						fmt.Sprintf(LinkNameFormat, step.Name, keyID))
				}
			}
			// We haven't errored out, so we can reduce (i.e take the reference link)
			stepsMetadataReduced[step.Name] = referenceLinkMb
		}
	}
	return stepsMetadataReduced, nil
}

/*
VerifyStepCommandAlignment (soft) verifies that for each step of the passed
layout the command executed, as per the passed link, matches the expected
command, as per the layout.  Soft verification means that, in case a command
does not align, a warning is issued.
*/
func VerifyStepCommandAlignment(layout Layout,
	stepsMetadata map[string]map[string]Metablock) {
	for _, step := range layout.Steps {
		linksPerStep, ok := stepsMetadata[step.Name]
		// We should never get here, layout verification must fail earlier
		if !ok || len(linksPerStep) < 1 {
			panic("Could not verify command alignment for step '" + step.Name +
				"', no link metadata found.")
		}

		for signerKeyID, linkMb := range linksPerStep {
			expectedCommandS := strings.Join(step.ExpectedCommand, " ")
			executedCommandS := strings.Join(linkMb.Signed.(Link).Command, " ")

			if expectedCommandS != executedCommandS {
				linkName := fmt.Sprintf(LinkNameFormat, step.Name, signerKeyID)
				fmt.Printf("WARNING: Expected command for step '%s' (%s) and command"+
					" reported by '%s' (%s) differ.\n",
					step.Name, expectedCommandS, linkName, executedCommandS)
			}
		}
	}
}

/*
VerifyLinkSignatureThesholds verifies that for each step of the passed layout,
there are at least Threshold links, validly signed by different authorized
functionaries.  The returned map of link metadata per steps contains only
links with valid signatures from distinct functionaries and has the format:
  {
    <step name> : {
      <key id>: Metablock,
      <key id>: Metablock,
      ...
    },
    <step name> : {
      <key id>: Metablock,
      <key id>: Metablock,
      ...
    }
    ...
  }
If for any step of the layout there are not enough links available, the first
return value is nil and the second return value is the error.
*/
func VerifyLinkSignatureThesholds(layout Layout,
	stepsMetadata map[string]map[string]Metablock) (
	map[string]map[string]Metablock, error) {
	// This will stores links with valid signature from an authorized functionary
	// for all steps
	stepsMetadataVerified := make(map[string]map[string]Metablock)

	// Try to find enough (>= threshold) links each with a valid signature from
	// distinct authorized functionaries for each step
	for _, step := range layout.Steps {
		// This will store links with valid signature from an authorized
		// functionary for the given step
		linksPerStepVerified := make(map[string]Metablock)

		// Check if there are any links at all for the given step
		linksPerStep, ok := stepsMetadata[step.Name]
		if !ok || len(linksPerStep) < 1 {
			continue
		}

		// For each link corresponding to a step, check that the signer key was
		// authorized, the layout contains a verification key and the signature
		// verification passes.  Only good links are stored, to verify thresholds
		// below.
		for signerKeyID, linkMb := range linksPerStep {
			for _, authorizedKeyID := range step.PubKeys {
				if signerKeyID == authorizedKeyID {
					if verifierKey, ok := layout.Keys[authorizedKeyID]; ok {
						if err := linkMb.VerifySignature(verifierKey); err == nil {
							linksPerStepVerified[signerKeyID] = linkMb
							break
						}
					}
				}
			}
		}
		// Store all good links for a step
		stepsMetadataVerified[step.Name] = linksPerStepVerified
	}

	// Verify threshold for each step
	for _, step := range layout.Steps {
		linksPerStepVerified, _ := stepsMetadataVerified[step.Name]

		if len(linksPerStepVerified) < step.Threshold {
			linksPerStep, _ := stepsMetadata[step.Name]
			return nil, fmt.Errorf("Step '%s' requires '%d' link metadata file(s)."+
				" '%d' out of '%d' available link(s) have a valid signature from an"+
				" authorized signer.", step.Name, step.Threshold,
				len(linksPerStepVerified), len(linksPerStep))
		}
	}
	return stepsMetadataVerified, nil
}

/*
LoadLinksForLayout loads for every Step of the passed Layout a Metablock
containing the corresponding Link.  A base path to a directory that contains
the links may be passed using linkDir.  Link file names are constructed,
using LinkNameFormat together with the corresponding step name and authorized
functionary key ids.  A map of link metadata is returned and has the following
format:
  {
    <step name> : {
      <key id>: Metablock,
      <key id>: Metablock,
      ...
    },
    <step name> : {
      <key id>: Metablock,
      <key id>: Metablock,
      ...
    }
    ...
  }
If a link cannot be loaded at a constructed link name or is invalid, it is
ignored. Only a preliminary threshold check is performed, that is, if there
aren't at least Threshold links for any given step, the first return value
is nil and the second return value is the error.
*/
func LoadLinksForLayout(layout Layout, linkDir string) (
	map[string]map[string]Metablock, error) {
	stepsMetadata := make(map[string]map[string]Metablock)

	for _, step := range layout.Steps {
		linksPerStep := make(map[string]Metablock)

		for _, authorizedKeyId := range step.PubKeys {
			linkName := fmt.Sprintf(LinkNameFormat, step.Name, authorizedKeyId)
			linkPath := osPath.Join(linkDir, linkName)

			var linkMb Metablock
			if err := linkMb.Load(linkPath); err != nil {
				continue
			}

			linksPerStep[authorizedKeyId] = linkMb
		}

		if len(linksPerStep) < step.Threshold {
			return nil, fmt.Errorf("Step '%s' requires '%d' link metadata file(s),"+
				" found '%d'.", step.Name, step.Threshold, len(linksPerStep))
		}

		stepsMetadata[step.Name] = linksPerStep
	}

	return stepsMetadata, nil
}

/*
VerifyLayoutExpiration verifies that the passed Layout has not expired.  It
returns an error if the (zulu) date in the Expires field is in the past.
*/
func VerifyLayoutExpiration(layout Layout) error {
	expires, err := time.Parse(time.RFC3339, layout.Expires)
	if err != nil {
		return err
	}
	// Uses timezone of expires, i.e. UTC
	if time.Until(expires) < 0 {
		return fmt.Errorf("Layout has expired on '%s'.", expires)
	}
	return nil
}

/*
VerifyLayoutSignatures verifies for each key in the passed key map the
corresponding signature of the Layout in the passed Metablock's Signed field.
Signatures and keys are associated by key id.  If the key map is empty, or the
Metablock's Signature field does not have a signature for one or more of the
passed keys, or a matching signature is invalid, an error is returned.
*/
func VerifyLayoutSignatures(layoutMb Metablock,
	layoutKeys map[string]Key) error {
	if len(layoutKeys) < 1 {
		return fmt.Errorf("Layout verification requires at least one key.")
	}

	for _, key := range layoutKeys {
		if err := layoutMb.VerifySignature(key); err != nil {
			return err
		}
	}
	return nil
}

/*
Merges the materials of the first step (as mentioned in the layout)
and the products of the last step and returns a new link.
This link reports the materials and products and summarizes the
overall software supply chain.
NOTE: The assumption is that the steps mentioned in the layout are
to be performed sequentially. So, the first step mentioned in the
layout denotes what comes into the supply chain and the last step
denotes what goes out.
*/
func GetSummaryLink(layout Layout, stepsMetadataReduced map[string]Metablock,
	stepName string) (Metablock, error) {
	var summaryLink Link
	var result Metablock
	if len(layout.Steps) > 0 {
		firstStepLink := stepsMetadataReduced[layout.Steps[0].Name]
		lastStepLink := stepsMetadataReduced[layout.Steps[len(layout.Steps)-1].Name]

		summaryLink.Materials = firstStepLink.Signed.(Link).Materials
		summaryLink.Name = stepName
		summaryLink.Type = firstStepLink.Signed.(Link).Type

		summaryLink.Products = lastStepLink.Signed.(Link).Products
		summaryLink.ByProducts = lastStepLink.Signed.(Link).ByProducts
		// Using the last command of the sublayout as the command
		// of the summary link can be misleading. Is it necessary to
		// include all the commands executed as part of sublayout?
		summaryLink.Command = lastStepLink.Signed.(Link).Command
	}

	result.Signed = summaryLink

	return result, nil
}

/*
Check if any step in the supply chain is a sublayout, and if so,
recursively resolve it and replace it with a summary link summarizing
the steps carried out in the sublayout.
*/
func VerifySublayouts(layout Layout,
	stepsMetadataVerified map[string]map[string]Metablock,
	superLayoutLinkPath string) (map[string]map[string]Metablock, error) {
	for stepName, linkData := range stepsMetadataVerified {
		for keyId, metadata := range linkData {
			if _, ok := metadata.Signed.(Layout); ok {
				layoutKeys := make(map[string]Key)
				layoutKeys[keyId] = layout.Keys[keyId]

				sublayoutLinkDir := fmt.Sprintf(SublayoutLinkDirFormat,
					stepName, keyId)
				sublayoutLinkPath := filepath.Join(superLayoutLinkPath,
					sublayoutLinkDir)
				summaryLink, err := InTotoVerify(metadata, layoutKeys,
					sublayoutLinkPath, stepName)
				if err != nil {
					return nil, err
				}
				linkData[keyId] = summaryLink
			}

		}
	}
	return stepsMetadataVerified, nil
}

/*
InTotoVerify can be used to verify an entire software supply chain according to
the in-toto specification.  It requires the metadata of the root layout, a map
that contains public keys to verify the root layout signatures, and a path to
a directory from where it can load link metadata files, which are treated as
signed evidence for the steps defined in the layout. The verification routine
is as follows:

1. Verify layout signature(s) using passed key(s)
2. Verify layout expiration date
3. Load link metadata files for steps of layout
4. Verify signatures and signature thresholds for steps of layout
5. Verify sublayouts recursively
6. Verify command alignment for steps of layout (only warns)
7. Verify artifact rules for steps of layout
8. Execute inspection commands (generates link metadata for each inspection)
9. Verify artifact rules for inspections of layout

If any of the verification routines fail, verification is aborted and an error
is returned.

NOTE: Parameter substitution, artifact rules of type "create", "modify"
and "delete" are currently not supported.
*/
func InTotoVerify(layoutMb Metablock, layoutKeys map[string]Key,
	linkDir string, stepName string) (Metablock, error) {

	var summaryLink Metablock
	var err error

	// Verify root signatures
	if err := VerifyLayoutSignatures(layoutMb, layoutKeys); err != nil {
		return summaryLink, err
	}

	// Extract the layout from its Metablock container (for further processing)
	layout := layoutMb.Signed.(Layout)

	// Verify layout expiration
	if err := VerifyLayoutExpiration(layout); err != nil {
		return summaryLink, err
	}

	// TODO: Substitute parameters

	// Load links for layout
	stepsMetadata, err := LoadLinksForLayout(layout, linkDir)
	if err != nil {
		return summaryLink, err
	}

	// Verify link signatures
	stepsMetadataVerified, err := VerifyLinkSignatureThesholds(layout,
		stepsMetadata)
	if err != nil {
		return summaryLink, err
	}

	// Verify and resolve sublayouts
	stepsSublayoutVerified, err := VerifySublayouts(layout,
		stepsMetadataVerified, linkDir)
	if err != nil {
		return summaryLink, err
	}

	// Verify command alignment (WARNING only)
	VerifyStepCommandAlignment(layout, stepsSublayoutVerified)

	// Given that signature thresholds have been checked above and the rest of
	// the relevant link properties, i.e. materials and products, have to be
	// exactly equal, we can reduce the map of steps metadata. However, we error
	// if the relevant properties are not equal among links of a step.
	stepsMetadataReduced, err := ReduceStepsMetadata(layout,
		stepsSublayoutVerified)
	if err != nil {
		return summaryLink, err
	}

	// Verify artifact rules
	if err = VerifyArtifacts(layout.StepsAsInterfaceSlice(), stepsMetadataReduced); err != nil {
		return summaryLink, err
	}

	inspectionMetadata, err := RunInspections(layout)
	if err != nil {
		return summaryLink, err
	}

	// Add steps metadata to inspection metadata, because inspection artifact
	// rules may also refer to artifacts reported by step links
	for k, v := range stepsMetadataReduced {
		inspectionMetadata[k] = v
	}

	if err = VerifyArtifacts(layout.InspectAsInterfaceSlice(), inspectionMetadata); err != nil {
		return summaryLink, err
	}

	summaryLink, err = GetSummaryLink(layout, stepsMetadataReduced, stepName)
	if err != nil {
		return summaryLink, err
	}

	return summaryLink, nil
}

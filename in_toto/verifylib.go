package intoto

import (
  "fmt"
  "time"
  "strings"
  "reflect"
  osPath "path"
  "path/filepath"
)

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

// Mimics Python's fnmatch.filter using Go's Match from path/filepath package
func FnFilter (pattern string, names []string) []string {
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


func VerifyArtifacts(items []interface{}, stepsMetadata map[string]Metablock) error {
  // Verify artifact rules for each item in the layout
  for _, itemI := range items {
    // The layout item (interface) must be a Link or an Inspection
    // we are only interested in the name and the expected materials and products
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
        return fmt.Errorf("VerifyArtifact received an item of invalid type," +
            " elements of passed slice 'items' must be one of 'Step' or" +
            " 'Inspection', got: '%s'", reflect.TypeOf(item))
    }
    srcLinkMb := stepsMetadata[itemName]

    verificationDataList := []map[string]interface{}{
      map[string]interface{}{
        "rules": expected_materials,
        "artifacts": srcLinkMb.Signed.(Link).Materials,
      },
      map[string]interface{}{
        "rules": expected_products,
        "artifacts": srcLinkMb.Signed.(Link).Products,
      },
    }

    // Process all material rules using the corresponding materials
    // and all product rules using the corresponding products
    for _, verificationData := range verificationDataList {

      rules := verificationData["rules"].([][]string)
      artifacts := verificationData["artifacts"].(map[string]interface{})

      // Create a queue of artifact names (paths)
      // Each rule only operates on artifacts in that queue
      // If a rule consumes an artifact (can be applied successfully) it is
      // removed from the queue.
      // By applying a DISALLOW rule eventually, verification may return an
      // error, if the rule matches any artifacts in the queue that should
      // have been consumed earlier.
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
        // TODO: Currently we only support "MATCH", "ALLOW" and "DISALLOW"
        switch ruleData["type"] {
          case "match":
            // Get destination link metadata
            dstLinkMb, exists := stepsMetadata[ruleData["dstName"]]
            if !exists {
              // Destination link does not exist, rule can't consume any artifacts
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

            // Normalize optional source and destination prefixes, i.e.
            // if there is a prefix, then add a trailing slash if not there yet
            for _, prefix := range []string{"srcPrefix", "dstPrefix"} {
              if ruleData[prefix] != "" &&
                  ! strings.HasSuffix(ruleData[prefix], "/") {
                ruleData[prefix] += "/"
              }
            }

            // Iterate over queue and add consumed artifacts
            // consumed is subtracted from queue
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

              // Only if a source and destination artifact pair was found
              // and their hashes are equal, will we mark the source artifact
              // as successfully consumed, i.e. it will be removed from thequeue
              consumed = append(consumed, srcPath)
            }
            queue = Subtract(queue, consumed)

          case "allow":
            consumed := FnFilter(ruleData["pattern"], queue)
            queue = Subtract(queue, consumed)

          case "disallow":
            disallowed := FnFilter(ruleData["pattern"], queue)
            if len(disallowed) > 0 {
              return fmt.Errorf("Artifact verification failed for %s '%s'." +
                  " Artifact(s) %s disallowed by rule %s.",
                  reflect.TypeOf(itemI), itemName, disallowed, rule)
            }

          // TODO: Support create, modify, delete rules
          default:
              return fmt.Errorf("Cannot process artifact rule '%s'. We" +
                  " don't support rules of type '%s'", rule,
                  strings.ToUpper(ruleData["type"]))
        }
      }
    }
  }
  return nil
}


func ReduceStepsMetadata(layout Layout, stepsMetadata map[string]map[string]Metablock) (map[string]Metablock, error){
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
          return nil, fmt.Errorf("Link '%s' and '%s' have different artifacts.",
              fmt.Sprintf(LinkNameFormat, step.Name, referenceKeyID),
              fmt.Sprintf(LinkNameFormat, step.Name, keyID))
        }
      }
      // We haven't errored out, so we can reduce
      stepsMetadataReduced[step.Name] = referenceLinkMb
    }
  }
  return stepsMetadataReduced, nil
}


func VerifyStepCommandAlignment(layout Layout, stepsMetadata map[string]map[string]Metablock) {
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
        fmt.Printf("WARNING: Expected command for step '%s' (%s) and command" +
            " reported by '%s' (%s) differ.\n",
            step.Name, expectedCommandS, linkName, executedCommandS)
      }
    }
  }
}


func VerifyLinkSignatureThesholds(layout Layout, stepsMetadata map[string]map[string]Metablock) (map[string]map[string]Metablock, error) {
  // Copy of passed stepsMetadata
  // But only stores links with valid signature from an authorized functionary
  stepsMetadataVerified := make(map[string]map[string]Metablock)

  // Try to find enough (>= threshold) links each with a valid signature from
  // distinct authorized functionaries for each step
  for _, step := range layout.Steps {
    // Stores links with valid signature from authorized functionary per step
    linksPerStepVerified := make(map[string]Metablock)

    // Check if there are any links at all for a given step
    linksPerStep, ok := stepsMetadata[step.Name]
    if !ok || len(linksPerStep) < 1 {
      continue
    }

    // For each link of corresponding to a step, check that the signer key
    // was authorized, the layout contains a verification key and the
    // signature verification passes.
    // Only good links are stored, to verify thresholds below
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
      return nil, fmt.Errorf(`Step '%s' requires '%d' link metadata file(s).
          '%d' out of '%d' available link(s) have a valid signature from an
          authorized signer.`, step.Name,
          step.Threshold, len(linksPerStepVerified), len(linksPerStep))
    }
  }
  return stepsMetadataVerified, nil
}


func LoadLinksForLayout(layout Layout, linkDir string) (map[string]map[string]Metablock, error) {
  stepsMetadata := make(map[string]map[string]Metablock)

  for _, step := range layout.Steps {
    linksPerStep := make(map[string]Metablock)

    for _, authorizedKeyId := range step.PubKeys {
      linkName := fmt.Sprintf(LinkNameFormat, step.Name, authorizedKeyId)
      linkPath := osPath.Join(linkDir, linkName)

      var linkMb Metablock
      if err := linkMb.Load(linkPath); err != nil {
        return nil, err
      }

      linksPerStep[authorizedKeyId] = linkMb
    }

    if len(linksPerStep) < step.Threshold {
      return nil, fmt.Errorf(`Step '%s' requires '%d' link metadata file(s),
          found '%d'.`, step.Name, step.Threshold, len(linksPerStep))
    }

    stepsMetadata[step.Name] = linksPerStep
  }

  return stepsMetadata, nil
}


func VerifyLayoutExpiration(layout Layout) error {
  expires, err := time.Parse(time.RFC3339, layout.Expires)
  if err != nil {
    return err
  }
  // Uses timesone of expires, i.e. UTC
  if time.Until(expires) < 0 {
    return fmt.Errorf("Layout has expired on '%s'.", expires)
  }
  return nil
}


func VerifyLayoutSignatures(layoutMb Metablock, layoutKeys map[string]Key) error {
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


func InTotoVerify(layoutPath string, layoutKeys map[string]Key, linkDir string) error {

  var layoutMb Metablock

  // Load layout
  if err := layoutMb.Load(layoutPath); err != nil {
    return err
  }

  // Verify root signatures
  if err := VerifyLayoutSignatures(layoutMb, layoutKeys); err != nil {
    return err
  }

  // Extract the layout from its Metablock container (for further processing)
  layout := layoutMb.Signed.(Layout)

  // Verify layout expiration
  if err := VerifyLayoutExpiration(layout); err != nil {
    return err
  }

  // Substitute parameters
  // TODO

  // Load links for layout
  stepsMetadata, err := LoadLinksForLayout(layout, linkDir)
  if err != nil {
    return err
  }

  // Verify link signatures
  stepsMetadataVerified, err := VerifyLinkSignatureThesholds(layout, stepsMetadata)
  if err != nil {
    return err
  }

  // Verify sublayouts
  // TODO

  // Verify command alignment (WARNING only)
  VerifyStepCommandAlignment(layout, stepsMetadataVerified)

  // Given that signature thresholds have been checked above and the rest of
  // the relevant link properties, i.e. materials and products, have to be
  // exactly equal, we can reduce the map of steps metadata. However, we error
  // if the relevant properties are not equal among links of a step.
  stepsMetadataReduced, err := ReduceStepsMetadata(layout, stepsMetadataVerified)

  // Go does not allow to pass pass []Step as []interface{}
  // We have to manually copy first :(
  // https://golang.org/doc/faq#convert_slice_of_interface
  stepsI := make([]interface{}, len(layout.Steps))
  for i, v := range layout.Steps {
      stepsI[i] = v
  }

  if err := VerifyArtifacts(stepsI, stepsMetadataReduced); err != nil {
    return err
  }

  // ...
  // TODO
  return nil
}




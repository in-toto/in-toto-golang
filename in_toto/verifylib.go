package intoto

import (
  "fmt"
  "time"
  "strings"
  "reflect"
  osPath "path"
)


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
  // stepsMetadataReduced, err := ReduceStepsMetadata(layout, stepsMetadataVerified)
  _, err = ReduceStepsMetadata(layout, stepsMetadataVerified)

  // ...
  // TODO
  return nil
}




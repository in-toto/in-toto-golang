package intoto

import (
  "fmt"
  osPath "path"
)


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
    if !ok {
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
  // TODO

  // Substitute parameters
  // TODO

  // Load links for layout
  stepsMetadata, err := LoadLinksForLayout(layout, linkDir)
  if err != nil {
    return err
  }

  // Verify link signatures
  // stepsMetadataVerified, err := VerifyLinkSignatureThesholds(layout, stepsMetadata)
  _, err = VerifyLinkSignatureThesholds(layout, stepsMetadata)
  if err != nil {
    return err
  }

  // ...
  // TODO
  return nil
}




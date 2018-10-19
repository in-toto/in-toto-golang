package intoto

import (
  "fmt"
  osPath "path"
)


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
          found '%d'`, step.Name, step.Threshold, len(linksPerStep))
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
  // stepsMetadata, err := LoadLinksForLayout(layout, linkDir)
   _, err := LoadLinksForLayout(layout, linkDir)
   if err != nil {
    return err
  }

  // Verify link signatures

  // ...
  // TODO
  return nil
}




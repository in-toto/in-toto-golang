package main

import (
  "fmt"
  osPath "path"
)


func LoadLinksForLayout(layout Layout, linkDir string) map[string]map[string]Metablock {
  stepsMetadata := make(map[string]map[string]Metablock)

  for _, step := range layout.Steps {
    linksPerStep := make(map[string]Metablock)

    for _, authorizedKeyId := range step.PubKeys {
      linkName := fmt.Sprintf(LinkNameFormat, step.Name, authorizedKeyId)
      linkPath := osPath.Join(linkDir, linkName)

      var linkMb Metablock
      linkMb.Load(linkPath)

      linksPerStep[authorizedKeyId] = linkMb
    }

    if len(linksPerStep) < step.Threshold {
      panic(fmt.Sprintf(`Step '%s' requires '%s' link metadata file(s),
          found '%s'`, step.Name, step.Threshold, len(linksPerStep)))
    }

    stepsMetadata[step.Name] = linksPerStep
  }

  return stepsMetadata
}


func VerifyLayoutSignatures(layoutMb Metablock, layoutKeys map[string]Key) {
  if len(layoutKeys) < 1 {
    panic("Layout signature verification requires at least one key.")
  }

  for _, key := range layoutKeys {
    layoutMb.VerifySignature(key)
  }
}


func InTotoVerify(layoutPath string, layoutKeys map[string]Key, linkDir string) {

  var layoutMb Metablock

  // Load layout
  layoutMb.Load(layoutPath)

  // Verify root signatures
  VerifyLayoutSignatures(layoutMb, layoutKeys)

  // Extract the layout from its Metablock container (for further processing)
  layout := layoutMb.Signed.(Layout)

  // Verify layout expiration
  // TODO

  // Substitute parameters
  // TODO

  // Load links for layout
  stepsMetadata := LoadLinksForLayout(layout, linkDir)

  fmt.Println(stepsMetadata)

  // Verify link signatures

  // ...
  // TODO
}




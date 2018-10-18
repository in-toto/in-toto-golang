package main



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
}




package in_toto

import (
  "fmt"
  "os"
  "os/exec"
  "syscall"
  "io/ioutil"
  "path/filepath"
  "crypto/sha256"
)

func RecordArtifact(path string) (map[string]interface{}, error) {
  // Read file from passed path
  content, err := ioutil.ReadFile(path)
  if err != nil {
    return nil, err
  }

  // Create its sha 256 hash (currently we only support sha256 here)
  hashed := sha256.Sum256(content)

  // Return it in a format that is conformant with link metadata artifacts
  return map[string]interface{} {
    "sha256" : fmt.Sprintf("%x", hashed),
  }, nil

}

func RecordArtifacts(paths []string) (map[string]interface{}, error) {
  artifacts := make(map[string]interface{})
  // NOTE: Walk cannot follow symlinks
  for _, path := range paths {
    err := filepath.Walk(path,
        func(path string, info os.FileInfo, err error) error {
      // Don't hash directories
      if info.IsDir() {
        return nil
      }
      artifact, err := RecordArtifact(path)
      if err != nil {
        return err
      }
      artifacts[path] = artifact
      return nil
    })
    if err != nil {
      return nil, err
    }
  }

  return artifacts, nil
}

func WaitErrToExitCode(err error) int {
  // If there's no exit code, we return -1
  retVal := -1

  // See https://stackoverflow.com/questions/10385551/get-exit-code-go
  if err != nil {
    if exiterr, ok := err.(*exec.ExitError); ok {
      // The program has exited with an exit code != 0
      // This works on both Unix and Windows. Although package
      // syscall is generally platform dependent, WaitStatus is
      // defined for both Unix and Windows and in both cases has
      // an ExitStatus() method with the same signature.
      if status, ok := exiterr.Sys().(syscall.WaitStatus); ok {
        retVal = status.ExitStatus()
      }
    }
  } else {
    retVal = 0
  }

  return retVal
}

func RunCommand(cmdArgs []string) (map[string]interface{}, error) {

  cmd := exec.Command(cmdArgs[0], cmdArgs[1:]...)
  stderrPipe, err := cmd.StderrPipe()
  if err != nil {
    return nil, err
  }
  stdoutPipe, err := cmd.StdoutPipe()
  if err != nil {
    return nil, err
  }

  if err := cmd.Start(); err != nil {
    return nil, err
  }

  // TODO: duplicate stdout, stderr
  stdout, _ := ioutil.ReadAll(stdoutPipe)
  stderr, _ := ioutil.ReadAll(stderrPipe)

  retVal := WaitErrToExitCode(cmd.Wait())

  return map[string]interface{}{
      "return-value": retVal,
      "stdout": stdout,
      "stderr": stderr,
    }, nil
}


func InTotoRun(name string, materialPaths []string, productPaths []string,
    cmdArgs []string) (Metablock, error) {
  var linkMb Metablock
  materials, err := RecordArtifacts(materialPaths)
  if err != nil {
    return linkMb, err
  }

  byProducts, err := RunCommand(cmdArgs)
  if err != nil {
    return linkMb, err
  }

  products, err := RecordArtifacts(productPaths)
  if err != nil {
    return linkMb, err
  }

  linkMb.Signatures = []Signature{}
  linkMb.Signed = Link{
      Type: "link",
      Name: name,
      Materials: materials,
      Products: products,
      ByProducts: byProducts,
      Command: cmdArgs,
      Environment: map[string]interface{}{},
    }

  return linkMb, nil
}

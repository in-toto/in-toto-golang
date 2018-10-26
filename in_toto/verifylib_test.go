package intoto

import (
  "os"
  "fmt"
  "testing"
  "path/filepath"
  "io/ioutil"
  )

const testData = "../test/data"

// TestMain calls all Test*'s of this package (intoto) explicitly with m.Run
// This can be used for test setup and teardown, e.g. copy test data to a tmp
// test dir, change to that dir and remove the and contents in the end
func TestMain(m *testing.M) {
  testDir, err := ioutil.TempDir("", "in_toto_test_dir")
  if err != nil {
    panic("Cannot create temp test dir")
  }

  // Copy test files to temp test directory
  // NOTE: Only works for a flat directory of files
  testFiles, _ := filepath.Glob(filepath.Join(testData, "*"))
  for _, inputPath := range testFiles {
    input, err := ioutil.ReadFile(inputPath)
    if err != nil {
      panic(fmt.Sprintf("Cannot copy test files (read error: %s)", err))
    }
    outputPath := filepath.Join(testDir, filepath.Base(inputPath))
    err = ioutil.WriteFile(outputPath, input, 0644)
    if err != nil {
      panic(fmt.Sprintf("Cannot copy test files (write error: %s)", err))
    }
  }

  cwd, _:= os.Getwd()
  os.Chdir(testDir)

  // Always change back to where we were and remove the temp directory
  defer os.Chdir(cwd)
  defer os.RemoveAll(testDir)

  // Run tests
  os.Exit(m.Run())
}

func TestInTotoVerifyPass(t *testing.T) {
  layoutPath := "demo.layout.template"
  pubKeyPath := "alice.pub"
  linkDir := "."

  var pubKey Key
  if err := pubKey.LoadPublicKey(pubKeyPath); err != nil {
    t.Error(err)
  }

  var layouKeys = map[string]Key{
    pubKey.KeyId: pubKey,
  }

  // No error should occur
  if err := InTotoVerify(layoutPath, layouKeys, linkDir); err != nil {
    t.Error(err)
  }
}


func TestInTotoVerifyLayoutDoesNotExist(t *testing.T) {
  err := InTotoVerify("layout/does/not/exist", map[string]Key{},
      "link/dir/does/not/matter")
  // Asssert error type to PathError
  if _, ok := err.(*os.PathError); ok == false {
    t.Fail()
  }
}

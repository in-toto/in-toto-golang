package in_toto

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

const testData = "../test/data"

// TestMain calls all Test*'s of this package (in_toto) explicitly with m.Run
// This can be used for test setup and teardown, e.g. copy test data to a tmp
// test dir, change to that dir and remove the and contents in the end
func TestMain(m *testing.M) {
	testDir, err := os.MkdirTemp("", "in_toto_test_dir")
	if err != nil {
		panic("Cannot create temp test dir")
	}

	// Copy test files to temp test directory
	// NOTE: Only works for a flat directory of files
	testFiles, _ := filepath.Glob(filepath.Join(testData, "*"))
	for _, inputPath := range testFiles {
		input, err := os.ReadFile(inputPath)
		if err != nil {
			panic(fmt.Sprintf("Cannot copy test files (read error: %s)", err))
		}
		outputPath := filepath.Join(testDir, filepath.Base(inputPath))
		err = os.WriteFile(outputPath, input, 0644)
		if err != nil {
			panic(fmt.Sprintf("Cannot copy test files (write error: %s)", err))
		}
	}

	cwd, _ := os.Getwd()
	err = os.Chdir(testDir)
	if err != nil {
		fmt.Printf("Unable to change dir to %s: %s", testDir, err)
	}
	// Always change back to where we were and remove the temp directory
	defer func(cwd string) {
		if err := os.Chdir(cwd); err != nil {
			fmt.Printf("Unable to change to directory %s: %s", cwd, err)
		}
	}(cwd)
	defer func(testDir string) {
		if err := os.RemoveAll(testDir); err != nil {
			fmt.Printf("Unable to remove directory %s: %s", testDir, err)
		}
	}(testDir)

	// Run tests
	m.Run()
}

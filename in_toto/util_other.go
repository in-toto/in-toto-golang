//go:build !unix

package in_toto

import (
	"errors"
	"os"
)

// isWritable checks that path is a writable directory on the platforms
// that have no access(2) such as Windows or js/wasm: it reads the owner
// write bit of the file mode instead.
func isWritable(path string) error {
	// get fileInfo
	info, err := os.Stat(path)
	if err != nil {
		return err
	}

	// check if path is a directory
	if !info.IsDir() {
		return errors.New("not a directory")
	}

	// Check if the user bit is enabled in file permission
	if info.Mode().Perm()&(1<<(uint(7))) == 0 {
		return errors.New("not writable")
	}
	return nil
}

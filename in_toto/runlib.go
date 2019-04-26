package in_toto

import (
	"io/ioutil"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
)

/*
RecordArtifact reads and hashes the contents of the file at the passed path
using sha256 and returns a map in the following format:
  {
    "<path>": {
      "sha256": <hex representation of hash>
    }
  }
If reading the file fails, the first return value is nil and the second return
value is the error.
*/

func RecordArtifact(path string) (map[string]interface{}, error) {

	hashObjectMap := createMap()

	// Read file from passed path
	contents, err := ioutil.ReadFile(path)

	hashedContentsMap := make(map[string]interface{})

	if err != nil {
		return nil, err
	}

	// Create a map of all the hashes present in the hash_func list
	hash_func := []string{"sha256"}
	for _, element := range hash_func {

		result := hashObjectMap[element].Compute([]uint8(contents))

		hashedContentsMap[element] = result
	}

	// Return it in a format that is conformant with link metadata artifacts
	return hashedContentsMap, nil
}

/*
RecordArtifacts walks through the passed slice of paths, traversing
subdirectories, and calls RecordArtifact for each file.  It returns a map in
the following format:
  {
    "<path>": {
      "sha256": <hex representation of hash>
    },
    "<path>": {
      "sha256": <hex representation of hash>
    },
    ...
  }
If recording an artifact fails the first return value is nil and the second
return value is the error.
*/

/*CAUTION:- We are handling infinite recursion with the help of rdept variable.
The function would walk through the directory untill it has reached it's
depth limit of 10.
*/
func RecordArtifacts(paths []string, rdepth int) (map[string]interface{}, error) {
	artifacts := make(map[string]interface{})
	// NOTE: Walk cannot follow symlinks
	for _, path := range paths {
		err := filepath.Walk(path,
			func(path string, info os.FileInfo, err error) error {
				// Abort if Walk function has a problem, e.g. path does not exist)
				if err != nil {
					return err
				}
				// Don't hash directories
				if info.IsDir() {
					return nil
				}
				//Code to verify for symlinks
				// rdepth is added to keep the recursion in control.
				if rdepth < 10{
					if info.Mode() & os.ModeSymlink != 0{
						sym_path, sym_err := os.Readlink(path)
						if sym_err != nil {
							return sym_err
						}
						recursed_artifacts, recursed_err := RecordArtifacts([]string{sym_path}, rdepth + 1)
						if recursed_err != nil {
							return recursed_err
						}
						for key, value := range recursed_artifacts{
							artifacts[key] = value
						}
						return nil
					}
				}
				artifact, err := RecordArtifact(path)

				// Abort if artifact can't be recorded, e.g. due to file permissions
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

/*
WaitErrToExitCode converts an error returned by Cmd.wait() to an exit code.  It
returns -1 if no exit code can be inferred.
*/
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

/*
RunCommand executes the passed command in a subprocess.  The first element of
cmdArgs is used as executable and the rest as command arguments.  It captures
and returns stdout, stderr and exit code.  The format of the returned map is:
  {
    "return-value": <exit code>,
    "stdout": "<standard output>",
    "stderr": "<standard error>"
  }
If the command cannot be executed or no pipes for stdout or stderr can be
created the first return value is nil and the second return value is the error.
NOTE: Since stdout and stderr are captured, they cannot be seen during the
command execution.
*/
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
		"stdout":       stdout,
		"stderr":       stderr,
	}, nil
}

/*
InTotoRun executes commands, e.g. for software supply chain steps or
inspections of an in-toto layout, and creates and returns corresponding link
metadata.  Link metadata contains recorded products at the passed productPaths
and materials at the passed materialPaths.  The returned link is wrapped in a
Metablock object.  If command execution or artifact recording fails the first
return value is an empty Metablock and the second return value is the error.
NOTE: Currently InTotoRun cannot be used to sign Link metadata.
*/
func InTotoRun(name string, materialPaths []string, productPaths []string,
	cmdArgs []string) (Metablock, error) {
	var linkMb Metablock
	materials, err := RecordArtifacts(materialPaths, 0)
	if err != nil {
		return linkMb, err
	}

	byProducts, err := RunCommand(cmdArgs)
	if err != nil {
		return linkMb, err
	}

	products, err := RecordArtifacts(productPaths, 0)
	if err != nil {
		return linkMb, err
	}

	linkMb.Signatures = []Signature{}
	linkMb.Signed = Link{
		Type:        "link",
		Name:        name,
		Materials:   materials,
		Products:    products,
		ByProducts:  byProducts,
		Command:     cmdArgs,
		Environment: map[string]interface{}{},
	}

	return linkMb, nil
}

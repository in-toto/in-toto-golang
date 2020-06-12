package in_toto

import (
	"errors"
	"io/ioutil"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestRecordArtifact(t *testing.T) {
	// Test successfully record one artifact
	result, err := RecordArtifact("foo.tar.gz")
	expected := map[string]interface{}{
		"sha256": "52947cb78b91ad01fe81cd6aef42d1f6817e92b9e6936c1e5aabb7c98514f355",
	}
	if !reflect.DeepEqual(result, expected) || err != nil {
		t.Errorf("RecordArtifact returned '(%s, %s)', expected '(%s, nil)'",
			result, err, expected)
	}

	// Test error by recording nonexistent artifact
	result, err = RecordArtifact("file-does-not-exist")
	if !os.IsNotExist(err) {
		t.Errorf("RecordArtifact returned '(%s, %s)', expected '(nil, %s)'",
			result, err, os.ErrNotExist)
	}
}

// TestSymlinkToFile checks if we can follow symlinks to a file
// Note: Symlink files are invisible for InToto right now.
// Therefore if we have a symlink like: foo.tar.gz.sym -> foo.tar.gz
// We will only calculate the hash for for.tar.gz
// The symlink will not be added to the list right now, nor will we calculate a checksum for it.
func TestSymlinkToFile(t *testing.T) {
	if err := os.Symlink("foo.tar.gz", "foo.tar.gz.sym"); err != nil {
		t.Errorf("Could not create a symlink: %s", err)
	}

	expected := map[string]interface{}{
		"foo.tar.gz": map[string]interface{}{
			"sha256": "52947cb78b91ad01fe81cd6aef42d1f6817e92b9e6936c1e5aabb7c98514f355",
		},
	}
	result, err := RecordArtifacts([]string{"foo.tar.gz.sym"}, 0)
	if !reflect.DeepEqual(result, expected) {
		t.Errorf("RecordArtifacts returned '(%s, %s)', expected '(%s, nil)'",
			result, err, expected)
	}

	if err := os.Remove("foo.tar.gz.sym"); err != nil {
		t.Errorf("Could not remove foo.tar.gz.sym: %s", err)
	}
}

// TestIndirectSymlinkCycles() tests for indirect symlink cycles in the form:
// symTestA/linkToB -> symTestB and symTestB/linkToA -> symTestA
func TestIndirectSymlinkCycles(t *testing.T) {
	if err := os.Mkdir("symTestA", 0700); err != nil {
		t.Errorf("Could not create tmpdir: %s", err)
	}
	if err := os.Mkdir("symTestB", 0700); err != nil {
		t.Errorf("Could not create tmpdir: %s", err)
	}

	// we need to get the current working directory here, otherwise
	// os.Symlink() will create a wrong symlink
	dir, err := os.Getwd()
	if err != nil {
		t.Error(err)
	}

	linkB := filepath.FromSlash("symTestA/linkToB.sym")
	linkA := filepath.FromSlash("symTestB/linkToA.sym")

	if err := os.Symlink(dir+"/symTestA", linkA); err != nil {
		t.Errorf("Could not create a symlink: %s", err)
	}
	if err := os.Symlink(dir+"/symTestB", linkB); err != nil {
		t.Errorf("Could not create a symlink: %s", err)
	}

	// provoke "symlink cycle detected" error
	_, err = RecordArtifacts([]string{"symTestA/linkToB.sym", "symTestB/linkToA.sym", "foo.tar.gz"}, 0)
	if !errors.Is(err, ErrSymCycle) {
		t.Errorf("We expected: %s, we got: %s", ErrSymCycle, err)
	}

	// make sure to clean up everything
	if err := os.Remove("symTestA/linkToB.sym"); err != nil {
		t.Errorf("Could not remove path: %s", err)
	}

	if err := os.Remove("symTestB/linkToA.sym"); err != nil {
		t.Errorf("Could not remove path: %s", err)
	}

	if err := os.Remove("symTestA"); err != nil {
		t.Errorf("Could not remove path: %s", err)
	}

	if err := os.Remove("symTestB"); err != nil {
		t.Errorf("Could not remove path: %s", err)
	}

}

// TestSymlinkToFolder checks if we are successfully following symlinks to folders
func TestSymlinkToFolder(t *testing.T) {
	if err := os.MkdirAll("symTest/symTest2", 0700); err != nil {
		t.Errorf("Could not create tmpdir: %s", err)
	}

	if err := os.Symlink("symTest/symTest2", "symTmpfile.sym"); err != nil {
		t.Errorf("Could not create a symlink: %s", err)
	}

	// create a filepath from slash, because otherwise
	// our tests are going to fail, because the path matching will
	// not work correctly on Windows
	p := filepath.FromSlash("symTest/symTest2/symTmpfile")

	if err := ioutil.WriteFile(p, []byte("abc"), 0400); err != nil {
		t.Errorf("Could not write symTmpfile: %s", err)
	}

	result, err := RecordArtifacts([]string{"symTmpfile.sym"}, 0)
	if err != nil {
		t.Error(err)
	}

	expected := map[string]interface{}{
		p: map[string]interface{}{
			"sha256": "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
		},
	}

	if !reflect.DeepEqual(result, expected) {
		t.Errorf("RecordArtifacts returned '(%s, %s)', expected '(%s, nil)'",
			result, err, expected)
	}

	// make sure to clean up everything
	if err := os.Remove("symTest/symTest2/symTmpfile"); err != nil {
		t.Errorf("Could not remove path symTest/symTest2/symTmpfile: %s", err)
	}

	if err := os.Remove("symTmpfile.sym"); err != nil {
		t.Errorf("Could not remove path symTest/symTest2/symTmpfile.sym: %s", err)
	}

	if err := os.Remove("symTest/symTest2"); err != nil {
		t.Errorf("Could not remove path symTest/symTest2: %s", err)
	}

	if err := os.Remove("symTest/"); err != nil {
		t.Errorf("Could not remove path symTest: %s", err)
	}
}

// This test provokes a symlink cycle
func TestSymlinkCycle(t *testing.T) {
	if err := os.Mkdir("symlinkCycle/", 0700); err != nil {
		t.Errorf("Could not create tmpdir: %s", err)
	}

	// we need to get the current working directory here, otherwise
	// os.Symlink() will create a wrong symlink
	dir, err := os.Getwd()
	if err != nil {
		t.Error(err)
	}
	// create a cycle ./symlinkCycle/symCycle.sym -> ./symlinkCycle/
	if err := os.Symlink(dir+"/symlinkCycle", "symlinkCycle/symCycle.sym"); err != nil {
		t.Errorf("Could not create a symlink: %s", err)
	}

	// provoke "symlink cycle detected" error
	_, err = RecordArtifacts([]string{"symlinkCycle/symCycle.sym", "foo.tar.gz"}, 0)
	if !errors.Is(err, ErrSymCycle) {
		t.Errorf("We expected: %s, we got: %s", ErrSymCycle, err)
	}

	if err := os.Remove("symlinkCycle/symCycle.sym"); err != nil {
		t.Errorf("Could not remove path symlinkCycle/symCycle.sym: %s", err)
	}

	if err := os.Remove("symlinkCycle"); err != nil {
		t.Errorf("Could not remove path symlinkCycle: %s", err)
	}
}

func TestRecordArtifacts(t *testing.T) {
	// Test successfully record multiple artifacts including temporary subdir
	if err := os.Mkdir("tmpdir", 0700); err != nil {
		t.Errorf("Could not create tmpdir: %s", err)
	}
	if err := ioutil.WriteFile("tmpdir/tmpfile", []byte("abc"), 0400); err != nil {
		t.Errorf("Could not write tmpfile: %s", err)
	}
	result, err := RecordArtifacts([]string{"foo.tar.gz",
		"demo.layout.template", "tmpdir/tmpfile"}, 0)
	expected := map[string]interface{}{
		"foo.tar.gz": map[string]interface{}{
			"sha256": "52947cb78b91ad01fe81cd6aef42d1f6817e92b9e6936c1e5aabb7c98514f355",
		},
		"demo.layout.template": map[string]interface{}{
			"sha256": "019e121a1e0a34aecde0aebb642162b11db4248c781cb8119f81f592723a0424",
		},
		"tmpdir/tmpfile": map[string]interface{}{
			"sha256": "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
		},
	}
	if !reflect.DeepEqual(result, expected) {
		t.Errorf("RecordArtifacts returned '(%s, %s)', expected '(%s, nil)'",
			result, err, expected)
	}
	if err := os.RemoveAll("tmpdir"); err != nil {
		t.Errorf("Could not remove tmpdir: %s", err)
	}

	// Test error by recording nonexistent artifact
	result, err = RecordArtifacts([]string{"file-does-not-exist"}, 0)
	if !os.IsNotExist(err) {
		t.Errorf("RecordArtifacts returned '(%s, %s)', expected '(nil, %s)'",
			result, err, os.ErrNotExist)
	}
}

func TestWaitErrToExitCode(t *testing.T) {
	// TODO: Find way to test/mock ExitError
	// Test exit code from error assessment
	parameters := []error{
		nil,
		errors.New(""),
		// &exec.ExitError{ProcessState: &os.ProcessState},
	}
	expected := []int{
		0,
		-1,
		// -1,
	}

	for i := 0; i < len(parameters); i++ {
		result := WaitErrToExitCode(parameters[i])
		if result != expected[i] {
			t.Errorf("WaitErrToExitCode returned %d, expected %d",
				result, expected[i])
		}
	}
}

func TestRunCommand(t *testing.T) {
	// Successfully run command and return metadata
	parameters := [][]string{
		{"sh", "-c", "true"},
		{"sh", "-c", "false"},
		{"sh", "-c", "printf out"},
		{"sh", "-c", "printf err >&2"},
	}
	expected := []map[string]interface{}{
		{"return-value": 0, "stdout": []byte(""), "stderr": []byte("")},
		{"return-value": 1, "stdout": []byte(""), "stderr": []byte("")},
		{"return-value": 0, "stdout": []byte("out"), "stderr": []byte("")},
		{"return-value": 0, "stdout": []byte(""), "stderr": []byte("err")},
	}
	for i := 0; i < len(parameters); i++ {
		result, err := RunCommand(parameters[i])
		if !reflect.DeepEqual(result, expected[i]) || err != nil {
			t.Errorf("RunCommand returned '(%s, %s)', expected '(%s, nil)'",
				result, err, expected[i])
		}
	}

	// Fail run command
	result, err := RunCommand([]string{"command-does-not-exist"})
	if result != nil || err == nil {
		t.Errorf("RunCommand returned '(%s, %s)', expected '(nil, *exec.Error)'",
			result, err)
	}
}

func TestInTotoRun(t *testing.T) {
	// Successfully run InTotoRun
	linkName := "Name"
	parameters := []map[string][]string{
		{
			"materialPaths": {"demo.layout.template"},
			"productPaths":  {"foo.tar.gz"},
			"cmdArgs":       {"sh", "-c", "printf out; printf err >&2"},
		},
	}
	expected := []Metablock{
		{
			Signatures: []Signature{},
			Signed: Link{
				Name: linkName,
				Type: "link",
				Materials: map[string]interface{}{
					"demo.layout.template": map[string]interface{}{
						"sha256": "019e121a1e0a34aecde0aebb642162b11db4248c781cb8119f81f592723a0424",
					},
				},
				Products: map[string]interface{}{
					"foo.tar.gz": map[string]interface{}{
						"sha256": "52947cb78b91ad01fe81cd6aef42d1f6817e92b9e6936c1e5aabb7c98514f355",
					},
				},
				ByProducts: map[string]interface{}{
					"return-value": 0, "stdout": []byte("out"), "stderr": []byte("err"),
				},
				Command:     []string{"sh", "-c", "printf out; printf err >&2"},
				Environment: map[string]interface{}{},
			},
		},
	}
	for i := 0; i < len(parameters); i++ {
		result, err := InTotoRun(linkName, parameters[i]["materialPaths"],
			parameters[i]["productPaths"], parameters[i]["cmdArgs"])
		if !reflect.DeepEqual(result, expected[i]) {
			t.Errorf("InTotoRun returned '(%s, %s)', expected '(%s, nil)'",
				result, err, expected[i])
		}
	}

	// Test in-toto run errors:
	// - error due to nonexistent material path
	// - error due to nonexistent product path
	// - error due to nonexistent run command
	parameters = []map[string][]string{
		{
			"materialPaths": {"material-does-not-exist"},
			"productPaths":  {""},
			"cmdArgs":       {"sh", "-c", "printf test"},
		},
		{
			"materialPaths": {},
			"productPaths":  {"product-does-not-exist"},
			"cmdArgs":       {"sh", "-c", "printf test"},
		},
		{
			"materialPaths": {},
			"productPaths":  {},
			"cmdArgs":       {"command-does-not-exist"},
		},
	}

	for i := 0; i < len(parameters); i++ {
		result, err := InTotoRun(linkName, parameters[i]["materialPaths"],
			parameters[i]["productPaths"], parameters[i]["cmdArgs"])
		if err == nil {
			t.Errorf("InTotoRun returned '(%s, %s)', expected '(%s, <error>)'",
				result, err, expected[i])
		}
	}
}

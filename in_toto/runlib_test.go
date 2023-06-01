package in_toto

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"sort"
	"testing"

	"github.com/secure-systems-lab/go-securesystemslib/dsse"
	"github.com/stretchr/testify/assert"
)

// Helper function checking whether running environment is Windows
func testOSisWindows() bool {
	os := runtime.GOOS
	return os == "windows"
}

func TestRecordArtifact(t *testing.T) {
	// Test successfully record one artifact
	result, err := RecordArtifact("foo.tar.gz", []string{"sha256"}, testOSisWindows())
	expected := map[string]interface{}{
		"sha256": "52947cb78b91ad01fe81cd6aef42d1f6817e92b9e6936c1e5aabb7c98514f355",
	}
	if !reflect.DeepEqual(result, expected) || err != nil {
		t.Errorf("RecordArtifact returned '(%s, %s)', expected '(%s, nil)'",
			result, err, expected)
	}

	// Test error by recording nonexistent artifact
	result, err = RecordArtifact("file-does-not-exist", []string{"sha256"}, testOSisWindows())
	if !os.IsNotExist(err) {
		t.Errorf("RecordArtifact returned '(%s, %s)', expected '(nil, %s)'",
			result, err, os.ErrNotExist)
	}

	result, err = RecordArtifact("foo.tar.gz", []string{"invalid"}, testOSisWindows())
	if !errors.Is(err, ErrUnsupportedHashAlgorithm) {
		t.Errorf("RecordArtifact returned '(%s, %s)', expected '(nil, %s)'", result, err, ErrUnsupportedHashAlgorithm)
	}
}

// copy helper function for building more complex test cases
// for our TestGitPathSpec
func copy(src, dst string) (int64, error) {
	sourceFileStat, err := os.Stat(src)
	if err != nil {
		return 0, err
	}

	if !sourceFileStat.Mode().IsRegular() {
		return 0, fmt.Errorf("%s is not a regular file", src)
	}

	source, err := os.Open(src)
	if err != nil {
		return 0, err
	}
	defer source.Close()

	destination, err := os.Create(dst)
	if err != nil {
		return 0, err
	}
	defer destination.Close()
	nBytes, err := io.Copy(destination, source)
	return nBytes, err
}

func TestGitPathSpec(t *testing.T) {
	// Create a more complex test scenario via building subdirectories
	// and copying existing files.
	directoriesToBeCreated := []string{
		"pathSpecTest",
		"pathSpecTest/alpha",
		"pathSpecTest/beta",
		"pathSpecTest/alpha/charlie",
	}
	for _, v := range directoriesToBeCreated {
		if err := os.Mkdir(v, 0700); err != nil {
			t.Errorf("could not create tmpdir: %s", err)
		}
	}
	filesToBeCreated := map[string]string{
		"heidi.pub":  "pathSpecTest/heidi.pub",
		"foo.tar.gz": "pathSpecTest/beta/foo.tar.gz",
		"dan":        "pathSpecTest/alpha/charlie/dan",
		"dan.pub":    "pathSpecTest/beta/dan.pub",
	}
	for k, v := range filesToBeCreated {
		_, err := copy(k, v)
		if err != nil {
			t.Errorf("could not copy file: %s", err)
		}
	}

	expected := map[string]interface{}{}
	// Let's start our test in the test/data directory
	result, err := RecordArtifacts([]string{"pathSpecTest"}, []string{"sha256"}, []string{
		"*.pub",           // Match all .pub files (even the ones in subdirectories)
		"beta/foo.tar.gz", // Match full path
		"alpha/**",        // Match all directories and files beneath alpha
	}, nil, testOSisWindows(), false)
	if !reflect.DeepEqual(result, expected) {
		t.Errorf("RecordArtifacts returned '(%s, %s)', expected '(%s, nil)'",
			result, err, expected)
	}

	// clean up
	err = os.RemoveAll("pathSpecTest")
	if err != nil {
		t.Errorf("could not clean up pathSpecTest directory: %s", err)
	}
}

// TestSymlinkToFile checks if we can follow symlinks to a file
// Note: Symlink files are invisible for InToto right now.
// Therefore if we have a symlink like: foo.tar.gz.sym -> foo.tar.gz
// We will only calculate the hash for for.tar.gz
// The symlink will not be added to the list right now, nor will we calculate a checksum for it.
func TestSymlinkToFile(t *testing.T) {
	if err := os.Symlink("foo.tar.gz", "foo.tar.gz.sym"); err != nil {
		t.Errorf("could not create a symlink: %s", err)
	}

	expected := map[string]interface{}{
		"foo.tar.gz.sym": map[string]interface{}{
			"sha256": "52947cb78b91ad01fe81cd6aef42d1f6817e92b9e6936c1e5aabb7c98514f355",
		},
	}
	result, err := RecordArtifacts([]string{"foo.tar.gz.sym"}, []string{"sha256"}, nil, nil, testOSisWindows(), false)
	if !reflect.DeepEqual(result, expected) {
		t.Errorf("RecordArtifacts returned '(%s, %s)', expected '(%s, nil)'",
			result, err, expected)
	}

	if err := os.Remove("foo.tar.gz.sym"); err != nil {
		t.Errorf("could not remove foo.tar.gz.sym: %s", err)
	}
}

// TestIndirectSymlinkCycles() tests for indirect symlink cycles in the form:
// symTestA/linkToB -> symTestB and symTestB/linkToA -> symTestA
func TestIndirectSymlinkCycles(t *testing.T) {
	if err := os.Mkdir("symTestA", 0700); err != nil {
		t.Errorf("could not create tmpdir: %s", err)
	}
	if err := os.Mkdir("symTestB", 0700); err != nil {
		t.Errorf("could not create tmpdir: %s", err)
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
		t.Errorf("could not create a symlink: %s", err)
	}
	if err := os.Symlink(dir+"/symTestB", linkB); err != nil {
		t.Errorf("could not create a symlink: %s", err)
	}

	// provoke "symlink cycle detected" error
	_, err = RecordArtifacts([]string{"symTestA/linkToB.sym", "symTestB/linkToA.sym", "foo.tar.gz"}, []string{"sha256"}, nil, nil, testOSisWindows(), true)
	if !errors.Is(err, ErrSymCycle) {
		t.Errorf("we expected: %s, we got: %s", ErrSymCycle, err)
	}

	// make sure to clean up everything
	if err := os.Remove("symTestA/linkToB.sym"); err != nil {
		t.Errorf("could not remove path: %s", err)
	}

	if err := os.Remove("symTestB/linkToA.sym"); err != nil {
		t.Errorf("could not remove path: %s", err)
	}

	if err := os.Remove("symTestA"); err != nil {
		t.Errorf("could not remove path: %s", err)
	}

	if err := os.Remove("symTestB"); err != nil {
		t.Errorf("could not remove path: %s", err)
	}

}

// TestSymlinkToFolder checks if we are successfully following symlinks to folders
func TestSymlinkToFolder(t *testing.T) {
	if err := os.MkdirAll("symTest/symTest2", 0700); err != nil {
		t.Errorf("could not create tmpdir: %s", err)
	}

	if err := os.Symlink("symTest/symTest2", "symTmpfile.sym"); err != nil {
		t.Errorf("could not create a symlink: %s", err)
	}

	// create a filepath from slash, because otherwise
	// our tests are going to fail, because the path matching will
	// not work correctly on Windows
	p := filepath.FromSlash("symTest/symTest2/symTmpfile")

	if err := os.WriteFile(p, []byte("abc"), 0400); err != nil {
		t.Errorf("could not write symTmpfile: %s", err)
	}

	result, err := RecordArtifacts([]string{"symTmpfile.sym"}, []string{"sha256"}, nil, nil, testOSisWindows(), true)
	if err != nil {
		t.Error(err)
	}

	expected := map[string]interface{}{
		filepath.Join("symTmpfile.sym", "symTmpfile"): map[string]interface{}{
			"sha256": "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
		},
	}

	if !reflect.DeepEqual(result, expected) {
		t.Errorf("RecordArtifacts returned '(%s, %s)', expected '(%s, nil)'",
			result, err, expected)
	}

	// make sure to clean up everything
	if err := os.Remove("symTest/symTest2/symTmpfile"); err != nil {
		t.Errorf("could not remove path symTest/symTest2/symTmpfile: %s", err)
	}

	if err := os.Remove("symTmpfile.sym"); err != nil {
		t.Errorf("could not remove path symTest/symTest2/symTmpfile.sym: %s", err)
	}

	if err := os.Remove("symTest/symTest2"); err != nil {
		t.Errorf("could not remove path symTest/symTest2: %s", err)
	}

	if err := os.Remove("symTest/"); err != nil {
		t.Errorf("could not remove path symTest: %s", err)
	}
}

// This test provokes a symlink cycle
func TestSymlinkCycle(t *testing.T) {
	if err := os.Mkdir("symlinkCycle/", 0700); err != nil {
		t.Errorf("could not create tmpdir: %s", err)
	}

	// we need to get the current working directory here, otherwise
	// os.Symlink() will create a wrong symlink
	dir, err := os.Getwd()
	if err != nil {
		t.Error(err)
	}
	// create a cycle ./symlinkCycle/symCycle.sym -> ./symlinkCycle/
	if err := os.Symlink(dir+"/symlinkCycle", "symlinkCycle/symCycle.sym"); err != nil {
		t.Errorf("could not create a symlink: %s", err)
	}

	// provoke "symlink cycle detected" error
	_, err = RecordArtifacts([]string{"symlinkCycle/symCycle.sym", "foo.tar.gz"}, []string{"sha256"}, nil, nil, testOSisWindows(), true)
	if !errors.Is(err, ErrSymCycle) {
		t.Errorf("we expected: %s, we got: %s", ErrSymCycle, err)
	}

	if err := os.Remove("symlinkCycle/symCycle.sym"); err != nil {
		t.Errorf("could not remove path symlinkCycle/symCycle.sym: %s", err)
	}

	if err := os.Remove("symlinkCycle"); err != nil {
		t.Errorf("could not remove path symlinkCycle: %s", err)
	}
}

func TestRecordArtifacts(t *testing.T) {
	// Test successfully record multiple artifacts including temporary subdir
	if err := os.Mkdir("tmpdir", 0700); err != nil {
		t.Errorf("could not create tmpdir: %s", err)
	}
	if err := os.WriteFile("tmpdir/tmpfile", []byte("abc"), 0400); err != nil {
		t.Errorf("could not write tmpfile: %s", err)
	}
	result, err := RecordArtifacts([]string{"foo.tar.gz",
		"tmpdir/tmpfile"}, []string{"sha256"}, nil, []string{"tmpdir/"}, testOSisWindows(), false)
	expected := map[string]interface{}{
		"foo.tar.gz": map[string]interface{}{
			"sha256": "52947cb78b91ad01fe81cd6aef42d1f6817e92b9e6936c1e5aabb7c98514f355",
		},
		"tmpfile": map[string]interface{}{
			"sha256": "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
		},
	}
	if !reflect.DeepEqual(result, expected) {
		t.Errorf("RecordArtifacts returned '(%s, %s)', expected '(%s, nil)'",
			result, err, expected)
	}
	// Test duplicated artifact after left strip
	if err := os.WriteFile("tmpdir/foo.tar.gz", []byte("abc"), 0400); err != nil {
		t.Errorf("could not write tmpfile: %s", err)
	}
	_, err = RecordArtifacts([]string{"foo.tar.gz",
		"tmpdir/foo.tar.gz"}, []string{"sha256"}, nil, []string{"tmpdir/"}, testOSisWindows(), false)
	if err == nil {
		t.Error("duplicated path error expected")
	}

	if err := os.RemoveAll("tmpdir"); err != nil {
		t.Errorf("could not remove tmpdir: %s", err)
	}

	// Test error by recording nonexistent artifact
	result, err = RecordArtifacts([]string{"file-does-not-exist"}, []string{"sha256"}, nil, nil, testOSisWindows(), false)
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
		result := waitErrToExitCode(parameters[i])
		if result != expected[i] {
			t.Errorf("waitErrToExitCode returned %d, expected %d",
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
		{"return-value": float64(0), "stdout": "", "stderr": ""},
		{"return-value": float64(1), "stdout": "", "stderr": ""},
		{"return-value": float64(0), "stdout": "out", "stderr": ""},
		{"return-value": float64(0), "stdout": "", "stderr": "err"},
	}
	for i := 0; i < len(parameters); i++ {
		result, err := RunCommand(parameters[i], "")
		if !reflect.DeepEqual(result, expected[i]) || err != nil {
			t.Errorf("RunCommand returned '(%s, %s)', expected '(%s, nil)'",
				result, err, expected[i])
		}
	}

	// Fail run command
	result, err := RunCommand([]string{"command-does-not-exist"}, "")
	if result != nil || err == nil {
		t.Errorf("RunCommand returned '(%s, %s)', expected '(nil, *exec.Error)'",
			result, err)
	}
}

func TestRunCommandErrors(t *testing.T) {
	tables := []struct {
		CmdArgs       []string
		RunDir        string
		ExpectedError error
	}{
		{nil, "", ErrEmptyCommandArgs},
		{[]string{}, "", ErrEmptyCommandArgs},
	}
	for _, table := range tables {
		_, err := RunCommand(table.CmdArgs, table.RunDir)
		if !errors.Is(err, ErrEmptyCommandArgs) {
			t.Errorf("RunCommand did not provoke expected error. Got: %s, want: %s", err, ErrEmptyCommandArgs)
		}
	}
}

func TestInTotoRun(t *testing.T) {
	// Successfully run InTotoRun
	linkName := "Name"

	var validKey Key
	if err := validKey.LoadKey("carol", "ed25519", []string{"sha256", "sha512"}); err != nil {
		t.Error(err)
	}

	tablesCorrect := []struct {
		materialPaths  []string
		productPaths   []string
		cmdArgs        []string
		key            Key
		hashAlgorithms []string
		useDSSE        bool
		result         Metadata
	}{
		{[]string{"alice.pub"}, []string{"foo.tar.gz"}, []string{"sh", "-c", "printf out; printf err >&2"}, validKey, []string{"sha256"}, false, &Metablock{
			Signed: Link{
				Name: linkName,
				Type: "link",
				Materials: map[string]interface{}{
					"alice.pub": map[string]interface{}{
						"sha256": "f051e8b561835b7b2aa7791db7bc72f2613411b0b7d428a0ac33d45b8c518039",
					},
				},
				Products: map[string]interface{}{
					"foo.tar.gz": map[string]interface{}{
						"sha256": "52947cb78b91ad01fe81cd6aef42d1f6817e92b9e6936c1e5aabb7c98514f355",
					},
				},
				ByProducts: map[string]interface{}{
					"return-value": float64(0), "stdout": "out", "stderr": "err",
				},
				Command:     []string{"sh", "-c", "printf out; printf err >&2"},
				Environment: map[string]interface{}{},
			},
			Signatures: []Signature{{
				KeyID: "be6371bc627318218191ce0780fd3183cce6c36da02938a477d2e4dfae1804a6",
				Sig:   "71dfec1af747d02f6463d4baf3bb2c1d903c107470be86c12349433f780b1030e5ca36a10ee5c5d74de16344fe16b459154fd2be05a58fb556dff934d6682403",
			}},
		},
		},
		{[]string{"alice.pub"}, []string{"foo.tar.gz"}, []string{}, validKey, []string{"sha256"}, false, &Metablock{
			Signed: Link{
				Name: linkName,
				Type: "link",
				Materials: map[string]interface{}{
					"alice.pub": map[string]interface{}{
						"sha256": "f051e8b561835b7b2aa7791db7bc72f2613411b0b7d428a0ac33d45b8c518039",
					},
				},
				Products: map[string]interface{}{
					"foo.tar.gz": map[string]interface{}{
						"sha256": "52947cb78b91ad01fe81cd6aef42d1f6817e92b9e6936c1e5aabb7c98514f355",
					},
				},
				ByProducts:  map[string]interface{}{},
				Command:     []string{},
				Environment: map[string]interface{}{},
			},
			Signatures: []Signature{{
				KeyID: "be6371bc627318218191ce0780fd3183cce6c36da02938a477d2e4dfae1804a6",
				Sig:   "f4a2d468965d595b4d29615fb2083ef7ac22a948e1530925612d73ba580ce9765d93db7b7ed1b9755d96f13a6a1e858c64693c2f7adcb311afb28cb57fbadc0c",
			}},
		},
		},
		{[]string{"alice.pub"}, []string{"foo.tar.gz"}, []string{}, validKey, []string{"sha256"}, true, &Envelope{
			envelope: &dsse.Envelope{
				Payload:     "eyJfdHlwZSI6ImxpbmsiLCJieXByb2R1Y3RzIjp7fSwiY29tbWFuZCI6W10sImVudmlyb25tZW50Ijp7fSwibWF0ZXJpYWxzIjp7ImFsaWNlLnB1YiI6eyJzaGEyNTYiOiJmMDUxZThiNTYxODM1YjdiMmFhNzc5MWRiN2JjNzJmMjYxMzQxMWIwYjdkNDI4YTBhYzMzZDQ1YjhjNTE4MDM5In19LCJuYW1lIjoiTmFtZSIsInByb2R1Y3RzIjp7ImZvby50YXIuZ3oiOnsic2hhMjU2IjoiNTI5NDdjYjc4YjkxYWQwMWZlODFjZDZhZWY0MmQxZjY4MTdlOTJiOWU2OTM2YzFlNWFhYmI3Yzk4NTE0ZjM1NSJ9fX0=",
				PayloadType: PayloadType,
				Signatures: []dsse.Signature{{
					KeyID: "be6371bc627318218191ce0780fd3183cce6c36da02938a477d2e4dfae1804a6",
					Sig:   "XgNp1Q5N/ivFxNyuUNHcjOarMIj3WXZpb00/ZVy2pxdiAeOZYKpJkXPa7wRAM5auuwrVph9TrwoJQuDpJrZaCw==",
				}},
			},
		}},
	}

	for _, table := range tablesCorrect {
		result, err := InTotoRun(linkName, "", table.materialPaths, table.productPaths, table.cmdArgs, table.key, table.hashAlgorithms, nil, nil, testOSisWindows(), false, table.useDSSE)
		if table.useDSSE {
			assert.Equal(t, table.result.(*Envelope).envelope, result.(*Envelope).envelope, fmt.Sprintf("InTotoRun returned '(%s, %s)', expected '(%s, nil)'", result, err, table.result))
		} else {
			assert.True(t, reflect.DeepEqual(result.(*Metablock), table.result.(*Metablock)), fmt.Sprintf("InTotoRun returned '(%s, %s)', expected '(%s, nil)'", result, err, table.result))
		}

		if result != nil {
			if err := result.Dump(linkName + ".link"); err != nil {
				t.Errorf("error while dumping link metablock to file")
			}
			loadedResult, err := LoadMetadata(linkName + ".link")
			if err != nil {
				t.Errorf("error while loading link metablock from file")
			}
			if table.useDSSE {
				assert.Equal(t, result.(*Envelope).envelope, loadedResult.(*Envelope).envelope, fmt.Sprintf("dump and loading of signed Link failed. Loaded result: '%s', dumped result '%s'", loadedResult, result))
			} else {
				assert.True(t, reflect.DeepEqual(loadedResult, result), fmt.Sprintf("dump and loading of signed Link failed. Loaded result: '%s', dumped result '%s'", loadedResult, result))
			}

			if err := os.Remove(linkName + ".link"); err != nil {
				t.Errorf("removing created link file failed")
			}
		}
	}

	// Run InToToRun with errors
	tablesInvalid := []struct {
		materialPaths  []string
		productPaths   []string
		cmdArgs        []string
		key            Key
		hashAlgorithms []string
	}{
		{[]string{"material-does-not-exist"}, []string{""}, []string{"sh", "-c", "printf test"}, Key{}, []string{"sha256"}},
		{[]string{"demo.layout"}, []string{"product-does-not-exist"}, []string{"sh", "-c", "printf test"}, Key{}, []string{"sha256"}},
		{[]string{""}, []string{"/invalid-path/"}, []string{"sh", "-c", "printf test"}, Key{}, []string{"sha256"}},
		{[]string{}, []string{}, []string{"command-does-not-exist"}, Key{}, []string{"sha256"}},
		{[]string{"demo.layout"}, []string{"foo.tar.gz"}, []string{"sh", "-c", "printf out; printf err >&2"}, Key{
			KeyID:               "this-is-invalid",
			KeyIDHashAlgorithms: nil,
			KeyType:             "",
			KeyVal:              KeyVal{},
			Scheme:              "",
		}, []string{"sha256"}},
	}

	for _, table := range tablesInvalid {
		result, err := InTotoRun(linkName, "", table.materialPaths, table.productPaths, table.cmdArgs, table.key, table.hashAlgorithms, nil, nil, testOSisWindows(), false, false)
		if err == nil {
			t.Errorf("InTotoRun returned '(%s, %s)', expected error",
				result, err)
		}
	}
}

func TestInTotoRecord(t *testing.T) {
	// Successfully run InTotoRecordStart
	linkName := "Name"

	var validKey Key
	if err := validKey.LoadKey("carol", "ed25519", []string{"sha256", "sha512"}); err != nil {
		t.Error(err)
	}

	tablesCorrect := []struct {
		materialPaths  []string
		productPaths   []string
		key            Key
		hashAlgorithms []string
		useDSSE        bool
		startResult    Metadata
		stopResult     Metadata
	}{
		{[]string{"alice.pub"}, []string{"foo.tar.gz"}, validKey, []string{"sha256"}, false, &Metablock{
			Signed: Link{
				Name: linkName,
				Type: "link",
				Materials: map[string]interface{}{
					"alice.pub": map[string]interface{}{
						"sha256": "f051e8b561835b7b2aa7791db7bc72f2613411b0b7d428a0ac33d45b8c518039",
					},
				},
				Products:    map[string]interface{}{},
				ByProducts:  map[string]interface{}{},
				Command:     []string{},
				Environment: map[string]interface{}{},
			},
			Signatures: []Signature{{
				KeyID: "be6371bc627318218191ce0780fd3183cce6c36da02938a477d2e4dfae1804a6",
				Sig:   "f02db2e08d065840f266df850eaef7cfb5364bbe1808708945eb45373f4757cfe70c86f7ad5e4d5f746d41489410e0407921b4480788cfae5a7d695e3aa62f06",
			}},
		}, &Metablock{
			Signed: Link{
				Name: linkName,
				Type: "link",
				Materials: map[string]interface{}{
					"alice.pub": map[string]interface{}{
						"sha256": "f051e8b561835b7b2aa7791db7bc72f2613411b0b7d428a0ac33d45b8c518039",
					},
				},
				Products: map[string]interface{}{
					"foo.tar.gz": map[string]interface{}{
						"sha256": "52947cb78b91ad01fe81cd6aef42d1f6817e92b9e6936c1e5aabb7c98514f355",
					},
				},
				ByProducts:  map[string]interface{}{},
				Command:     []string{},
				Environment: map[string]interface{}{},
			},
			Signatures: []Signature{{
				KeyID: "be6371bc627318218191ce0780fd3183cce6c36da02938a477d2e4dfae1804a6",
				Sig:   "f4a2d468965d595b4d29615fb2083ef7ac22a948e1530925612d73ba580ce9765d93db7b7ed1b9755d96f13a6a1e858c64693c2f7adcb311afb28cb57fbadc0c",
			}},
		},
		},
		{[]string{"alice.pub"}, []string{"foo.tar.gz"}, validKey, []string{"sha256"}, true, &Envelope{
			envelope: &dsse.Envelope{
				PayloadType: PayloadType,
				Payload:     "eyJfdHlwZSI6ImxpbmsiLCJieXByb2R1Y3RzIjp7fSwiY29tbWFuZCI6W10sImVudmlyb25tZW50Ijp7fSwibWF0ZXJpYWxzIjp7ImFsaWNlLnB1YiI6eyJzaGEyNTYiOiJmMDUxZThiNTYxODM1YjdiMmFhNzc5MWRiN2JjNzJmMjYxMzQxMWIwYjdkNDI4YTBhYzMzZDQ1YjhjNTE4MDM5In19LCJuYW1lIjoiTmFtZSIsInByb2R1Y3RzIjp7fX0=",
				Signatures: []dsse.Signature{{
					KeyID: "be6371bc627318218191ce0780fd3183cce6c36da02938a477d2e4dfae1804a6",
					Sig:   "1u46q3nVmmvqKz/exUviEBPyfRndXwxouG+Jk1GadqKvhyfZv8to//xLPQWC+zy4bPQTicOp1yIBHqFO0bNeBw==",
				}},
			},
		}, &Envelope{
			envelope: &dsse.Envelope{
				PayloadType: PayloadType,
				Payload:     "eyJfdHlwZSI6ImxpbmsiLCJieXByb2R1Y3RzIjp7fSwiY29tbWFuZCI6W10sImVudmlyb25tZW50Ijp7fSwibWF0ZXJpYWxzIjp7ImFsaWNlLnB1YiI6eyJzaGEyNTYiOiJmMDUxZThiNTYxODM1YjdiMmFhNzc5MWRiN2JjNzJmMjYxMzQxMWIwYjdkNDI4YTBhYzMzZDQ1YjhjNTE4MDM5In19LCJuYW1lIjoiTmFtZSIsInByb2R1Y3RzIjp7ImZvby50YXIuZ3oiOnsic2hhMjU2IjoiNTI5NDdjYjc4YjkxYWQwMWZlODFjZDZhZWY0MmQxZjY4MTdlOTJiOWU2OTM2YzFlNWFhYmI3Yzk4NTE0ZjM1NSJ9fX0=",
				Signatures: []dsse.Signature{{
					KeyID: "be6371bc627318218191ce0780fd3183cce6c36da02938a477d2e4dfae1804a6",
					Sig:   "XgNp1Q5N/ivFxNyuUNHcjOarMIj3WXZpb00/ZVy2pxdiAeOZYKpJkXPa7wRAM5auuwrVph9TrwoJQuDpJrZaCw==",
				}},
			},
		},
		},
	}

	for _, table := range tablesCorrect {
		result, err := InTotoRecordStart(linkName, table.materialPaths, table.key, table.hashAlgorithms, nil, nil, testOSisWindows(), false, table.useDSSE)
		assert.Nil(t, err, "unexpected error while running record start")
		if table.useDSSE {
			assert.Equal(t, table.startResult.(*Envelope).envelope, result.(*Envelope).envelope, "result from record start did not match expected result")
		} else {
			assert.Equal(t, table.startResult.(*Metablock), result.(*Metablock), "result from record start did not match expected result")
		}
		stopResult, err := InTotoRecordStop(result, table.productPaths, table.key, table.hashAlgorithms, nil, nil, testOSisWindows(), false, table.useDSSE)
		assert.Nil(t, err, "unexpected error while running record stop")
		if table.useDSSE {
			assert.Equal(t, table.stopResult.(*Envelope).envelope, stopResult.(*Envelope).envelope, "result from record stop did not match expected result")
		} else {
			assert.Equal(t, table.stopResult.(*Metablock), stopResult.(*Metablock), "result from record stop did not match expected result")
		}
	}
}

// TestRecordArtifactWithBlobs ensures that we calculate the same hash for blobs
func TestRecordArtifactWithBlobs(t *testing.T) {
	type args struct {
		path           string
		hashAlgorithms []string
	}
	tests := []struct {
		name    string
		args    args
		want    map[string]interface{}
		wantErr error
	}{
		{
			name: "test binary blob without line normalization segments",
			args: args{
				path:           "foo.tar.gz",
				hashAlgorithms: []string{"sha256", "sha384", "sha512"},
			},
			want: map[string]interface{}{"sha256": "52947cb78b91ad01fe81cd6aef42d1f6817e92b9e6936c1e5aabb7c98514f355",
				"sha384": "ce17464027a7d7c15b15032b404fc76fdbadfa1fa566d7f7747020df2542a293b3098873a98dbbda6e461f7767b8ff6c",
				"sha512": "bb040966a5a6aefb646909f636f7f99c9e16b684a1f0e83a87dc30c3ab4d9dec2f9b0091d8be74bbc78ba29cb0c2dd027c223579028cf9822b0bccc49d493a6d"},
			wantErr: nil,
		},
		{
			name: "test binary blob with windows-like line breaks as byte segments",
			args: args{
				path:           "helloworld",
				hashAlgorithms: []string{"sha256", "sha384", "sha512"},
			},
			want: map[string]interface{}{"sha256": "fd895747460401ca62d81f310538110734ff5401f8ef86c3ab27168598225db8",
				"sha384": "ddc3ac40ca8d04929e13c42d555a5a6774d35bfac9e2f4cde5847ab3f12f36831faa3baf1b33922b53d288b352ae4b9a",
				"sha512": "46f0e37e72879843f95ddecc4d511c9ba90241c34b471c2f2caca2784abe185da50ddc5252562b2a911b7cfedafa3e878f0e6b7aa843c136915da5306061e501"},
			wantErr: nil,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := RecordArtifact(tt.args.path, tt.args.hashAlgorithms, false)
			if err != tt.wantErr {
				t.Errorf("RecordArtifact() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("RecordArtifact() got = %v, want %v", got, tt.want)
			}
		})
	}
}

// Copy of TestRecordArtifact and TestRecordArtifactWithBlobs with lineNormalization parameter set as true.
// Need to be changed when line normalization is properly implemented.
func TestLineNormalizationFlag(t *testing.T) {
	type args struct {
		path           string
		hashAlgorithms []string
	}
	tests := []struct {
		name    string
		args    args
		wantErr error
	}{
		{
			name: "test line normalization with only new line character",
			args: args{
				path:           "line-ending-linux",
				hashAlgorithms: []string{"sha256", "sha384", "sha512"},
			},
			wantErr: nil,
		},
		{
			name: "test line normalization with carriage return and new line characters",
			args: args{
				path:           "line-ending-windows",
				hashAlgorithms: []string{"sha256", "sha384", "sha512"},
			},
			wantErr: nil,
		},
		{
			name: "test line normalization with only carriage return character",
			args: args{
				path:           "line-ending-macos",
				hashAlgorithms: []string{"sha256", "sha384", "sha512"},
			},
			wantErr: nil,
		},
		{
			name: "test line normalization with combination of all of the above",
			args: args{
				path:           "line-ending-mixed",
				hashAlgorithms: []string{"sha256", "sha384", "sha512"},
			},
			wantErr: nil,
		},
	}
	expected := map[string]interface{}{
		"sha256": "efb929dfabd55c93796fc61cbf1fe6157445f093167dbee82e8b069842a4fceb",
		"sha384": "936e88775dfd17c24ed41e3a896dfdf3395707acee1b6f16a52ae144bdcd8611fd17e817f5b75e5a3cf7a1dacf187bae",
		"sha512": "1d7a485cb2c3cf22c11b4be9afbf1745e053e21a40301d3e8143350d6d2873117c12acef49d4b3650b5262e8a26ffe809b177f968845bd268f26ffd978d314bd",
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := RecordArtifact(tt.args.path, tt.args.hashAlgorithms, true)
			if err != tt.wantErr {
				t.Errorf("RecordArtifact() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, expected) {
				t.Errorf("RecordArtifact() got = %v, want %v", got, expected)
			}
		})
	}
}

func TestInTotoMatchProducts(t *testing.T) {
	link := &Link{
		Products: map[string]any{
			"foo": map[string]string{
				"sha256": "8a51c03f1ff77c2b8e76da512070c23c5e69813d5c61732b3025199e5f0c14d5",
			},
			"bar": map[string]string{
				"sha256": "bb97edb3507a35b119539120526d00da595f14575da261cd856389ecd89d3186",
			},
			"baz": map[string]string{
				"sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
			},
		},
	}
	if _, err := os.Create("bar"); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Create("baz"); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Create("quux"); err != nil {
		t.Fatal(err)
	}

	testDir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		paths                  []string
		excludePatterns        []string
		lstripPaths            []string
		expectedOnlyInProducts []string
		expectedNotInProducts  []string
		expectedDiffer         []string
	}{
		{
			paths:                  []string{"bar", "baz", "quux"},
			expectedOnlyInProducts: []string{"foo"},
			expectedNotInProducts:  []string{"quux"},
			expectedDiffer:         []string{"bar"},
		},
		{
			paths:                  []string{"bar", "baz", "quux"},
			excludePatterns:        []string{"ba*"},
			expectedOnlyInProducts: []string{"bar", "baz", "foo"},
			expectedNotInProducts:  []string{"quux"},
			expectedDiffer:         []string{},
		},
		{
			paths:                  []string{"baz"},
			expectedOnlyInProducts: []string{"bar", "foo"},
			expectedNotInProducts:  []string{},
			expectedDiffer:         []string{},
		},
		{
			paths:                  []string{filepath.Join(testDir, "baz")},
			lstripPaths:            []string{fmt.Sprintf("%s%s", testDir, string(os.PathSeparator))},
			expectedOnlyInProducts: []string{"bar", "foo"},
			expectedNotInProducts:  []string{},
			expectedDiffer:         []string{},
		},
	}

	for _, test := range tests {
		onlyInProducts, notInProducts, differ, err := InTotoMatchProducts(link, test.paths, []string{"sha256"}, test.excludePatterns, test.lstripPaths)
		assert.Nil(t, err)

		sort.Slice(onlyInProducts, func(i, j int) bool {
			return onlyInProducts[i] < onlyInProducts[j]
		})
		sort.Slice(notInProducts, func(i, j int) bool {
			return notInProducts[i] < notInProducts[j]
		})
		sort.Slice(differ, func(i, j int) bool {
			return differ[i] < differ[j]
		})

		assert.Equal(t, test.expectedOnlyInProducts, onlyInProducts)
		assert.Equal(t, test.expectedNotInProducts, notInProducts)
		assert.Equal(t, test.expectedDiffer, differ)
	}
}

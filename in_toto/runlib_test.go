package in_toto

import (
	"errors"
	"io/ioutil"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"fmt"
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

	// Test error by recording inexistent artifact
	result, err = RecordArtifact("file-does-not-exist")
	if !os.IsNotExist(err) {
		t.Errorf("RecordArtifact returned '(%s, %s)', expected '(nil, %s)'",
			result, err, os.ErrNotExist)
	}
}

func TestRecordArtifacts(t *testing.T) {
	// Test successfully record multiple artifacts including temporary subdir
	os.Mkdir("tmpdir", 0700)

	// Folder Creation for Symlink Test
	path1 := "tmpdir/NewFolder"
	path2 := ""
	target := filepath.Join(path1, "test_symlink.txt")
	os.MkdirAll(path1, 0755)
	ioutil.WriteFile(target, []byte("Hello\n"), 0644)
	symlink := filepath.Join(path2, "this_is_symlink")
	os.Symlink("tmpdir/NewFolder", symlink)
	// Folder Creation for symlink test END

	ioutil.WriteFile("tmpdir/tmpfile", []byte("abc"), 0400)
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
	fmt.Println(result)


	//Test to check perfomence with symlink
	result, err = RecordArtifacts([]string{"foo.tar.gz",
		"demo.layout.template", "tmpdir/tmpfile", "this_is_symlink"}, 0)
	expected = map[string]interface{}{
		"foo.tar.gz": map[string]interface{}{
			"sha256": "52947cb78b91ad01fe81cd6aef42d1f6817e92b9e6936c1e5aabb7c98514f355",
		},
		"demo.layout.template": map[string]interface{}{
			"sha256": "019e121a1e0a34aecde0aebb642162b11db4248c781cb8119f81f592723a0424",
		},
		"tmpdir/tmpfile": map[string]interface{}{
			"sha256": "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
		},
		"tmpdir/NewFolder/test_symlink.txt": map[string]interface{}{
			"sha256": "66a045b452102c59d840ec097d59d9467e13a3f34f6494e539ffd32c1bb35f18",
		},
	}
	if !reflect.DeepEqual(result, expected) {
		t.Errorf("RecordArtifacts returned '(%s, %s)', expected '(%s, nil)'",
			result, err, expected)
	}
	fmt.Println(result)

	//Test to check perfomence with only symlink
	result, err = RecordArtifacts([]string{"this_is_symlink"}, 0)
	expected = map[string]interface{}{
		"tmpdir/NewFolder/test_symlink.txt": map[string]interface{}{
			"sha256": "66a045b452102c59d840ec097d59d9467e13a3f34f6494e539ffd32c1bb35f18",
		},
	}
	if !reflect.DeepEqual(result, expected) {
		t.Errorf("RecordArtifacts returned '(%s, %s)', expected '(%s, nil)'",
			result, err, expected)
	}
	fmt.Println(result)

	os.RemoveAll("tmpdir")
	os.RemoveAll("this_is_symlink")

	// Test error by recording inexistent artifact
	result, err = RecordArtifacts([]string{"file-does-not-exist"}, 0)
	if !os.IsNotExist(err) {
		t.Errorf("RecordArtifacts returned '(%s, %s)', expected '(nil, %s)'",
			result, err, os.ErrNotExist)
	}
}

func TestWaitErrToExitCode(t *testing.T) {
	// TODO: Find way to test/mock ExitError
	// Test exit code from error assement
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
	// - error due to inexistent material path
	// - error due to inexistent product path
	// - error due to inexistent run command
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

package in_toto

import (
	"os"
	"reflect"
	"sort"
	"testing"
)

func TestSet(t *testing.T) {
	testSet := NewSet()
	if testSet.Has("a") {
		t.Errorf("not added element 'a' in set %s", testSet.Slice())
	}
	testSet.Add("a")
	if !testSet.Has("a") {
		t.Errorf("added element 'a' not in set %s", testSet.Slice())
	}
	testSet.Add("a")
	setLen := len(testSet)
	if setLen != 1 {
		t.Errorf("expected len 1, got %v for set %s", setLen, testSet.Slice())
	}
	testSet.Remove("a")
	if testSet.Has("a") {
		t.Errorf("removed element 'a' in set %s", testSet.Slice())
	}
	// Nothing should happen
	testSet.Remove("a")
}

func TestSetIntersection(t *testing.T) {
	testSet1 := NewSet("a", "b", "c")
	testSet2 := NewSet("b", "c", "d")
	expected := NewSet("b", "c")
	res := testSet1.Intersection(testSet2)

	if !reflect.DeepEqual(res, expected) {
		t.Errorf("expected %s, got %s", expected.Slice(), res.Slice())
	}
}

func TestSetDifference(t *testing.T) {
	testSet1 := NewSet("a", "b", "c")
	testSet2 := NewSet("b", "c", "d")
	expected := NewSet("a")
	res := testSet1.Difference(testSet2)

	if !reflect.DeepEqual(res, expected) {
		t.Errorf("expected %s, got %s", expected.Slice(), res.Slice())
	}
}

func TestSetSlice(t *testing.T) {
	testSet := NewSet("a", "b", "c")
	expected := []string{"a", "b", "c"}

	res := testSet.Slice()
	sort.Strings(res)
	if !reflect.DeepEqual(res, expected) {
		t.Errorf("expected: %s, got: %s", expected, res)
	}
}

func TestSetFilter(t *testing.T) {
	cases := []struct {
		name           string
		pattern        string
		base, expected Set
	}{
		{"match foo", "foo", NewSet("foo", "foobar", "bar"), NewSet("foo")},
		{"match with wildcard", "foo*", NewSet("foo", "foobar", "bar"), NewSet("foo", "foobar")},
		{"no match", "foo", NewSet("bar"), NewSet()},
		{"no match (due to invalid pattern)", "[", NewSet("["), NewSet()},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			res := tc.base.Filter(tc.pattern)
			if !reflect.DeepEqual(res, tc.expected) {
				t.Errorf("expected: %s, got: %s", tc.expected.Slice(), res.Slice())
			}
		})
	}
}

func TestArtifactsDictKeyStrings(t *testing.T) {
	expected := []string{"a", "b", "c"}
	testMap := map[string]HashObj{"a": nil, "b": nil, "c": nil}
	res := artifactsDictKeyStrings(testMap)
	sort.Strings(res)
	if !reflect.DeepEqual(res, expected) {
		t.Errorf("expected: %s, got: %s", expected, res)
	}
}

func TestSubsetCheck(t *testing.T) {
	tables := []struct {
		subset   []string
		superset Set
		result   bool
	}{
		{[]string{"sha256"}, NewSet("sha256", "sha512"), true},
		{[]string{"sha512"}, NewSet("sha256"), false},
		{[]string{"sha256", "sha512"}, NewSet("sha128", "sha256", "sha512"), true},
		{[]string{"sha256", "sha512", "sha384"}, NewSet("sha128"), false},
	}
	for _, table := range tables {
		result := table.superset.IsSubSet(NewSet(table.subset...))
		if table.result != result {
			t.Errorf("result mismatch for: %#v, %#v, got: %t, should have got: %t", table.subset, table.superset, result, table.result)
		}
	}
}

func TestIsWritable(t *testing.T) {
	notWritable, err := os.MkdirTemp("", "")
	if err != nil {
		t.Error(err)
	}
	writable, err := os.MkdirTemp("", "")
	if err != nil {
		t.Error(err)
	}

	err = os.Chmod(notWritable, os.FileMode(0000))
	if err != nil {
		t.Error(err)
	}

	err = isWritable(notWritable)
	if err == nil {
		t.Errorf("%s should be not writable, but is writable", notWritable)
	}

	err = isWritable(writable)
	if err != nil {
		t.Errorf("%s should be writable, but it is not writable", writable)
	}
}

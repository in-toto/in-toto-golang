package in_toto

import (
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

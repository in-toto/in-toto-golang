package in_toto

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"regexp"
	"sort"
	"strconv"
)

/*
_encodeCanonicalString is a helper function to canonicalize the passed string
according to the OLPC canonical JSON specification for strings (see
http://wiki.laptop.org/go/Canonical_JSON).  String canonicalization consists of
escaping backslashes ("\") and double quotes (") and wrapping the resulting
string in double quotes (").
*/
func _encodeCanonicalString(s string) string {
	re := regexp.MustCompile(`([\"\\])`)
	return fmt.Sprintf("\"%s\"", re.ReplaceAllString(s, "\\$1"))
}

/*
_encodeCanonical is a helper function to recursively canonicalize the passed
object according to the OLPC canonical JSON specification (see
http://wiki.laptop.org/go/Canonical_JSON) and write it to the passed
*bytes.Buffer.  If canonicalization fails it returns an error.
*/
func _encodeCanonical(obj interface{}, result *bytes.Buffer) (err error) {
	// Since this function is called recursively, we use panic if an error occurs
	// and recover in a deferred function, which is always called before
	// returning. There we set the error that is returned eventually.
	defer func() {
		if r := recover(); r != nil {
			err = errors.New(r.(string))
		}
	}()

	switch objAsserted := obj.(type) {
	case string:
		result.WriteString(_encodeCanonicalString(objAsserted))

	case bool:
		if objAsserted {
			result.WriteString("true")
		} else {
			result.WriteString("false")
		}

	// Golang's JSON decoder, which we use before canonicalization, in order to
	// transform any passed object to a generic JSON object, stores JSON
	// numbers as float64. Hence, it is safe to expect all numeric values to be
	// float64.
	case float64:
		// The used canonicalization spec only allows non-floating point numbers
		result.WriteString(strconv.Itoa(int(objAsserted)))

	case nil:
		result.WriteString("null")

	// Canonicalize slice
	case []interface{}:
		result.WriteString("[")
		for i, val := range objAsserted {
			_encodeCanonical(val, result)
			if i < (len(objAsserted) - 1) {
				result.WriteString(",")
			}
		}
		result.WriteString("]")

	case map[string]interface{}:
		result.WriteString("{")

		// Make a list of keys
		mapKeys := []string{}
		for key, _ := range objAsserted {
			mapKeys = append(mapKeys, key)
		}
		// Sort keys
		sort.Strings(mapKeys)

		// Canonicalize map
		for i, key := range mapKeys {
			_encodeCanonical(key, result)
			result.WriteString(":")
			_encodeCanonical(objAsserted[key], result)
			if i < (len(mapKeys) - 1) {
				result.WriteString(",")
			}
			i++
		}
		result.WriteString("}")

	default:
		// We recover in a deferred function defined above
		panic(fmt.Sprintf("Can't canonicalize '%s' of type '%s'",
			objAsserted, reflect.TypeOf(objAsserted)))
	}
	return nil
}

/*
EncodeCanonical JSON canonicalizes the passed object and returns it as a byte
slice.  It uses the OLPC canonical JSON specification (see
http://wiki.laptop.org/go/Canonical_JSON).  If canonicalization fails the byte
slice is nil and the second return value contains the error.
*/
func EncodeCanonical(obj interface{}) ([]byte, error) {
	// FIXME: Terrible hack to turn the passed struct into a map, converting
	// the struct's variable names to the json key names defined in the struct
	data, err := json.Marshal(obj)
	if err != nil {
		return nil, err
	}
	var jsonMap interface{}
	if err := json.Unmarshal(data, &jsonMap); err != nil {
		return nil, err
	}

	// Create a buffer and write the canonicalized JSON bytes to it
	var result bytes.Buffer
	if err := _encodeCanonical(jsonMap, &result); err != nil {
		return nil, err
	}

	return result.Bytes(), nil
}

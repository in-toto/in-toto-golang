package main

import (
  "fmt"
  "sort"
  "regexp"
  "bytes"
  "encoding/json"
  "reflect"
  "strconv"
)

func _encode_canonical_string(s string) string  {
  re := regexp.MustCompile(`([\"\\])`)
  return fmt.Sprintf("\"%s\"", re.ReplaceAllString(s, "\\$1"))
}

func _encode_canonical(obj interface{}, result *bytes.Buffer) {
  switch objAsserted := obj.(type) {
    case string:
      result.WriteString(_encode_canonical_string(objAsserted))

    case bool:
      if objAsserted {
        result.WriteString("true")
      } else {
        result.WriteString("false")
      }

    // Golang's JSON decoder that we always use reads before doing
    // canonicalization stores alls JSON numbers as float64 so it is safe to
    // only expect float64 Also securesystemslib only does ints in
    // canonicalization, so it is safe to convert the float to an int before
    // writing its ASCII representation
    case float64:
      result.WriteString(strconv.Itoa(int(objAsserted)))

    case nil:
      result.WriteString("null")

    case []interface{}:
      result.WriteString("[")
      for i, val := range objAsserted {
        _encode_canonical(val, result)
        if i < (len(objAsserted) - 1) {
          result.WriteString(",")
        }
      }
      result.WriteString("]")

    // Assume that the keys are always strings
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
        _encode_canonical(key, result)
        result.WriteString(":")
        _encode_canonical(objAsserted[key], result)
        if i < (len(mapKeys) - 1) {
          result.WriteString(",")
        }
        i++
      }
      result.WriteString("}")
    default:
      fmt.Println("I don't handle", objAsserted, "of type", reflect.TypeOf(objAsserted))
  }
}

func encode_canonical(obj interface{}) []byte {
  // FIXME: Terrible hack to turn the passed struct into a map, converting
  // the struct's variable names to the json key names defined in the struct
  data, _ := json.Marshal(obj)
  var jsonMap interface{}
  json.Unmarshal(data, &jsonMap)

  // Create a buffer and write the canonicalized JSON bytes to it
  var result bytes.Buffer
  _encode_canonical(jsonMap, &result)

  return result.Bytes()
}

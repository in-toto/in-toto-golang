package intoto

import (
  "fmt"
  "sort"
  "regexp"
  "bytes"
  "encoding/json"
  "reflect"
  "strconv"
  "errors"
)

func _encode_canonical_string(s string) string  {
  re := regexp.MustCompile(`([\"\\])`)
  return fmt.Sprintf("\"%s\"", re.ReplaceAllString(s, "\\$1"))
}

func _encode_canonical(obj interface{}, result *bytes.Buffer) (err error) {
  // Since this function is called recursively, we use panic if an error occurs
  // and recover in below function, which is always called before returning, to
  // set the error that is returned eventually
  defer func() {
    if r := recover(); r != nil {
        err = errors.New(r.(string))
      }
  }()

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

    // It should be safe to assume that the keys are always strings
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
      panic(fmt.Sprintf("Can't canonicalize '%s' of type '%s'",
          objAsserted, reflect.TypeOf(objAsserted)))
  }
  return nil
}

func encode_canonical(obj interface{}) ([]byte, error) {
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
  if err := _encode_canonical(jsonMap, &result); err != nil {
    return nil, err
  }

  return result.Bytes(), nil
}

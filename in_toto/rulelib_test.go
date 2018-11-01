package in_toto

import (
  "testing"
  )

func TestUnpackValidRules(t *testing.T) {

  // A list of valid rules (lists)
  // Each will be passed to rulelib.UnpackRule below
  rules := [][]string {
    []string{"CREATE", "foo"},
    []string{"DELETE", "foo"},
    []string{"MODIFY", "foo"},
    []string{"ALLOW", "foo"},
    []string{"DISALLOW", "foo"},
    []string {"MATCH", "foo", "IN", "source-path", "WITH", "PRODUCTS", "IN",
        "dest-path", "FROM", "step-name"},
    []string {"MATCH", "foo", "IN", "source-path", "WITH", "MATERIALS",
        "FROM", "step-name"},
    []string {"MATCH", "foo", "WITH", "PRODUCTS", "IN", "dest-path",
        "FROM", "step-name"},
    []string {"MATCH", "foo", "WITH", "MATERIALS", "FROM", "step-name"},
  }

  // These are the expected results from rulelib.UnpackRule for above rules
  // (associated by index)
  expectedRuleMaps := []map[string]string {
     map[string]string{"type": "create", "pattern": "foo"},
     map[string]string{"type": "delete", "pattern": "foo"},
     map[string]string{"type": "modify", "pattern": "foo"},
     map[string]string{"type": "allow", "pattern": "foo"},
     map[string]string{"type": "disallow", "pattern": "foo"},
    map[string]string{"type": "match", "pattern": "foo",
        "srcPrefix": "source-path", "dstPrefix": "dest-path",
        "dstType": "products" , "dstName": "step-name"},
    map[string]string{"type": "match", "pattern": "foo",
        "srcPrefix": "source-path", "dstPrefix": "",
        "dstType": "materials" , "dstName": "step-name"},
    map[string]string{"type": "match", "pattern": "foo",
        "srcPrefix": "", "dstPrefix": "dest-path",
        "dstType": "products" , "dstName": "step-name"},
    map[string]string{"type": "match", "pattern": "foo",
        "srcPrefix": "", "dstPrefix": "",
        "dstType": "materials" , "dstName": "step-name"},
  }

  for i, rule := range rules {
    returnedRuleMap, err := UnpackRule(rule)
    if err != nil {
      t.Error(err)
    }

    for _, key := range []string{"type", "pattern", "srcPrefix", "dstPrefix",
        "dstName", "dstType"} {
      if returnedRuleMap[key] != expectedRuleMaps[i][key] {
        t.Errorf("Invalid '%s' in unpacked rule '%s', should be '%s', got" +
              " '%s'", key, rule, expectedRuleMaps[i][key],
              returnedRuleMap[key])
      }
    }
  }
}

func TestUnpackInvalidRules(t *testing.T) {
  rules := [][]string {
    []string{"CREATE", "foo", "too-long"},
    []string{"SUBVERT", "foo"},
    []string{"MODIFY"},
    []string {"MATCH", "foo", "too-many-patterns", "IN", "source-path", "WITH",
      "PRODUCTS", "IN", "dest-path", "FROM", "step-name"},
    []string {"MATCH", "foo", "WITH", "GUMMY", "BEARS"},
  }
  for _, rule := range rules {
    if _, err := UnpackRule(rule); err == nil {
      t.Errorf("Invalid rule %s should return error from UnpackRule.", rule)
    }
  }

}
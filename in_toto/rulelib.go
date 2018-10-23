package intoto

import (
  "fmt"
  "strings"
  )

var errorMsg string = "Wrong rule format, available formats are:\n\t" +
  "MATCH <pattern> [IN <source-path-prefix>] WITH (MATERIALS|PRODUCTS)" +
      " [IN <destination-path-prefix>] FROM <step>,\n\t" +
  "CREATE <pattern>,\n\t" +
  "DELETE <pattern>,\n\t" +
  "MODIFY <pattern>,\n\t" +
  "ALLOW <pattern>,\n\t" +
  "DISALLOW <pattern>\n\n"



func unpackRule(rule []string) (map[string]string, error) {
  // Cache rule len
  ruleLen := len(rule)

  // Create all lower rule copy to case insensitively parse out tokens whose
  // position we don't know yet
  // We keep the original rule to retain the non-token elements' case
  ruleLower := make([]string, ruleLen)
  for i, val := range rule {
    ruleLower[i] = strings.ToLower(val)
  }

  switch ruleLower[0] {
    case "create", "modify", "delete", "allow", "disallow":
        if ruleLen != 2 {
          return nil,
              fmt.Errorf("%s Got:\n\t %s", errorMsg, rule)
        }

        return map[string]string {
          "type": ruleLower[0],
          "pattern": rule[1],
        }, nil

    case "match":
      var srcPrefix string
      var dstType string
      var dstPrefix string
      var dstName string

      if ruleLen == 10 && ruleLower[2] == "in" &&
          ruleLower[4] == "with" && ruleLower[6] == "in" &&
          ruleLower[8] == "from" {
        srcPrefix = rule[3]
        dstType = ruleLower[5]
        dstPrefix = rule[7]
        dstName = rule[9]

      } else if ruleLen == 8 && ruleLower[2] == "in" &&
          ruleLower[4] == "with" && ruleLower[6] == "from" {
        srcPrefix = rule[3]
        dstType = ruleLower[5]
        dstPrefix = ""
        dstName = rule[7]

      } else if ruleLen == 8 && ruleLower[2] == "with" &&
          ruleLower[4] == "in" && ruleLower[6] == "from" {
        srcPrefix = ""
        dstType = ruleLower[3]
        dstPrefix = rule[5]
        dstName = rule[7]

      } else if ruleLen == 6 && ruleLower[2] == "with" &&
          ruleLower[4] == "from" {
        srcPrefix = ""
        dstType = ruleLower[3]
        dstPrefix = ""
        dstName = rule[5]

      } else {
        return nil,
            fmt.Errorf("%s Got:\n\t %s", errorMsg, rule)

      }

      return map[string]string{
        "type": ruleLower[0],
        "pattern": rule[1],
        "srcPrefix": srcPrefix,
        "dstPrefix": dstPrefix,
        "dstType": dstType,
        "dstName": dstName,
      }, nil


    default:
      return nil,
          fmt.Errorf("%s Got:\n\t %s", errorMsg, rule)

  }
}
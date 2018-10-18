package main

type KeyVal struct {
  Private string `json:"private"`
  Public string `json:"public"`
}

type Key struct {
  KeyId string `json:"keyid"`
  KeyIdHashAlgorithms []string `json:"keyid_hash_algorithms"`
  KeyType string `json:"keytype"`
  KeyVal KeyVal `json:"keyval"`
  Scheme string `json:"scheme"`
}

type Signature struct {
  KeyId string `json:"keyid"`
  Sig string `json:"sig"`
}

type Link struct {
  Type string `json:"_type"`
  Name string `json:"name"`
  Materials map[string]interface{} `json:"materials"`
  Products map[string]interface{} `json:"products"`
  ByProducts map[string]interface{} `json:"byproducts"`
  Command []string `json:"command"`
  Environment map[string][]interface{} `json:"environment"`
}

type Inspection struct {
  Type string `json:"_type"`
  Run []string `json:"run"`
  //TODO: Abstraction for Steps and Inspections?
  Name string  `json:"name"`
  ExpectedMaterials [][]string `json:"expected_materials"`
  ExpectedProducts [][]string `json:"expected_products"`
}

type Step struct {
  Type string `json:"_type"`
  PubKeys []string `json:"pubkeys"`
  ExpectedCommand []string `json:"expected_command"`
  Threshold int `json:"threshold"`

  //TODO: Abstraction for Steps and Inspections?
  Name string  `json:"name"`
  ExpectedMaterials [][]string `json:"expected_materials"`
  ExpectedProducts [][]string `json:"expected_products"`
}

type Layout struct {
  Type string `json:"_type"`
  Steps []Step `json:"steps"`
  Inspect []Inspection `json:"inspect"`
  Keys map[string]Key `json:"keys"`
  Expires string `json:"expires"`
  Readme string `json:"readme"`
}

type Metablock struct {
  // NOTE: Whenever we want to access an attribute of `Signed` we have to
  // perform type assertion, e.g. `metablock.Signed.(Layout).Keys`
  // Maybe there is a better way to store either Layouts or Links in `Signed`?
  // The notary folks seem to have separate container structs:
  // https://github.com/theupdateframework/notary/blob/master/tuf/data/root.go#L10-L14
  // https://github.com/theupdateframework/notary/blob/master/tuf/data/targets.go#L13-L17
  // I implemented it this way, because there will be several functions that
  // receive or return a Metablock, where the inner signed has to be inferred
  // on runtime, e.g. when iterating over links for a layout, and a link can
  // turn out to be a layout (sublayout)
  Signed interface{} `json:"signed"`
  Signatures []Signature `json:"signatures"`
}
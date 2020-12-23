# In-toto Go implementation
[![build](https://github.com/in-toto/in-toto-golang/workflows/build/badge.svg)](https://github.com/in-toto/in-toto-golang/actions?query=workflow%3Abuild) [![Coverage Status](https://coveralls.io/repos/github/in-toto/in-toto-golang/badge.svg)](https://coveralls.io/github/in-toto/in-toto-golang) [![PkgGoDev](https://pkg.go.dev/badge/github.com/in-toto/in-toto-golang)](https://pkg.go.dev/github.com/in-toto/in-toto-golang) [![Go Report Card](https://goreportcard.com/badge/github.com/in-toto/in-toto-golang)](https://goreportcard.com/report/github.com/in-toto/in-toto-golang)


Go implementation of the 
[in-toto Python reference implementation](https://github.com/in-toto/in-toto).

## Docs

To read the documentation along with some examples, run:

```bash
godoc -http :8080
```

and navigate to `localhost:8080/pkg/github.com/in-toto/in-toto-golang/in_toto/`


## Not (yet) supported

This golang implementation was focused on verification on admission controllers
and kubectl plugins. As such, it focused on providing a strong, auditable set
of core functions rather than a broad and (possibly) unstable feature set. In
other words, we believe that the current feature set is stable enough for
production use.

If any of these features are necessary for your use case please let us know and
we will try to provide them as soon as possible!

* [GPG keys](https://github.com/in-toto/in-toto-golang/issues/26)

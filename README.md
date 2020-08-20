# Go in-toto verification
[![Build Status](https://travis-ci.com/in-toto/in-toto-golang.svg?branch=master)](https://travis-ci.com/in-toto/in-toto-golang) [![Coverage Status](https://coveralls.io/repos/github/in-toto/in-toto-golang/badge.svg)](https://coveralls.io/github/in-toto/in-toto-golang) [![Build status](https://ci.appveyor.com/api/projects/status/n45pmpso0t5b40vk?svg=true)](https://ci.appveyor.com/project/in-toto/in-toto-golang)


Basic Go implementation of in-toto supply chain verification, based on the
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
* [Layout parameter substitution](https://github.com/in-toto/in-toto-golang/issues/29)
* [Hashing algorithms, other than `sha256` (in artifact recording)](https://github.com/in-toto/in-toto-golang/issues/31)
* [Exclude patterns (in artifact recording)](https://github.com/in-toto/in-toto-golang/issues/33)

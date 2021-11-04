## in-toto verify

Verify that the software supply chain of the delivered product

### Synopsis

in-toto-verify is the main verification tool of the suite, and 
it is used to verify that the software supply chain of the delivered 
product was carried out as defined in the passed in-toto supply chain 
layout. Evidence for supply chain steps must be available in the form 
of link metadata files named ‘<step name>.<functionary keyid prefix>.link’.

```
in-toto verify [flags]
```

### Options

```
  -h, --help                         help for verify
  -i, --intermediate-certs strings   Path(s) to PEM formatted certificates, used as intermediaries to verify
                                     the chain of trust to the layout's trusted root. These will be used in
                                     addition to any intermediates in the layout.
  -l, --layout string                Path to root layout specifying the software supply chain to be verified
  -k, --layout-keys strings          Path(s) to PEM formatted public key(s), used to verify the passed 
                                     root layout's signature(s). Passing at least one key using
                                     '--layout-keys' is required. For each passed key the layout
                                     must carry a valid signature.
  -d, --link-dir string              Path to directory where link metadata files for steps defined in 
                                     the root layout should be loaded from. If not passed links are 
                                     loaded from the current working directory.
      --normalize-line-endings       Enable line normalization in order to support different
                                     operating systems. It is done by replacing all line separators
                                     with a new line character.
```

### SEE ALSO

* [in-toto](in-toto.md)	 - Framework to secure integrity of software supply chains


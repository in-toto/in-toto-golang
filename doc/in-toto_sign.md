## in-toto sign

Provides command line interface to sign in-toto link or layout metadata

### Synopsis

Provides command line interface to sign in-toto link or layout metadata

```
in-toto sign [flags]
```

### Options

```
  -f, --file string     Path to link or layout file to be signed or verified.
  -h, --help            help for sign
  -k, --key string      Path to PEM formatted private key used to sign the passed 
                        root layout's signature(s). Passing exactly one key using
                        '--key' is required.
  -o, --output string   Path to store metadata file after signing
      --verify          Verify signature of signed file
```

### SEE ALSO

* [in-toto](in-toto.md)	 - Framework to secure integrity of software supply chains


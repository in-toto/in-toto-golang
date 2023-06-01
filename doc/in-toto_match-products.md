## in-toto match-products

Check if local artifacts match products in passed link

```
in-toto match-products [flags]
```

### Options

```
  -e, --exclude stringArray        gitignore-style patterns to exclude artifacts from matching
  -h, --help                       help for match-products
  -l, --link string                Path to link metadata file
      --lstrip-paths stringArray   Path prefixes used to left-strip artifact paths before storing
                                   them to the resulting link metadata. If multiple prefixes
                                   are specified, only a single prefix can match the path of
                                   any artifact and that is then left-stripped. All prefixes
                                   are checked to ensure none of them are a left substring
                                   of another.
  -p, --path stringArray           file or directory paths to local artifacts, default is CWD (default [.])
```

### SEE ALSO

* [in-toto](in-toto.md)	 - Framework to secure integrity of software supply chains


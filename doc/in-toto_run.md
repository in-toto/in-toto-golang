## in-toto run

Executes the passed command and records paths and hashes of 'materials'

### Synopsis

Executes the passed command and records paths and hashes of 'materials' (i.e.
files before command execution) and 'products' (i.e. files after command
execution) and stores them together with other information (executed command,
return value, stdout, stderr, ...) to a link metadata file, which is signed
with the passed key.  Returns nonzero value on failure and zero otherwise.

```
in-toto run [flags]
```

### Options

```
  -c, --cert string                       Path to a PEM formatted certificate that corresponds with
                                          the provided key.
  -e, --exclude stringArray               Path patterns to match paths that should not be recorded as 0
                                          ‘materials’ or ‘products’. Passed patterns override patterns defined
                                          in environment variables or config files. See Config docs for details.
  -h, --help                              help for run
  -k, --key string                        Path to a PEM formatted private key file used to sign
                                          the resulting link metadata.
  -l, --lstrip-paths stringArray          Path prefixes used to left-strip artifact paths before storing
                                          them to the resulting link metadata. If multiple prefixes
                                          are specified, only a single prefix can match the path of
                                          any artifact and that is then left-stripped. All prefixes
                                          are checked to ensure none of them are a left substring
                                          of another.
  -m, --materials stringArray             Paths to files or directories, whose paths and hashes
                                          are stored in the resulting link metadata before the
                                          command is executed. Symlinks are followed.
  -d, --metadata-directory string         Directory to store link metadata (default "./")
  -n, --name string                       Name used to associate the resulting link metadata
                                          with the corresponding step defined in an in-toto layout.
  -x, --no-command                        Indicate that there is no command to be executed for the step.
      --normalize-line-endings            Enable line normalization in order to support different
                                          operating systems. It is done by replacing all line separators
                                          with a new line character.
  -p, --products stringArray              Paths to files or directories, whose paths and hashes
                                          are stored in the resulting link metadata after the
                                          command is executed. Symlinks are followed.
  -r, --run-dir string                    runDir specifies the working directory of the command.
                                          If runDir is the empty string, the command will run in the
                                          calling process's current directory. The runDir directory must
                                          exist, be writable, and not be a symlink.
      --spiffe-workload-api-path string   UDS path for SPIFFE workload API
```

### SEE ALSO

* [in-toto](in-toto.md)	 - Framework to secure integrity of software supply chains


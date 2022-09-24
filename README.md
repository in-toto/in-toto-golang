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

## Example

A very simple example, just to help you starting:

```go
package main

import (
	"time"
	toto "github.com/in-toto/in-toto-golang/in_toto"
)

func main() {
	t := time.Now()
	t = t.Add(30 * 24 * time.Hour)

	var keys = make(map[string]toto.Key)

	var metablock = toto.Metablock{
		Signed: toto.Layout{
			Type: "layout",
			Expires:  t.Format("2006-01-02T15:04:05Z"),
			Steps: []toto.Step{},
			Inspect: []toto.Inspection{},
			Keys:  keys,
		},
	}

	var key toto.Key

	key.LoadKey("keys/alice", "rsassa-pss-sha256", []string{"sha256", "sha512"})

	metablock.Sign(key)

	metablock.Dump("root.layout")
}
```

## Running the Demo

To run the demo, pull down the source code, install Go, and run `make test-verify`.
This will use openssl to generate a certificate chain.

To run the demo using Spire, pull down the source code, install Go and Docker, and run `make test-spiffe-verify`.

SPIFFE compliant Leaf certificates are generated with SVIDs corresponding to functionaries. These certificates are consumed by in-toto to sign link-meta data and the layout policy.

During the in-toto verification process, `certificate constraints` are checked to ensure the build step link meta-data was signed with the correct SVID.

## Building

Download the source, run `make build`.

## CLI

```text
Usage:
  in-toto [command]

Available Commands:
  help        Help about any command
  key         Key management commands
  record      Creates a signed link metadata file in two steps, in order to provide evidence for supply chain steps that cannot be carried out by a single command
  run         Executes the passed command and records paths and hashes of 'materials'
  sign        Provides command line interface to sign in-toto link or layout metadata
  verify      Verify that the software supply chain of the delivered product

Flags:
  -h, --help                              help for in-toto

Use "in-toto [command] --help" for more information about a command.
```

### key

```text
Key management commands

Usage:
  in-toto key [command]

Available Commands:
  id          Output the key id for a given key
  layout      Output the key layout for a given key in <KEYID>: <KEYOBJ> format

Flags:
  -h, --help   help for key

Use "in-toto key [command] --help" for more information about a command.
```

### run

```text
Executes the passed command and records paths and hashes of 'materials' (i.e.
files before command execution) and 'products' (i.e. files after command
execution) and stores them together with other information (executed command,
return value, stdout, stderr, ...) to a link metadata file, which is signed
with the passed key.  Returns nonzero value on failure and zero otherwise.

Usage:
  in-toto run [flags]

Flags:
  -c, --cert string                       Path to a PEM formatted certificate that corresponds with
                                          the provided key.
  -e, --exclude stringArray               path patterns to match paths that should not be recorded as 0
                                          ‘materials’ or ‘products’. Passed patterns override patterns defined
                                          in environment variables or config files. See Config docs for details.
  -h, --help                              help for run
  -k, --key string                        Path to a PEM formatted private key file used to sign
                                          the resulting link metadata. (passing one of '--key'
                                          or '--gpg' is required) 
  -l, --lstrip-paths stringArray          path prefixes used to left-strip artifact paths before storing
                                          them to the resulting link metadata. If multiple prefixes
                                          are specified, only a single prefix can match the path of
                                          any artifact and that is then left-stripped. All prefixes
                                          are checked to ensure none of them are a left substring
                                          of another.
  -m, --materials stringArray             Paths to files or directories, whose paths and hashes
                                          are stored in the resulting link metadata before the
                                          command is executed. Symlinks are followed.
  -n, --name string                       Name used to associate the resulting link metadata
                                          with the corresponding step defined in an in-toto
                                          layout.
        --normalize-line-endings          Enable line normalization in order to support different
                                          operating systems. It is done by replacing all line separators
                                          with a new line character.
  -d, --metadata-directory string         directory to store link metadata (default "./")
  -p, --products stringArray              Paths to files or directories, whose paths and hashes
                                          are stored in the resulting link metadata after the
                                          command is executed. Symlinks are followed.
  -r, --run-dir string                    runDir specifies the working directory of the command.
                                          If runDir is the empty string, the command will run in the
                                          calling process's current directory. The runDir directory must
                                          exist, be writable, and not be a symlink.
      --spiffe-workload-api-path string   uds path for spiffe workload api
```

### sign

```text
Provides command line interface to sign in-toto link or layout metadata

Usage:
  in-toto sign [flags]

Flags:
  -f, --file string     Path to link or layout file to be signed or verified.
  -h, --help            help for sign
  -k, --key string      Path to PEM formatted private key used to sign the passed 
                        root layout's signature(s). Passing exactly one key using
                        '--layout-key' is required.
  -o, --output string   Path to store metadata file to be signed
```

### verify

```text
in-toto-verify is the main verification tool of the suite, and 
it is used to verify that the software supply chain of the delivered 
product was carried out as defined in the passed in-toto supply chain 
layout. Evidence for supply chain steps must be available in the form 
of link metadata files named ‘<step name>.<functionary keyid prefix>.link’.

Usage:
  in-toto verify [flags]

Flags:
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

### record

```text
Creates a signed link metadata file in two steps, in order to provide
evidence for supply chain steps that cannot be carried out by a single command
(for which ‘in-toto-run’ should be used). It returns a non-zero value on
failure and zero otherwise.

Usage:
  in-toto record [command]

Available Commands:
  start       Creates a preliminary link file recording the paths and hashes of the
passed materials and signs it with the passed functionary’s key.
  stop        Records and adds the paths and hashes of the passed products to the link metadata file and updates the signature.

Flags:
  -c, --cert string                       Path to a PEM formatted certificate that corresponds with the provided key.
  -e, --exclude stringArray               Path patterns to match paths that should not be recorded as 
                                          ‘materials’ or ‘products’. Passed patterns override patterns defined
                                          in environment variables or config files. See Config docs for details.
  -h, --help                              help for record
  -k, --key string                        Path to a private key file to sign the resulting link metadata.
                                          The keyid prefix is used as an infix for the link metadata filename,
                                          i.e. ‘<name>.<keyid prefix>.link’. See ‘–key-type’ for available
                                          formats. Passing one of ‘–key’ or ‘–gpg’ is required.
  -l, --lstrip-paths stringArray          Path prefixes used to left-strip artifact paths before storing
                                          them to the resulting link metadata. If multiple prefixes
                                          are specified, only a single prefix can match the path of
                                          any artifact and that is then left-stripped. All prefixes
                                          are checked to ensure none of them are a left substring
                                          of another.
  -d, --metadata-directory string         directory to store link metadata (default "./")
  -n, --name string                       name for the resulting link metadata file.
                                          It is also used to associate the link with a step defined
                                          in an in-toto layout.
      --normalize-line-endings            Enable line normalization in order to support different
                                          operating systems. It is done by replacing all line separators
                                          with a new line character.
      --spiffe-workload-api-path string   uds path for spiffe workload api

Use "in-toto record [command] --help" for more information about a command.
```

### Completion

```text
Generate completion script
Usage:
  in-toto completion [bash|zsh|fish|powershell]

Flags:
  -h, --help   help for completion
```

#### Bash

```shell
$ source <(in-toto completion bash)
# To load completions for each session, execute once:
# Linux (the target location may differ depending on your distro):
$ in-toto completion bash > /etc/bash_completion.d/in-toto
# macOS:
$ in-toto completion bash > /usr/local/etc/bash_completion.d/in-toto
```

#### Zsh

```shell
# If shell completion is not already enabled in your environment,
# you will need to enable it.  You can execute the following once:
$ echo "autoload -U compinit; compinit" >> ~/.zshrc
# To load completions for each session, execute once:
$ in-toto completion zsh > "${fpath[1]}/_in-toto"
# You will need to start a new shell for this setup to take effect.
```

#### Fish

```shell
fish:
$ in-toto completion fish | source
# To load completions for each session, execute once:
$ in-toto completion fish > ~/.config/fish/completions/in-toto.fish
```

#### PowerShell

```shell
PS> in-toto completion powershell | Out-String | Invoke-Expression
# To load completions for every new session, run:
PS> in-toto completion powershell > in-toto.ps1
# and source this file from your PowerShell profile.
```

## Layout Certificate Constraints

Currently the following constraints supported:

```json
{
  "cert_constraints": [{
    "common_name": "write-code.example.com",
      "dns_names": [
        ""
      ],
      "emails": [
        ""
      ],
      "organizations": [
        "*"
      ],
      "roots": [
        "*"
      ],
      "uris": [
        "spiffe://example.com/write-code"
      ]
  }, {
    "uris": [],
    "common_names": ["Some User"]
  }]
}
```

## Not (yet) supported

This golang implementation was focused on verification on admission controllers
and kubectl plugins. As such, it focused on providing a strong, auditable set
of core functions rather than a broad and (possibly) unstable feature set. In
other words, we believe that the current feature set is stable enough for
production use.

If any of these features are necessary for your use case please let us know and
we will try to provide them as soon as possible!

* [GPG keys](https://github.com/in-toto/in-toto-golang/issues/26)

# in-toto-spiffe Proof Of Concept -- Not for Prod

in-toto is a specification to provide policy and attestations for software supply chains.
Managing the PKI around in-toto has been a major reason cited as lack of adoption.
The project aims to provide a non-production proof of concept on integrating SPIRE PKI orchestration
with in-toto build chain attestation.

The integration effort required support for CA based validation of functionaries.  In-toto currently
requires the corresponding public key for each key used in the process.  This process does not
fit within most enterprise PKI policy.  Validation of signatures based on certificate constraints
will allow end-users to integrate in-toto with existing enterprise PKI.

## Running the Demo

To run the demo, pull down the source code, install Go, and run `make test-verify`
This will use openssl to gerate a certificate chain.

SPIFFE compliant Leaf certificates are generated with SVIDs corresponding to functionaries.  These certificates are consumed
by in-toto to sign link-meta data and the layout policy.

During the in-toto verification process, `certificate constraints` are checked to ensure
the build step link meta-data was signed with the correct SVID.


## Building

Download the source, run `make build`

## CLI

```
Usage:
  in-toto [command]

Available Commands:
  help        Help about any command
  run         Executes the passed command and records paths and hashes of 'materials'
  sign        Provides command line interface to sign in-toto link or layout metadata
  verify      Verify that the software supply chain of the delivered product

Flags:
  -h, --help   help for in-toto

Use "in-toto [command] --help" for more information about a command.
```

### run
```
Executes the passed command and records paths and hashes of 'materials' (i.e.
files before command execution) and 'products' (i.e. files after command
execution) and stores them together with other information (executed command,
return value, stdout, stderr, ...) to a link metadata file, which is signed
with the passed key.  Returns nonzero value on failure and zero otherwise.

Usage:
  in-toto run [flags]

Flags:
  -c, --cert string               Path to a PEM formatted certificate that corresponds with
                                  the provided key.
  -h, --help                      help for run
  -k, --key string                Path to a PEM formatted private key file used to sign
                                  the resulting link metadata. (passing one of '--key'
                                  or '--gpg' is required)
  -m, --materials stringArray     Paths to files or directories, whose paths and hashes
                                  are stored in the resulting link metadata before the
                                  command is executed. Symlinks are followed.
  -n, --name string               Name used to associate the resulting link metadata
                                  with the corresponding step defined in an in-toto
                                  layout.
  -d, --output-directory string   directory to store link metadata (default "./")
  -p, --products stringArray      Paths to files or directories, whose paths and hashes
                                  are stored in the resulting link metadata after the
                                  command is executed. Symlinks are followed.
```
### sign
```
Provides command line interface to sign in-toto link or layout metadata

Usage:
  in-toto sign [flags]

Flags:
  -f, --file string     Path to link or layout file to be signed or verified.
  -h, --help            help for sign
  -k, --key string      Path to PEM formatted private key used to sign the passed
                        root layout's signature(s). Passing exactly one key using
                        '--layout-key' is       required.
  -o, --output string   Path to store metadata file to be signed
```
### verify
```
in-toto-verify is the main verification tool of the suite, and
it is used to verify that the software supply chain of the delivered
product was carried out as defined in the passed in-toto supply chain
layout. Evidence for supply chain steps must be available in the form
of link metadata files named ‘<step name>.<functionary keyid prefix>.link’.

Usage:
  in-toto verify [flags]

Flags:
  -h, --help                         help for verify
  -i, --intermediate-certs strings   Path(s) to PEM formatted certificates, used as intermediaetes to verify
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
 ```

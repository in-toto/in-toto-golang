#!/bin/env python
from securesystemslib import interface
from in_toto.models.layout import Layout
from in_toto.models.metadata import Metablock


def main():
    key_owner = interface.import_rsa_privatekey_from_file("./test/alice")

    layout = Layout.read({
    "signatures": [],
    "signed": {
    "_type": "layout",
    "expires": "2021-03-17T00:13:15Z",
    "inspect": [],
    "keys": {
    "70ca5750c2eda80b18f41f4ec5f92146789b5d68dd09577be422a0159bd13680": {
        "keyid": "70ca5750c2eda80b18f41f4ec5f92146789b5d68dd09577be422a0159bd13680",
        "keyid_hash_algorithms": [
        "sha256",
        "sha512"
        ],
        "keytype": "rsa",
        "keyval": {
        "private": "",
        "public": "-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAr2u+1EN9NMIAtqYZ2pqF\n3ov4omRpdgEorv1L4sBMaFN+2EPyqeMTF838/W4V/1fHLr5jaqIVY0VjcpAmCRJ6\noRhxw/6o7dgiIPsrTCWQHFAkXcElgb+2JUXWZO3azX90fxFliucPPj0IrLgK3u5O\nD+XgaT773Za2JJSe7A0Iacjb23Elm2T05ydtrWHy5zVMmg+Yj64iaXRxoLUhFpdp\nNOw/rVIUSiFItip+SAZjIsjqQDILzy4RcNUJqBFHG2N/cEwnO+ozb1G9sCtGSya6\nBkCQGhmX64xgehpSUomDod2q3ZmNlS2+9aUMpNq4TksLL08mhQkZi7atNoG4rq4p\nnwIDAQAB\n-----END PUBLIC KEY-----"
        },
        "scheme": "rsassa-pss-sha256"
    }
    },
    "readme": "",
    "steps": [
    {
        "_type": "step",
        "expected_command": [
        "-c",
        "echo hello > ./test/data/foo.py"
        ],
        "expected_materials": [
        [
        "DISALLOW",
        "*"
        ]
        ],
        "expected_products": [
        [
        "DISALLOW",
        "*"
        ]
        ],
        "name": "write-code",
        "pubkeys": [
        "70ca5750c2eda80b18f41f4ec5f92146789b5d68dd09577be422a0159bd13680"
        ],
        "threshold": 1
    },
    {
        "_type": "step",
        "expected_command": [
        "tar",
        "zcvf",
        "./test/data/foo.py"
        ],
        "expected_materials": [
        [
        "MATCH",
        "*",
        "WITH",
        "PRODUCTS",
        "FROM",
        "write-code"
        ]
        ],
        "expected_products": [
        [
        "ALLOW",
        "./test/data/foo.py"
        ],
        [
        "DISALLOW",
        "*"
        ]
        ],
        "name": "package",
        "pubkeys": [
        "70ca5750c2eda80b18f41f4ec5f92146789b5d68dd09577be422a0159bd13680"
        ],
        "threshold": 1
    }
    ]
    }
})

    metadata = Metablock(signed=layout)

    # Sign and dump layout to "root.layout"
    metadata.sign(key_owner)
    metadata.dump("root.layout")


if __name__ == '__main__':
    main()
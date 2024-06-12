# Go Zcash Address parser

A golang implementation of zcash address parsers

Parsing and serialization for Zcash addresses, including:

* base58-encoded transparent p2pkh and p2sh addresses
* bech32-encoded Sapling addresses
* bech32m-encoded ZIP 320 TEX addresses
* Unified Addresses

The main function in this library, DecodeAddress() takes a
string and a Network and returns a struct of with the following
definition and any errors.

```Go
type ZcashAddress struct {
  P2pkh   *[20]byte
  P2sh    *[20]byte
  Sapling *[43]byte
  Unified *unifiedaddress.UnifiedAddress
  Tex     *[20]byte
}
```

Note that only one of these values will be non-nil.

The Network struct

```Go
type Network struct {
  p2pkhLead    [2]byte
  p2shLead     [2]byte
  texHRP       string
  saplingHRP   string
  unifiedHRP   string
  unifiedR1HRP string
}
```

provides the encoding prefixes for the Mainnet, Testnet, and Regtest networks.

A set of convenience methods: DecodeP2pkh(), DecodeP2sh(), DecodeSapling(), and DecodeOrchard()
have been provided for direct decoding to a specific type.

The length of the encoding is limited by f4jumble to 4194368 bytes in accordance with
<https://zips.z.cash/zip-0316>

A unified address contains a map of Unknown Encodings of unknown lengths.

```Go
type UnifiedAddress struct {
  P2pkh   *[20]byte
  P2sh    *[20]byte
  Sapling *[43]byte
  Orchard *[43]byte
  Unknown map[uint64][]byte
}
```

Entries in the `Unknown` map correspond to unified address receivers and metadata entries
that do not correspond to typecodes understood by this library.

Implementation patterns can be found in the zcashaddress_test.go found in this repository.

Test Vectors in the file zcashaddress_test.go are a port of the vectors found at
<https://github.com/zcash/zcash-test-vectors/blob/master/test-vectors/rust/unified_address.rs>

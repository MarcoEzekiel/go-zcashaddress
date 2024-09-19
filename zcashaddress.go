// package zcashaddress
//
// Parsing and serialization for Zcash addresses, including:
// * base58-encoded transparent p2pkh and p2sh addresses
// * bech32-encoded Sapling addresses
// * bech32m-encoded ZIP 320 TEX addresses
// * Unified Addresses

package zcashaddress

import (
	"errors"

	"github.com/MarcoEzekiel/go-zcashaddress/unifiedaddress"
	"github.com/btcsuite/btcd/btcutil/base58"
	"github.com/btcsuite/btcd/btcutil/bech32"
)

// A parsed Zcash address. Fields of this structure are mutually exclusive; only one field may be non-nil.
type ZcashAddress struct {
	P2pkh   *[20]byte
	P2sh    *[20]byte
	Sapling *[43]byte
	Unified *unifiedaddress.UnifiedAddress
	Tex     *[20]byte
}

// A set of address prefix and lead-byte constants for a Zcash network.
type Network struct {
	p2pkhLead    [2]byte
	p2shLead     [2]byte
	texHRP       string
	saplingHRP   string
	unifiedHRP   string
	unifiedR1HRP string
}

// The Zcash mainnet network constants.
func Mainnet() Network {
	return Network{
		p2pkhLead:    [2]byte{0x1c, 0xb8},
		p2shLead:     [2]byte{0x1c, 0xbd},
		texHRP:       "tex",
		saplingHRP:   "zs",
		unifiedHRP:   "u",
		unifiedR1HRP: "ur",
	}
}

// The Zcash testnet network constants.
func Testnet() Network {
	return Network{
		p2pkhLead:    [2]byte{0x1D, 0x25},
		p2shLead:     [2]byte{0x1c, 0xba},
		texHRP:       "textest",
		saplingHRP:   "ztestsapling",
		unifiedHRP:   "utest",
		unifiedR1HRP: "urtest",
	}
}

// The Zcash regtest network constants.
func Regtest() Network {
	return Network{
		p2pkhLead:    [2]byte{0x1c, 0x25},
		p2shLead:     [2]byte{0x1c, 0xba},
		texHRP:       "texregtest",
		saplingHRP:   "zregtestsapling",
		unifiedHRP:   "uregtest",
		unifiedR1HRP: "urregtest",
	}
}

// DecodeAddress is the primary function for decoding all zcash address types.
// It returns a ZcashAddress; only one of the fields of the returned struct will be non-nil.
func DecodeAddress(address string, network Network) (result ZcashAddress, err error) {
	//
	// Try base58 decoding. If the prefix matches a the transparent address prefix bytes, this
	// is a Zcash transparent address.
	// ignore the error from attempting to CheckDecode return in final error if all other decodes fail
	decoded, base58Version, base58Error := base58.CheckDecode(address)
	if base58Error == nil {
		if base58Version == network.p2pkhLead[0] && decoded[0] == network.p2pkhLead[1] && len(decoded) == 21 {
			result.P2pkh = new([20]byte)
			copy(result.P2pkh[:], decoded[1:])
			return result, nil
		} else if base58Version == network.p2shLead[0] && decoded[0] == network.p2shLead[1] && len(decoded) == 21 {
			result.P2sh = new([20]byte)
			copy(result.P2sh[:], decoded[1:])
			return result, nil
		}
	}

	// bech32m decoding
	// currently for tex addresses
	// ignore the error from attempting to bech32.DecodeGeneric
	// return in final error if all other decodes fail
	humanReadablePrefix, bech32m_decoded_address, bech32Version, bech32Error := bech32.DecodeGeneric(address)
	if bech32Error == nil {
		if bech32Version == bech32.VersionM {
			if humanReadablePrefix == network.texHRP {
				conv, err := bech32.ConvertBits(bech32m_decoded_address, 5, 8, true)
				if err == nil {
					if len(conv) == 20 {
						result.Tex = new([20]byte)
						copy(result.Tex[:], conv)
						return result, nil
					} else {
						return result, errors.New("tex address data must be 20 bytes")
					}
				} else {
					return result, err
				}
			} else if humanReadablePrefix == network.unifiedR1HRP {
				// attempt unified R1 decoding
				return result, errors.New("unified address revision 1 decoding not yet supported")
			}
		} else if bech32Version == bech32.Version0 {
			// this might be Sapling? Check for the "z" HRP
			if humanReadablePrefix == network.saplingHRP {
				data, err := bech32.ConvertBits(bech32m_decoded_address, 5, 8, true)
				if err == nil {
					if len(data) == 43 {
						result.Sapling = new([43]byte)
						copy(result.Sapling[:], data)
						return result, nil
					} else {
						return result, errors.New("sapling address data must be 43 bytes")
					}
				} else {
					return result, err
				}
			}
		}
	}

	// attempt to decode as unified addresses
	unified, unifiedDecodedErr := unifiedaddress.DecodeUnified(address, network.unifiedHRP)
	if unifiedDecodedErr == nil {
		result.Unified = unified
		return result, nil
	}

	// if all decode attempts fail return the empty ZcashAddress and all errors
	return result, errors.Join(base58Error, bech32Error, unifiedDecodedErr)
}

// Convenience function for decoding transparent p2pkh addresses.
//
// This will decode the 20-byte payload of:
// * A base58-encoded p2pkh address
// * The p2pkh receiver of a Unified Address
// * If `allowTex == true`, a ZIP 320 TEX address
//
// or will return `nil` if the address does not contain a transparent public key hash.
func DecodeP2pkh(address string, network Network, allowTex bool) (*[20]byte, error) {
	decoded, err := DecodeAddress(address, network)
	if err != nil {
		return nil, err
	} else if decoded.P2pkh != nil {
		return decoded.P2pkh, nil
	} else if decoded.Unified != nil {
		return decoded.Unified.P2pkh, nil
	} else if decoded.Tex != nil && allowTex {
		return decoded.Tex, nil
	} else {
		return nil, nil
	}
}

// Convenience function for decoding transparent p2sh addresses.
//
// This will decode the 20-byte payload of:
// * A base58-encoded p2sh address
// * The p2sh receiver of a Unified Address
//
// or will return `nil` if the address does not contain a transparent script hash.
func DecodeP2sh(address string, network Network) (*[20]byte, error) {
	decoded, err := DecodeAddress(address, network)
	if err != nil {
		return nil, err
	} else if decoded.P2sh != nil {
		return decoded.P2sh, nil
	} else if decoded.Unified != nil {
		return decoded.Unified.P2sh, nil
	} else {
		return nil, nil
	}
}

// Convenience function for decoding Sapling addresses.
//
// This will decode the 43-byte payload of:
// * A bech32-encoded Sapling address
// * The Sapling receiver of a Unified Address
//
// or will return `nil` if the address does not contain a Sapling address.
func DecodeSapling(address string, network Network) (*[43]byte, error) {
	decoded, err := DecodeAddress(address, network)
	if err != nil {
		return nil, err
	} else if decoded.Sapling != nil {
		return decoded.Sapling, nil
	} else if decoded.Unified != nil {
		return decoded.Unified.Sapling, nil
	} else {
		return nil, nil
	}
}

// Convenience function for decoding Orchard addresses.
//
// This will decode the 43-byte payload of:
// * The Orchard receiver of a Unified Address
//
// or will return `nil` if the address is not a Unified address or does not contain
// an Orchard receiver.
func DecodeOrchard(address string, network Network) (*[43]byte, error) {
	decoded, err := DecodeAddress(address, network)
	if err != nil {
		return nil, err
	} else if decoded.Unified != nil {
		return decoded.Unified.Orchard, nil
	} else {
		return nil, nil
	}
}

// Convenience function for creating ZcashAddress from [20]byte P2pkh array
//
// this will return a ZcashAddress with the P2kh value added to payload
func P2pkh(data [20]byte) ZcashAddress {
	return ZcashAddress{
		P2pkh:   &data,
		P2sh:    nil,
		Sapling: nil,
		Unified: nil,
		Tex:     nil,
	}
}

// Convenience function for creating ZcashAddress from [20]byte P2sh array
//
// this will return a ZcashAddress with the P2sh value added to payload
func P2sh(data [20]byte) ZcashAddress {
	return ZcashAddress{
		P2pkh:   nil,
		P2sh:    &data,
		Sapling: nil,
		Unified: nil,
		Tex:     nil,
	}
}

// Convenience function for creating ZcashAddress from [43]byte Sapling array
//
// this will return a ZcashAddress with the Sapling value added to payload
func Sapling(data [43]byte) ZcashAddress {
	return ZcashAddress{
		P2pkh:   nil,
		P2sh:    nil,
		Sapling: &data,
		Unified: nil,
		Tex:     nil,
	}
}

// Convenience function for creating ZcashAddress from [20]byte Tex array
//
// this will return a ZcashAddress with the Tex value added to payload
func Tex(data [20]byte) ZcashAddress {
	return ZcashAddress{
		P2pkh:   nil,
		P2sh:    nil,
		Sapling: nil,
		Unified: nil,
		Tex:     &data,
	}
}

// Convenience function for creating ZcashAddress from an UnifiedAddress
//
// this will return a ZcashAddress with the UnifiedAddress value added to payload
func Unified(data unifiedaddress.UnifiedAddress) ZcashAddress {
	return ZcashAddress{
		P2pkh:   nil,
		P2sh:    nil,
		Sapling: nil,
		Unified: &data,
		Tex:     nil,
	}
}

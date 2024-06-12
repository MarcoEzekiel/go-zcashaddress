// package unifiedaddress
//
// Encodes and decodes Zcash Unified Addresses from their serialized string representations.
package unifiedaddress

import (
	"bytes"
	"errors"
	"fmt"

	"github.com/MarcoEzekiel/go-f4jumble"
	"github.com/MarcoEzekiel/go-zcashaddress/internal/compactsize"
	"github.com/btcsuite/btcd/btcutil/bech32"
)

type ItemType uint64

// breaking the sequential order of items NoPreviousItem is a max value for ordering checks
// in DecodeUnified()git
const (
	P2PKHItem      ItemType = 0x00
	P2SHItem       ItemType = 0x01
	SaplingItem    ItemType = 0x02
	OrchardItem    ItemType = 0x03
	NoPreviousItem ItemType = 0xffffffff
)

func getExpectedLength(itemType ItemType) uint64 {
	switch itemType {
	case P2PKHItem:
		return 20
	case P2SHItem:
		return 20
	case SaplingItem:
		return 43
	case OrchardItem:
		return 43
	default:
		return 0
	}
}

func getItemName(itemType ItemType) string {
	var itemName string

	switch itemType {
	case P2PKHItem, P2SHItem:
		itemName = "transparent"
	case SaplingItem:
		itemName = "sapling"
	case OrchardItem:
		itemName = "orchard"
	default:
		itemName = "unknown"
	}
	return itemName
}

func tlv(typecode uint64, value []byte) ([]byte, error) {
	start, err := compactsize.WriteCompactSize(typecode, true)
	if err != nil {
		return nil, err
	}

	simplified := uint64(len(value))
	st, err2 := compactsize.WriteCompactSize(simplified, true)
	if err2 != nil {
		return nil, err
	}

	return append(start, append(st, value...)...), nil
}

func padding(hrp string) []byte {
	hrpBytes := []byte(hrp)
	padLength := 16 - len(hrpBytes)
	if padLength < 0 {
		padLength = 0
	}
	return append(hrpBytes, bytes.Repeat([]byte{0x00}, padLength)...)
}

// A Zcash Unified Address.
//
// The `P2pkh` and `P2sh` fields of this structure are mutually exclusive; only one of these may be non-nil.
type UnifiedAddress struct {
	P2pkh   *[20]byte
	P2sh    *[20]byte
	Sapling *[43]byte
	Orchard *[43]byte
	Unknown map[uint64][]byte
}

// Encodes a UnifiedAddress to its string representation as defined in
// [ZIP 316].
//
// This function will return an error if the UnifiedAddress contains both
// P2pkh and P2sh receivers.
//
// [ZIP 316]: https://zips.z.cash/zip-0316#encoding-of-unified-addresses
func EncodeUnified(addr *UnifiedAddress, hrp string) (string, error) {
	if addr.P2pkh != nil && addr.P2sh != nil {
		return "", errors.New("both P2PKH and P2SH items found in unified address")
	}

	encodedItems := make([][]byte, 0)
	if addr.P2pkh != nil {
		tlvVal, err := tlv(uint64(P2PKHItem), addr.P2pkh[:])
		if err != nil {
			return "", err
		} else {
			encodedItems = append(encodedItems, tlvVal)
		}
	}
	if addr.P2sh != nil {
		tlvVal, err := tlv(uint64(P2SHItem), addr.P2sh[:])
		if err != nil {
			return "", err
		} else {
			encodedItems = append(encodedItems, tlvVal)
		}
	}
	if addr.Sapling != nil {
		tlvVal, err := tlv(uint64(SaplingItem), addr.Sapling[:])
		if err != nil {
			return "", err
		} else {
			encodedItems = append(encodedItems, tlvVal)
		}
	}
	if addr.Orchard != nil {
		tlvVal, err := tlv(uint64(OrchardItem), addr.Orchard[:])
		if err != nil {
			return "", err
		} else {
			encodedItems = append(encodedItems, tlvVal)
		}
	}
	for itemType, item := range addr.Unknown {
		if len(item) > 0 {
			tlvVal, err := tlv(uint64(itemType), item)
			if err != nil {
				return "", err
			} else {
				encodedItems = append(encodedItems, tlvVal)
			}
		}
	}
	encodedItems = append(encodedItems, padding(hrp))
	var rBytes []byte
	for _, item := range encodedItems {
		rBytes = append(rBytes, item...)
	}
	jumbledBytes, err := f4jumble.F4Jumble(rBytes)

	if err != nil {
		return "", err
	}

	converted, convertErr := bech32.ConvertBits(jumbledBytes, 8, 5, true)
	if convertErr != nil {
		return "", convertErr
	}
	encoded, encodeErr := bech32.EncodeM(hrp, converted)
	if encodeErr != nil {
		return "", encodeErr
	}
	return encoded, nil
}

// Decodes a UnifiedAddress from its string encoding as defined in
// [ZIP 316].
//
// This validates the encoded string against the provided expected human-readable
// part, and returns an error if an unexpected HRP is encountered or if
// the encoding is invalid.
//
// [ZIP 316]: https://zips.z.cash/zip-0316#encoding-of-unified-addresses
func DecodeUnified(encoded, expectedHrp string) (*UnifiedAddress, error) {

	hrp, data, version, encoding := bech32.DecodeNoLimitWithVersion(encoded)

	if version != bech32.VersionM {
		return nil, errors.New("unified addresses must be encoded with bech32m")
	}

	if hrp != expectedHrp || encoding != nil {
		return nil, errors.New("invalid HRP or encoding")
	}
	if len(data) < 48 {
		return nil, errors.New("invalid encoded data length")
	}
	convertedBits, convertedBitsErr := bech32.ConvertBits(data, 5, 8, false)
	if convertedBitsErr != nil {
		return nil, convertedBitsErr
	}

	decoded, decodedeErr := f4jumble.F4JumbleInv(convertedBits)
	if decodedeErr != nil {
		return nil, decodedeErr
	}

	suffix := decoded[len(decoded)-16:]
	if !bytes.Equal(suffix, padding(expectedHrp)) {
		return nil, errors.New("invalid trailing padding")
	}
	rest := decoded[:len(decoded)-16]

	receivers := make(map[uint64][]byte)
	// before we start define that we have not defined a "previous" item
	prevType := NoPreviousItem

	for len(rest) > 0 {
		itemType, remaining, e := compactsize.ParseCompactSize(rest, true)

		if e != nil {
			return nil, fmt.Errorf("error decoding item type %w", e)
		}

		itemLen, remaining, e2 := compactsize.ParseCompactSize(remaining, true)
		if e2 != nil {
			return nil, fmt.Errorf("error decoding item data %w", e2)
		}

		expectedLen := getExpectedLength(ItemType(itemType))

		if expectedLen > 0 && itemLen != expectedLen {
			return nil, fmt.Errorf("incorrect item length for typecode %d", itemType)
		}

		if len(remaining) < int(itemLen) {
			return nil, fmt.Errorf("insufficient data for receiver with typecode %d", itemType)
		}

		item := remaining[:itemLen]
		rest = remaining[itemLen:]

		//check for duplicate names
		if _, exists := receivers[itemType]; exists {
			return nil, fmt.Errorf("duplicate %s item detected", getItemName(ItemType(itemType)))
		}

		receivers[itemType] = item
		// check order of returns
		if prevType != NoPreviousItem && ItemType(itemType) <= prevType {
			return nil, errors.New("items out of order")
		}
		prevType = ItemType(itemType)
	}

	result := new(UnifiedAddress)
	result.Unknown = make(map[uint64][]byte)
	for itemType, data := range receivers {
		switch itemType {
		case uint64(P2PKHItem):
			result.P2pkh = new([20]byte)
			copy(result.P2pkh[:], data)
		case uint64(P2SHItem):
			result.P2sh = new([20]byte)
			copy(result.P2sh[:], data)
		case uint64(SaplingItem):
			result.Sapling = new([43]byte)
			copy(result.Sapling[:], data)
		case uint64(OrchardItem):
			result.Orchard = new([43]byte)
			copy(result.Orchard[:], data)
		default:
			result.Unknown[itemType] = data
		}
	}

	return result, nil
}

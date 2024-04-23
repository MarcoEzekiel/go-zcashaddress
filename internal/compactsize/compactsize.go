package compactsize

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"math"
)

const maxCompactSize = 0x2000000

func Convert_byte_to_hex(addr []byte) []string {
	var hexes []string
	for i := 0; i < len(addr); i++ {
		hex_val := fmt.Sprintf("%X", addr[i])
		hexes = append(hexes, "0x"+hex_val)
	}
	return hexes
}

// Writes a uint64 value as its CompactSize byte representation.
//
// If `allowOutOfRange` is true, this will allow the serialization of
// values greater than 0x2000000.
func WriteCompactSize(n uint64, allowOutOfRange bool) ([]byte, error) {
	if !allowOutOfRange && n > maxCompactSize {
		return nil, errors.New("number exceeds maximum compact size")
	}
	var buf bytes.Buffer
	if n < 253 {
		buf.WriteByte(byte(n))
	} else if n <= math.MaxUint16 {
		buf.WriteByte(253)
		binaryWrite(&buf, uint16(n))
	} else if n <= math.MaxUint32 {
		buf.WriteByte(254)
		binaryWrite(&buf, uint32(n))
	} else {
		buf.WriteByte(255)
		binaryWrite(&buf, n)
	}

	return buf.Bytes(), nil
}

// Reads a uint64 value from its CompactSize byte representation.
//
// If `allowOutOfRange` is true, this will allow the deserialization of
// values greater than 0x2000000; larger values will be reported as an
// error instead of being returned as a uint64.
func ParseCompactSize(rest []byte, allowOutOfRange bool) (uint64, []byte, error) {
	if len(rest) < 1 {
		return 0, nil, errors.New("invalid compact size encoding")
	}
	b := rest[0]
	var n uint64
	var err error
	switch b {

	case 253:
		if len(rest) < 3 {
			return 0, nil, errors.New("invalid compact size encoding")
		}
		n, rest = uint64(binaryReadUint16(rest[1:])), rest[3:]
	case 254:
		if len(rest) < 5 {
			return 0, nil, errors.New("invalid compact size encoding")
		}
		n, rest = uint64(binaryReadUint32(rest[1:])), rest[5:]
	case 255:
		if len(rest) < 9 {
			return 0, nil, errors.New("invalid compact size encoding")
		}
		n, rest = binaryReadUint64(rest[1:]), rest[9:]
	default:
		n, rest = uint64(b), rest[1:]
	}
	if !allowOutOfRange && n > maxCompactSize {
		return 0, nil, errors.New("number exceeds maximum compact size")
	}
	return n, rest, err
}

func binaryWrite(buf *bytes.Buffer, n interface{}) {
	_ = binary.Write(buf, binary.LittleEndian, n)
}

func binaryReadUint16(b []byte) uint16 {
	return binary.LittleEndian.Uint16(b)
}

func binaryReadUint32(b []byte) uint32 {
	return binary.LittleEndian.Uint32(b)
}

func binaryReadUint64(b []byte) uint64 {
	return binary.LittleEndian.Uint64(b)
}

package compactsize

import (
	"fmt"
	"testing"
)

func TestCompactSize(t *testing.T) {
	allowU64 := false

	for _, n := range []uint64{0, 1, 252, 253, 254, 255, 256, 0xFFFE, 0xFFFF, 0x010000, 0x010001, 0x02000000} {
		encoding, err := WriteCompactSize(n, allowU64)

		if err != nil {
			t.Error(err)
		}
		_, remaining, err := ParseCompactSize(encoding, allowU64)

		if err != nil {
			t.Error(err)
		}
		if len(remaining) != 0 {
			t.Error("parseCompactSize did not consume entire encoding")
		}
		fmt.Println("")
	}

	assertParseFails([]byte{0xFE, 0x01, 0x00, 0x00, 0x02}, false)
	assertParseFails([]byte{0xFF, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00}, false)
	assertParseFails([]byte{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}, false)

	allowU64 = true
	for _, n := range []uint64{0xFFFFFFFE, 0xFFFFFFFF, 0x0100000000, 0xFFFFFFFFFFFFFFFF} {
		encoding, err := WriteCompactSize(n, allowU64)
		if err != nil {
			t.Error(err)
		}
		_, remaining, err := ParseCompactSize(encoding, allowU64)
		if err != nil {
			t.Error(err)
		}
		if len(remaining) != 0 {
			t.Error("parseCompactSize did not consume entire encoding")
		}
	}
}

func assertParseFails(encoding []byte, allowU64 bool) {
	_, _, err := ParseCompactSize(encoding, allowU64)
	if err == nil {
		panic(fmt.Sprintf("parseCompactSize(%v) failed to return an error", encoding))
	}
}

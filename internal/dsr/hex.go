package dsr

import (
	"encoding/hex"
	"fmt"
)

// HexBytes is a hex-encoded byte slice. Used for bundle manifest signatures.
// JSON marshal/unmarshal converts between hex strings and []byte transparently.
type HexBytes []byte

func (h HexBytes) MarshalJSON() ([]byte, error) {
	return []byte(`"` + hex.EncodeToString(h) + `"`), nil
}

func (h *HexBytes) UnmarshalJSON(data []byte) error {
	if len(data) < 2 || data[0] != '"' || data[len(data)-1] != '"' {
		return fmt.Errorf("HexBytes: expected JSON string")
	}
	b, err := hex.DecodeString(string(data[1 : len(data)-1]))
	if err != nil {
		return fmt.Errorf("HexBytes: invalid hex: %w", err)
	}
	*h = HexBytes(b)
	return nil
}

func hexDecode(s string) ([]byte, error) {
	b, err := hex.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("invalid hex string: %w", err)
	}
	return b, nil
}

func hexEncode(b []byte) string {
	return hex.EncodeToString(b)
}

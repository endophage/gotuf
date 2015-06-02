package data

import (
	"encoding/json"

	cjson "github.com/tent/canonical-json-go"
)

type SignedSnapshot struct {
	Signatures []Signature
	Signed     Snapshot
}

type Snapshot struct {
	Type    string `json:"_type"`
	Version int    `json:"version"`
	Expires string `json:"expires"`
	Meta    Files  `json:"meta"`
}

func (sp *Snapshot) hashForRole(role string) HexBytes {
	return sp.Meta[role].Hashes["sha256"]
}

func (sp SignedSnapshot) ToSigned() (*Signed, error) {
	s, err := cjson.Marshal(sp.Signed)
	if err != nil {
		return nil, err
	}
	signed := json.RawMessage{}
	err = signed.UnmarshalJSON(s)
	if err != nil {
		return nil, err
	}
	sigs := make([]Signature, len(sp.Signatures))
	copy(sigs, sp.Signatures)
	return &Signed{
		Signatures: sigs,
		Signed:     signed,
	}, nil
}

func SnapshotFromSigned(s *Signed) (*SignedSnapshot, error) {
	sp := Snapshot{}
	err := json.Unmarshal(s.Signed, &sp)
	if err != nil {
		return nil, err
	}
	sigs := make([]Signature, len(s.Signatures))
	copy(sigs, s.Signatures)
	return &SignedSnapshot{
		Signatures: sigs,
		Signed:     sp,
	}, nil
}

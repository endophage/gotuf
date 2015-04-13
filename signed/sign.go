package signed

import (
	"github.com/endophage/go-tuf/Godeps/_workspace/src/github.com/agl/ed25519"
	cjson "github.com/endophage/go-tuf/Godeps/_workspace/src/github.com/tent/canonical-json-go"

	"github.com/endophage/go-tuf/data"
	"github.com/endophage/go-tuf/keys"
)

// Sign takes a data.Signed and a key, calculated and adds the signature
// to the data.Signed
//func Sign(s *data.Signed, k *data.Key) {
//	id := k.ID()
//	signatures := make([]data.Signature, 0, len(s.Signatures)+1)
//	for _, sig := range s.Signatures {
//		if sig.KeyID == id {
//			continue
//		}
//		signatures = append(signatures, sig)
//	}
//	priv := [ed25519.PrivateKeySize]byte{}
//	copy(priv[:], k.Value.Private)
//	sig := ed25519.Sign(&priv, s.Signed)
//	s.Signatures = append(signatures, data.Signature{
//		KeyID:     id,
//		Method:    "ed25519",
//		Signature: sig[:],
//	})
//}

// Signer encapsulates a signing service with some convenience methods to
// interface between TUF keys and the generic service interface
type Signer struct {
	service TrustService
}

// Sign takes a data.Signed and a key, calculated and adds the signature
// to the data.Signed
func (signer *Signer) Sign(s *data.Signed, keys ...*keys.PublicKey) {
	signatures := make([]data.Signature, 0, len(s.Signatures)+1)
	keyIDMemb = make(map[string]struct{})
	keyIDs = make([]string, 0, len(keys))
	for _, key := range keys {
		keyIDMemb[key.ID] = struct{}{}
	}
	for _, sig := range s.Signatures {
		if _, ok := keyIDMemb[sig.KeyID]; ok {
			continue
		}
		signatures = append(signatures, sig)
	}
	newSigs := signer.service.Sign(keyIDs, s.Signed)
	s.Signatures = append(signatures, newSigs...)
}

func (signer *Signer) Marshal(v interface{}, keys ...*keys.PublicKey) (*data.Signed, error) {
	b, err := cjson.Marshal(v)
	if err != nil {
		return nil, err
	}
	s := &data.Signed{Signed: b}
	Sign(s, keys...)
	return s, nil
}

func (signer *Signer) NewKey(keyType string) (keys.PublicKey, error) {
	return signer.service.Create(keyType)
}

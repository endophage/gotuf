package keys

import (
	"errors"

	"github.com/agl/ed25519"
	"github.com/miekg/pkcs11"
)

var (
	// ErrExists happens when a Key already exists in a database
	ErrExists = errors.New("rufus: key already in db")
	// ErrInvalidKeyID error happens when a key isn't found
	ErrInvalidKeyID = errors.New("rufus: invalid key id")
	// ErrFailedKeyGeneration happens when there is a failure in generating a key
	ErrFailedKeyGeneration = errors.New("rufus: failed to generate new key")
)

// Key represents all the information of a key, including the private and public bits
type Key struct {
	ID      string
	Type    string
	Public  [ed25519.PublicKeySize]byte
	Private *[ed25519.PrivateKeySize]byte
}

// Serialize returns the public key bits
func (k *Key) Serialize() *JSONKey {
	return &JSONKey{
		Type:   k.Type,
		ID:     k.ID,
		Public: k.Public[:],
	}
}

// HSMRSAKey represents the information for an HSMRSAKey with ObjectHandle for private portion
type HSMRSAKey struct {
	ID      string
	Type    string
	Public  []byte
	Private pkcs11.ObjectHandle
}

// Serialize returns the public key bits
func (k *HSMRSAKey) Serialize() *JSONKey {
	return &JSONKey{
		Type:   k.Type,
		ID:     k.ID,
		Public: k.Public,
	}
}

// JSONKey maps a key's public key bits to a json representation
type JSONKey struct {
	ID     string   `json:"id"`
	Type   string   `json:"type"`
	Public HexBytes `json:"public"`
}

// Signature gives a json representation for a signed blob
type Signature struct {
	KeyID     string   `json:"keyid"`
	Signature HexBytes `json:"signature"`
}

// SigningRequest represents the json that comes when a signing request is made
type SigningRequest struct {
	Blob HexBytes `json:"blob"`
}

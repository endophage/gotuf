package keys

import (
	"crypto/rand"
	"errors"

	"github.com/endophage/go-tuf/Godeps/_workspace/src/github.com/agl/ed25519"
	cjson "github.com/endophage/go-tuf/Godeps/_workspace/src/github.com/tent/canonical-json-go"
	"github.com/endophage/go-tuf/data"
)

var (
	ErrWrongType        = errors.New("tuf: invalid key type")
	ErrExists           = errors.New("tuf: key already in db")
	ErrWrongID          = errors.New("tuf: key id mismatch")
	ErrInvalidKey       = errors.New("tuf: invalid key")
	ErrInvalidRole      = errors.New("tuf: invalid role")
	ErrInvalidKeyID     = errors.New("tuf: invalid key id")
	ErrInvalidThreshold = errors.New("tuf: invalid role threshold")
)

type KeyValue struct {
	Public HexBytes `json:"public"`
	//	Private HexBytes `json:"private,omitempty"`
}

type Key struct {
	Type  string   `json:"keytype"`
	Value KeyValue `json:"keyval"`
}

func (k *Key) ID() string {
	// create a copy so the private key is not included
	data, _ := cjson.Marshal(&Key{
		Type:  k.Type,
		Value: KeyValue{Public: k.Value.Public},
	})
	digest := sha256.Sum256(data)
	return hex.EncodeToString(digest[:])
}

type PublicKey struct {
	Key
	ID string
}

func NewPublicKey(keyType string, public []byte) *PublicKey {
	// create a copy so the private key is not included
	key := Key{
		Type:  keyType,
		Value: KeyValue{Public: k.Value.Public},
	}
	return &PublicKey{key, key.ID()}
}

type Role struct {
	KeyIDs    map[string]struct{}
	Threshold int
}

func (r *Role) ValidKey(id string) bool {
	_, ok := r.KeyIDs[id]
	return ok
}

type DB struct {
	roles map[string]*Role
	keys  map[string]*PublicKey
}

func NewDB() *DB {
	return &DB{
		roles: make(map[string]*Role),
		keys:  make(map[string]*PublicKey),
	}
}

func (db *DB) AddKey(k *PublicKey) error {
	if _, ok := db.Types[k.Type]; !ok {
		return ErrWrongType
	}
	//if len(k.Value.Public) != ed25519.PublicKeySize {
	//	return ErrInvalidKey
	//}

	var key PublicKey
	copy(key.Value.Public[:], k.Value.Public)
	key.ID = k.ID
	db.keys[key.ID] = &key
	return nil
}

var validRoles = map[string]struct{}{
	"root":      {},
	"targets":   {},
	"snapshot":  {},
	"timestamp": {},
}

func ValidRole(name string) bool {
	_, ok := validRoles[name]
	return ok
}

func (db *DB) AddRole(name string, r *data.Role) error {
	if !ValidRole(name) {
		return ErrInvalidRole
	}
	if r.Threshold < 1 {
		return ErrInvalidThreshold
	}

	role := &Role{
		KeyIDs:    make(map[string]struct{}),
		Threshold: r.Threshold,
	}
	for _, id := range r.KeyIDs {
		if len(id) != data.KeyIDLength {
			return ErrInvalidKeyID
		}
		role.KeyIDs[id] = struct{}{}
	}

	db.roles[name] = role
	return nil
}

func (db *DB) GetKey(id string) *Key {
	return db.keys[id]
}

func (db *DB) GetRole(name string) *Role {
	return db.roles[name]
}

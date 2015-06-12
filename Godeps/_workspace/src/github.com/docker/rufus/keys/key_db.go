package keys

// KeyDB represents an in-memory key keystore
type KeyDB struct {
	keys map[string]*Key
}

// CreateKey is needed to implement KeyManager. Returns an empty key.
func (db *KeyDB) CreateKey() (*JSONKey, error) {
	k := &Key{}

	return k.Serialize(), nil

}

// AddKey Adds a new key to the database
func (db *KeyDB) AddKey(key *Key) error {
	if _, ok := db.keys[key.ID]; ok {
		return ErrExists
	}
	db.keys[key.ID] = key
	return nil
}

// GetKey returns the private bits of a key
func (db *KeyDB) GetKey(keyID string) (*Key, error) {
	if key, ok := db.keys[keyID]; ok {
		return key, nil
	}
	return nil, ErrInvalidKeyID
}

// DeleteKey deletes the keyID from the database
func (db *KeyDB) DeleteKey(keyID string) error {
	_, err := db.GetKey(keyID)
	if err != nil {
		return err
	}
	delete(db.keys, keyID)
	return nil
}

// KeyInfo returns the public bits of a key, given a specific keyID
func (db *KeyDB) KeyInfo(keyID string) (*JSONKey, error) {
	key, err := db.GetKey(keyID)
	if err != nil {
		return nil, err
	}
	return key.Serialize(), nil
}

// NewKeyDB returns an instance of KeyDB
func NewKeyDB() *KeyDB {
	return &KeyDB{
		keys: make(map[string]*Key),
	}
}

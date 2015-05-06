package store

import (
	"encoding/json"

	"github.com/endophage/go-tuf/data"
)

type targetsWalkFunc func(path string, meta data.FileMeta) error

type MetadataStore interface {
	GetMeta() (map[string]json.RawMessage, error)
	SetMeta(name string, blob json.RawMessage) error
}

type KeyStore interface {
	GetKeys(role string) ([]*data.Key, error)
	SaveKey(role string, key *data.Key) error
}

type TargetStore interface {
	WalkStagedTargets(paths []string, targetsFn targetsWalkFunc) error
}

type LocalStore interface {
	MetadataStore
	KeyStore
	TargetStore
	Clean() error
	Commit(meta map[string]json.RawMessage, consistentSnapshot bool, hashes map[string]data.Hashes) error
}

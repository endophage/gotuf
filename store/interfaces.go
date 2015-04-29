package store

import (
	"encoding/json"

	"github.com/endophage/go-tuf/data"
)

type targetsWalkFunc func(path string, meta data.FileMeta) error

type MetadataStore interface {
	GetMeta() (map[string]json.RawMessage, error)
	SetMeta(string, json.RawMessage) error
}

type KeyStore interface {
	GetKeys(string) ([]*data.Key, error)
	SaveKey(string, *data.Key) error
}

type TargetStore interface {
	WalkStagedTargets(paths []string, targetsFn targetsWalkFunc) error
}

type LocalStore interface {
	MetadataStore
	KeyStore
	TargetStore
	Clean() error
	Commit(map[string]json.RawMessage, bool, map[string]data.Hashes) error
}

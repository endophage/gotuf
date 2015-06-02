package store

import (
	"encoding/json"
	"io"

	"github.com/endophage/gotuf/data"
)

type targetsWalkFunc func(path string, meta data.FileMeta) error

type MetadataStore interface {
	GetMeta(name string, size int64) (json.RawMessage, error)
	SetMeta(name string, blob json.RawMessage) error
}

// These functions should be handled by the keyDB or signer
//type KeyStore interface {
//	GetKeys(role string) ([]*data.Key, error)
//	SaveKey(role string, key *data.Key) error
//}

type TargetStore interface {
	WalkStagedTargets(paths []string, targetsFn targetsWalkFunc) error
}

type LocalStore interface {
	MetadataStore
	//	KeyStore
	TargetStore
	Clean() error
	Commit(meta map[string]json.RawMessage, consistentSnapshot bool, hashes map[string]data.Hashes) error
}

type RemoteStore interface {
	MetadataStore
	GetTarget(path string) (io.ReadCloser, error)
}

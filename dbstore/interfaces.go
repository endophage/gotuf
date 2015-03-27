package dbstore

import (
	"encoding/json"

	"github.com/endophage/go-tuf/data"
)

type TargetsWalkFunc func(path string, meta data.FileMeta) error

type LocalStore interface {
	GetMeta() (map[string]json.RawMessage, error)
	SetMeta(string, json.RawMessage) error

	// WalkStagedTargets calls targetsFn for each staged target file in paths.
	//
	// If paths is empty, all staged target files will be walked.
	WalkStagedTargets(paths []string, targetsFn TargetsWalkFunc) error

	Commit(map[string]json.RawMessage, bool, map[string]data.Hashes) error
	GetKeys(string) ([]*data.Key, error)
	SaveKey(string, *data.Key) error
	Clean() error
}

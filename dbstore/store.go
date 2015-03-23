package dbstore

import (
	"encoding/json"
	"fmt"

	//	"code.google.com/p/go-sqlite/go1/sqlite3"
	"github.com/endophage/go-tuf/data"
)

const (
	connString  string = ":inmemory:"
	objectTable string = "objects"
	repoTable   string = "repositories"
	keysTable   string = "keys"
)

type targetsWalkFunc func(string, data.FileMeta) error

type LocalStore interface {
	GetMeta() (map[string]json.RawMessage, error)
	SetMeta(string, json.RawMessage) error

	// WalkStagedTargets calls targetsFn for each staged target file in paths.
	//
	// If paths is empty, all staged target files will be walked.
	WalkStagedTargets(paths []string, targetsFn targetsWalkFunc) error

	Commit(map[string]json.RawMessage, bool, map[string]data.Hashes) error
	GetKeys(string) ([]*data.Key, error)
	SaveKey(string, *data.Key) error
	Clean() error
}

// implements LocalStore
type dbStore struct {
	//	db    sqlite3.Conn
	meta  map[string]json.RawMessage
	files map[string]data.FileMeta
	keys  map[string][]*data.Key
}

func DBStore(meta map[string]json.RawMessage, files map[string]data.FileMeta) LocalStore {
	if meta == nil {
		meta = make(map[string]json.RawMessage)
	}
	return &dbStore{
		//		db:    sqlite3.Open(connString),
		meta:  meta,
		files: files,
		keys:  make(map[string][]*data.Key),
	}
}

func (m *dbStore) GetMeta() (map[string]json.RawMessage, error) {
	return m.meta, nil
}

func (m *dbStore) SetMeta(name string, meta json.RawMessage) error {
	m.meta[name] = meta
	return nil
}

func (m *dbStore) WalkStagedTargets(paths []string, targetsFn targetsWalkFunc) error {
	if len(paths) == 0 {
		for path, meta := range m.files {
			if err := targetsFn(path, meta); err != nil {
				return err
			}
		}
		return nil
	}

	for _, path := range paths {
		meta, ok := m.files[path]
		if !ok {
			return fmt.Errorf("File Not Found")
		}
		if err := targetsFn(path, meta); err != nil {
			return err
		}
	}
	return nil
}

func (m *dbStore) Commit(map[string]json.RawMessage, bool, map[string]data.Hashes) error {
	// TODO (endophage): write meta files to cache
	return nil
}

func (m *dbStore) GetKeys(role string) ([]*data.Key, error) {
	return m.keys[role], nil
}

func (m *dbStore) SaveKey(role string, key *data.Key) error {
	if _, ok := m.keys[role]; !ok {
		m.keys[role] = make([]*data.Key, 0)
	}
	m.keys[role] = append(m.keys[role], key)
	return nil
}

func (m *dbStore) Clean() error {
	// TODO (endophage): purge stale items from db? May just/also need a remove method
	return nil
}

func (m *dbStore) AddObject(path string, meta data.FileMeta) {
	m.files[path] = meta
}

func (m *dbStore) RemoveObject(path string) {
	delete(m.files, path)
}

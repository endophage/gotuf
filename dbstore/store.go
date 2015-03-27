package dbstore

import (
	"encoding/hex"
	"encoding/json"
	"fmt"

	"code.google.com/p/go-sqlite/go1/sqlite3"
	"github.com/endophage/go-tuf/data"
)

const (
	tufLoc      string = "/tmp/tuf"
	connString  string = "/Users/david/gopath/src/github.com/endophage/go-tuf/db/files.db"
	objectTable string = "objects"
	repoTable   string = "repositories"
	keysTable   string = "keys"
)

// implements LocalStore
type dbStore struct {
	db    *sqlite3.Conn
	meta  map[string]json.RawMessage
	files map[string]data.FileMeta
	keys  map[string][]*data.Key
}

func DBStore(meta map[string]json.RawMessage) *dbStore {
	if meta == nil {
		meta = make(map[string]json.RawMessage)
	}
	conn, err := sqlite3.Open(connString)
	if err != nil {
		panic("can't connect to db")
	}
	store := dbStore{
		db:    conn,
		meta:  meta,
		files: make(map[string]data.FileMeta),
		keys:  make(map[string][]*data.Key),
	}

	return &store
}

// GetMeta loads existing TUF metadata files
func (m *dbStore) GetMeta() (map[string]json.RawMessage, error) {
	return m.meta, nil
}

// SetMeta writes individual TUF metadata files
func (m *dbStore) SetMeta(name string, meta json.RawMessage) error {
	m.meta[name] = meta
	return nil
}

// WalkStagedTargets walks all targets in scope
func (m *dbStore) WalkStagedTargets(paths []string, targetsFn TargetsWalkFunc) error {
	if len(paths) == 0 {
		files := m.loadFiles("")
		for path, meta := range files {
			if err := targetsFn(path, meta); err != nil {
				return err
			}
		}
		return nil
	}

	for _, path := range paths {
		files := m.loadFiles(path)
		meta, ok := files[path]
		if !ok {
			return fmt.Errorf("File Not Found")
		}
		if err := targetsFn(path, meta); err != nil {
			return err
		}
	}
	return nil
}

// Commit writes a set of consistent (possibly) TUF metadata files
func (m *dbStore) Commit(metafiles map[string]json.RawMessage, consistent bool, hashes map[string]data.Hashes) error {
	// TODO (endophage): write meta files to cache
	return nil

}

// GetKeys returns private keys
func (m *dbStore) GetKeys(role string) ([]*data.Key, error) {
	return m.keys[role], nil
}

// SaveKey saves a new private key
func (m *dbStore) SaveKey(role string, key *data.Key) error {
	if _, ok := m.keys[role]; !ok {
		m.keys[role] = make([]*data.Key, 0)
	}
	m.keys[role] = append(m.keys[role], key)
	return nil
}

// Clean removes staged targets
func (m *dbStore) Clean() error {
	// TODO (endophage): purge stale items from db? May just/also need a remove method
	return nil
}

// AddBlob adds an object to the store
func (m *dbStore) AddBlob(path string, meta data.FileMeta) {
	jsonbytes := []byte{}
	if meta.Custom != nil {
		jsonbytes, _ = meta.Custom.MarshalJSON()
	}
	hashStr := hex.EncodeToString(meta.Hashes["sha256"]) // .([]byte)
	err := m.db.Exec("INSERT INTO `filemeta` VALUES (?,?,?,?);", path, hashStr, meta.Length, jsonbytes)
	if err != nil {
		fmt.Println(err)
	}
}

// RemoveBlob removes an object from the store
func (m *dbStore) RemoveBlob(path string) error {
	return m.db.Exec("DELETE FROM `filemeta` WHERE `path`=?", path)
}

func (m *dbStore) loadFiles(path string) map[string]data.FileMeta {
	var err error
	var r *sqlite3.Stmt
	files := make(map[string]data.FileMeta)
	sql := "SELECT * FROM `filemeta`"
	if path != "" {
		sql = fmt.Sprintf("%s %s", sql, "WHERE `path`=?")
		r, err = m.db.Query(sql, path)
	} else {
		r, err = m.db.Query(sql)
	}
	var file data.FileMeta
	for ; err == nil; err = r.Next() {
		var path string
		var hash string
		var custom json.RawMessage
		var size int64
		r.Scan(&path, &hash, &size, &custom)
		hashBytes, err := hex.DecodeString(hash)
		if err != nil {
			fmt.Println("didn't get hex hash")
		}
		file = data.FileMeta{
			Length: size,
			Hashes: data.Hashes{
				"sha256": hashBytes,
				"sha512": hashBytes,
			},
		}
		if custom != nil {
			file.Custom = &custom
		}
		files[path] = file
	}
	return files
}

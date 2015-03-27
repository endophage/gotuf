package store

import (
	"encoding/hex"
	"encoding/json"
	"fmt"

	"code.google.com/p/go-sqlite/go1/sqlite3"
	"github.com/endophage/go-tuf/data"
)

const (
	tufLoc      string = "/tmp/tuf"
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

func DBStore(db *sqlite3.Conn, meta map[string]json.RawMessage) *dbStore {
	if meta == nil {
		meta = make(map[string]json.RawMessage)
	}
	store := dbStore{
		db:    db,
		meta:  meta,
		files: make(map[string]data.FileMeta),
		keys:  make(map[string][]*data.Key),
	}

	return &store
}

// GetMeta loads existing TUF metadata files
func (dbs *dbStore) GetMeta() (map[string]json.RawMessage, error) {
	return dbs.meta, nil
}

// SetMeta writes individual TUF metadata files
func (dbs *dbStore) SetMeta(name string, meta json.RawMessage) error {
	dbs.meta[name] = meta
	return nil
}

// WalkStagedTargets walks all targets in scope
func (dbs *dbStore) WalkStagedTargets(paths []string, targetsFn targetsWalkFunc) error {
	if len(paths) == 0 {
		files := dbs.loadFiles("")
		for path, meta := range files {
			if err := targetsFn(path, meta); err != nil {
				return err
			}
		}
		return nil
	}

	for _, path := range paths {
		files := dbs.loadFiles(path)
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
func (dbs *dbStore) Commit(metafiles map[string]json.RawMessage, consistent bool, hashes map[string]data.Hashes) error {
	// TODO (endophage): write meta files to cache
	return nil

}

// GetKeys returns private keys
func (dbs *dbStore) GetKeys(role string) ([]*data.Key, error) {
	return dbs.keys[role], nil
}

// SaveKey saves a new private key
func (dbs *dbStore) SaveKey(role string, key *data.Key) error {
	if _, ok := dbs.keys[role]; !ok {
		dbs.keys[role] = make([]*data.Key, 0)
	}
	dbs.keys[role] = append(dbs.keys[role], key)
	return nil
}

// Clean removes staged targets
func (dbs *dbStore) Clean() error {
	// TODO (endophage): purge stale items from db? May just/also need a remove method
	return nil
}

// AddBlob adds an object to the store
func (dbs *dbStore) AddBlob(path string, meta data.FileMeta) {
	jsonbytes := []byte{}
	if meta.Custom != nil {
		jsonbytes, _ = meta.Custom.MarshalJSON()
	}
	sha256Str := hex.EncodeToString(meta.Hashes["sha256"])
	sha512Str := hex.EncodeToString(meta.Hashes["sha512"])
	err := dbs.db.Exec("INSERT INTO `filemeta` VALUES (?,?,?,?,?);", path, sha256Str, sha512Str, meta.Length, jsonbytes)
	if err != nil {
		fmt.Println(err)
	}
}

// RemoveBlob removes an object from the store
func (dbs *dbStore) RemoveBlob(path string) error {
	return dbs.db.Exec("DELETE FROM `filemeta` WHERE `path`=?", path)
}

func (dbs *dbStore) loadFiles(path string) map[string]data.FileMeta {
	var err error
	var r *sqlite3.Stmt
	files := make(map[string]data.FileMeta)
	sql := "SELECT * FROM `filemeta`"
	if path != "" {
		sql = fmt.Sprintf("%s %s", sql, "WHERE `path`=?")
		r, err = dbs.db.Query(sql, path)
	} else {
		r, err = dbs.db.Query(sql)
	}
	var file data.FileMeta
	for ; err == nil; err = r.Next() {
		var path string
		var sha256 string
		var sha512 string
		var custom json.RawMessage
		var size int64
		r.Scan(&path, &sha256, &sha512, &size, &custom)
		sha256Bytes, err := hex.DecodeString(sha256)
		sha512Bytes, err := hex.DecodeString(sha512)
		if err != nil {
			fmt.Println("didn't get hex hash")
		}
		file = data.FileMeta{
			Length: size,
			Hashes: data.Hashes{
				"sha256": sha256Bytes,
				"sha512": sha512Bytes,
			},
		}
		if custom != nil {
			file.Custom = &custom
		}
		files[path] = file
	}
	return files
}

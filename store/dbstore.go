package store

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"path"

	"code.google.com/p/go-sqlite/go1/sqlite3"
	"github.com/docker/go-tuf/data"
)

const (
	tufLoc      string = "/tmp/tuf"
	objectTable string = "objects"
	repoTable   string = "repositories"
	keysTable   string = "keys"
)

// implements LocalStore
type dbStore struct {
	db        *sqlite3.Conn
	imageName string
	meta      map[string]json.RawMessage
	keys      map[string][]*data.Key
}

func DBStore(db *sqlite3.Conn, imageName string, keys map[string][]*data.Key) *dbStore {
	store := dbStore{
		db:        db,
		imageName: imageName,
		keys:      keys,
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
func (dbs *dbStore) WalkStagedTargets(relPaths []string, targetsFn targetsWalkFunc) error {
	if len(relPaths) == 0 {
		files := dbs.loadFiles("")
		for absPath, meta := range files {
			if err := targetsFn(absPath, meta); err != nil {
				return err
			}
		}
		return nil
	}

	for _, relPath := range relPaths {
		absPath := dbs.absPath(relPath)
		fmt.Println(absPath)
		files := dbs.loadFiles(absPath)
		meta, ok := files[absPath]
		if !ok {
			return fmt.Errorf("File Not Found")
		}
		if err := targetsFn(absPath, meta); err != nil {
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
func (dbs *dbStore) AddBlob(relPath string, meta data.FileMeta) {
	jsonbytes := []byte{}
	if meta.Custom != nil {
		jsonbytes, _ = meta.Custom.MarshalJSON()
	}
	absPath := dbs.absPath(relPath)

	err := dbs.db.Exec("INSERT OR REPLACE INTO `filemeta` VALUES (?,?,?);", absPath, meta.Length, jsonbytes)
	if err != nil {
		fmt.Println(err)
	}
	dbs.addBlobHashes(absPath, meta.Hashes)
}

func (dbs *dbStore) addBlobHashes(absPath string, hashes data.Hashes) {
	sql := "INSERT OR REPLACE INTO `filehashes` VALUES (?,?,?);"
	var err error
	for alg, hash := range hashes {
		err = dbs.db.Exec(sql, absPath, alg, hex.EncodeToString(hash))
		if err != nil {
			fmt.Println(err)
		}
	}
}

// RemoveBlob removes an object from the store
func (dbs *dbStore) RemoveBlob(relPath string) error {
	absPath := dbs.absPath(relPath)
	return dbs.db.Exec("DELETE FROM `filemeta` WHERE `path`=?", absPath)
}

func (dbs *dbStore) loadFiles(absPath string) map[string]data.FileMeta {
	var err error
	var r *sqlite3.Stmt
	files := make(map[string]data.FileMeta)
	sql := "SELECT `filemeta`.`path`, `size`, `alg`, `hash`, `custom` FROM `filemeta` JOIN `filehashes` ON `filemeta`.`path` = `filehashes`.`path`"
	if absPath != "" {
		sql = fmt.Sprintf("%s %s", sql, "WHERE `filemeta`.`path`=?")
		r, err = dbs.db.Query(sql, absPath)
	} else {
		r, err = dbs.db.Query(sql)
	}
	for ; err == nil; err = r.Next() {
		var absPath string
		var size int64
		var custom json.RawMessage
		var alg string
		var hash string
		r.Scan(&absPath, &size, &alg, &hash, &custom)
		hashBytes, err := hex.DecodeString(hash)
		if err != nil {
			// We're going to skip items with unparseable hashes as they
			// won't be valid in the targets.json
			fmt.Println("Hash was not stored in hex as expected")
			continue
		}
		if file, ok := files[absPath]; ok {
			file.Hashes[alg] = hashBytes
		} else {
			file = data.FileMeta{
				Length: size,
				Hashes: data.Hashes{
					alg: hashBytes,
				},
			}
			if custom != nil {
				file.Custom = &custom
			}
			files[absPath] = file
		}
	}
	return files
}

func (dbs *dbStore) absPath(relPath string) string {
	return path.Join(dbs.imageName, relPath)
}

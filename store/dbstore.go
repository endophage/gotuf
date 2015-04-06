package store

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"path"
	"strings"

	"code.google.com/p/go-sqlite/go1/sqlite3"
	"github.com/docker/go-tuf/data"
)

const (
	tufLoc string = "/tmp/tuf"
)

// implements LocalStore
type dbStore struct {
	db        *sqlite3.Conn
	imageName string
}

func DBStore(db *sqlite3.Conn, imageName string) *dbStore {
	store := dbStore{
		db:        db,
		imageName: imageName,
	}

	return &store
}

// GetMeta loads existing TUF metadata files
func (dbs *dbStore) GetMeta() (map[string]json.RawMessage, error) {
	metadataDir := path.Join(tufLoc, dbs.imageName)
	var err error
	meta := make(map[string]json.RawMessage)
	files, err := ioutil.ReadDir(metadataDir)
	if err != nil {
		if _, ok := err.(*os.PathError); ok {
			return meta, nil
		}
		return nil, err
	}
	for _, file := range files {
		if strings.HasSuffix(file.Name(), ".json") {
			data, err := dbs.readFile(file.Name())
			if err != nil {
				continue
			}
			meta[file.Name()] = json.RawMessage(data)
		}
	}
	return meta, err
}

// SetMeta writes individual TUF metadata files
func (dbs *dbStore) SetMeta(name string, meta json.RawMessage) error {
	return dbs.writeFile(name, meta)
}

// WalkStagedTargets walks all targets in scope
func (dbs *dbStore) WalkStagedTargets(paths []string, targetsFn targetsWalkFunc) error {
	if len(paths) == 0 {
		files := dbs.loadTargets("")
		for path, meta := range files {
			if err := targetsFn(path, meta); err != nil {
				return err
			}
		}
		return nil
	}

	for _, path := range paths {
		files := dbs.loadTargets(path)
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
	keys := []*data.Key{}
	var err error
	var r *sqlite3.Stmt
	sql := "SELECT `key` FROM `keys` WHERE `role` = ? AND `namespace` = ?;"
	r, err = dbs.db.Query(sql, role, dbs.imageName)
	for ; err == nil; err = r.Next() {
		var jsonStr string
		key := data.Key{}
		r.Scan(&jsonStr)
		err := json.Unmarshal([]byte(jsonStr), &key)
		if err != nil {
			return nil, err
		}
		keys = append(keys, &key)
	}
	return keys, nil
}

// SaveKey saves a new private key
func (dbs *dbStore) SaveKey(role string, key *data.Key) error {
	jsonBytes, err := json.Marshal(key)
	if err != nil {
		return fmt.Errorf("Could not JSON Marshal Key")
	}
	return dbs.db.Exec("INSERT INTO `keys` (`namespace`, `role`, `key`) VALUES (?,?,?);", dbs.imageName, role, string(jsonBytes))
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

	err := dbs.db.Exec("INSERT OR REPLACE INTO `filemeta` VALUES (?,?,?,?);", dbs.imageName, path, meta.Length, jsonbytes)
	if err != nil {
		fmt.Println(err)
	}
	dbs.addBlobHashes(path, meta.Hashes)
}

func (dbs *dbStore) addBlobHashes(path string, hashes data.Hashes) {
	sql := "INSERT OR REPLACE INTO `filehashes` VALUES (?,?,?,?);"
	var err error
	for alg, hash := range hashes {
		err = dbs.db.Exec(sql, dbs.imageName, path, alg, hex.EncodeToString(hash))
		if err != nil {
			fmt.Println(err)
		}
	}
}

// RemoveBlob removes an object from the store
func (dbs *dbStore) RemoveBlob(path string) error {
	return dbs.db.Exec("DELETE FROM `filemeta` WHERE `path`=? AND `namespace`=?", path, dbs.imageName)
}

func (dbs *dbStore) loadTargets(path string) map[string]data.FileMeta {
	var err error
	var r *sqlite3.Stmt
	files := make(map[string]data.FileMeta)
	sql := "SELECT `filemeta`.`path`, `size`, `alg`, `hash`, `custom` FROM `filemeta` JOIN `filehashes` ON `filemeta`.`path` = `filehashes`.`path` AND `filemeta`.`namespace` = `filehashes`.`namespace` WHERE `filemeta`.`namespace`=?"
	if path != "" {
		sql = fmt.Sprintf("%s %s", sql, "AND `filemeta`.`path`=?")
		r, err = dbs.db.Query(sql, dbs.imageName, path)
	} else {
		r, err = dbs.db.Query(sql, dbs.imageName)
	}
	for ; err == nil; err = r.Next() {
		var absPath, alg, hash string
		var size int64
		var custom json.RawMessage
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

func (dbs *dbStore) writeFile(name string, content []byte) error {
	fullPath := path.Join(tufLoc, dbs.imageName, name)
	dirPath := path.Dir(fullPath)
	err := os.MkdirAll(dirPath, 0744)
	if err != nil {
		return err
	}
	return ioutil.WriteFile(fullPath, content, 0744)
}

func (dbs *dbStore) readFile(name string) ([]byte, error) {
	fullPath := path.Join(tufLoc, dbs.imageName, name)
	content, err := ioutil.ReadFile(fullPath)
	return content, err
}

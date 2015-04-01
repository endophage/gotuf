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
	var absPath string
	var err error
	meta := make(map[string]json.RawMessage)
	files, err := ioutil.ReadDir(metadataDir)
	if err != nil {
		return nil, err
	}
	for _, file := range files {
		if strings.HasSuffix(file.Name(), ".json") {
			absPath = dbs.absPath(file.Name())
			data, err := dbs.readFile(absPath)
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
	absPath := dbs.absPath(name)
	return dbs.writeFile(absPath, meta)
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
	keys := []*data.Key{}
	absPath := dbs.absPath(role)
	var err error
	var r *sqlite3.Stmt
	sql := "SELECT `key` FROM `keys` WHERE `role` = ?;"
	r, err = dbs.db.Query(sql, absPath)
	for ; err == nil; err = r.Next() {
		var jsonStr string
		key := data.Key{}
		r.Scan(&role, &jsonStr)
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
	absPath := dbs.absPath(role)
	return dbs.db.Exec("INSERT INTO `keys` (`role`, `key`) VALUES (?,?);", absPath, string(jsonBytes))
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

func (dbs *dbStore) absPath(relPath string) string {
	return path.Join(dbs.imageName, relPath)
}

func (dbs *dbStore) writeFile(name string, content []byte) error {
	fullPath := path.Join(tufLoc, name)
	dirPath := path.Dir(fullPath)
	err := os.MkdirAll(dirPath, 0644)
	if err != nil {
		return err
	}
	return ioutil.WriteFile(fullPath, content, 0644)
}

func (dbs *dbStore) readFile(name string) ([]byte, error) {
	fullPath := path.Join(tufLoc, name)
	content, err := ioutil.ReadFile(fullPath)
	return content, err
}

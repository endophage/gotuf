package store

import (
	"encoding/json"
	//	"fmt"
	"testing"

	"github.com/endophage/go-tuf/data"
	"github.com/endophage/go-tuf/util"
)

// TestDBStore just ensures we can initialize an empty store.
// Nothing to test, just ensure no crashes :-)
func TestDBStore(t *testing.T) {
	db := util.GetSqliteDB()
	defer util.FlushDB(db)
	_ = DBStore(
		db,
		make(map[string]json.RawMessage),
	)
}

func TestLoadFiles(t *testing.T) {
	db := util.GetSqliteDB()
	defer util.FlushDB(db)
	store := DBStore(db, make(map[string]json.RawMessage))

	store.db.Exec("INSERT INTO `filemeta` VALUES (\"/foo.txt\", \"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855\", \"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855\", 0, \"\")")

	called := false
	check := func(path string, meta data.FileMeta) error {
		if called {
			t.Fatal("Store only has one item but check called > once.")
		} else {
			called = true
		}

		if path != "/foo.txt" {
			t.Fatal("Path is incorrect")
		}

		if meta.Length != 0 {
			t.Fatal("Length is incorrect")
		}

		if len(meta.Hashes) != 2 {
			t.Fatal("Hashes map has been modified")
		}

		return nil
	}
	store.WalkStagedTargets([]string{}, check)
	if !called {
		t.Fatal("Walk func never called")
	}
}

func TestAddBlob(t *testing.T) {
	db := util.GetSqliteDB()
	defer util.FlushDB(db)
	store := DBStore(db, make(map[string]json.RawMessage))
	meta := util.SampleMeta()
	store.AddBlob("/foo.txt", meta)

	called := false
	check := func(path string, meta data.FileMeta) error {
		if called {
			t.Fatal("Store only has one item but check called > once.")
		} else {
			called = true
		}

		if path != "/foo.txt" {
			t.Fatal("Path is incorrect")
		}

		if meta.Length != 1 {
			t.Fatal("Length is incorrect")
		}

		sha256, ok256 := meta.Hashes["sha256"]
		sha512, ok512 := meta.Hashes["sha512"]
		if len(meta.Hashes) != 2 || !ok256 || !ok512 {
			t.Fatal("Hashes map has been modified")
		}

		hash := data.HexBytes{0x01, 0x02}
		if sha256[0] != hash[0] || sha256[1] != hash[1] {
			t.Fatal("SHA256 has been modified")
		}
		hash = data.HexBytes{0x03, 0x04}
		if sha512[0] != hash[0] || sha512[1] != hash[1] {
			t.Fatal("SHA512 has been modified")
		}
		return nil
	}

	store.WalkStagedTargets([]string{}, check)

	if !called {
		t.Fatal("Walk func never called")
	}
}

func TestRemoveBlob(t *testing.T) {
	testPath := "/foo.txt"
	db := util.GetSqliteDB()
	defer util.FlushDB(db)
	store := DBStore(db, make(map[string]json.RawMessage))
	meta := util.SampleMeta()

	store.AddBlob(testPath, meta)

	called := false
	check := func(path string, meta data.FileMeta) error {
		called = true
		return nil
	}

	store.RemoveBlob(testPath)

	store.WalkStagedTargets([]string{}, check)

	if called {
		t.Fatal("Walk func called on empty db")
	}

}

func TestLoadFilesWithPath(t *testing.T) {
	db := util.GetSqliteDB()
	defer util.FlushDB(db)
	store := DBStore(db, make(map[string]json.RawMessage))
	meta := util.SampleMeta()

	store.AddBlob("/foo.txt", meta)
	store.AddBlob("/bar.txt", meta)

	called := false
	check := func(path string, meta data.FileMeta) error {
		if called {
			t.Fatal("Store only has one item but check called > once.")
		} else {
			called = true
		}

		if path != "/foo.txt" {
			t.Fatal("Path is incorrect")
		}

		return nil
	}

	store.WalkStagedTargets([]string{"/foo.txt"}, check)

	if !called {
		t.Fatal("Walk func never called")
	}
}

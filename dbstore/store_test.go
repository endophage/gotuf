package dbstore

import (
	"encoding/json"
	//	"fmt"
	"testing"

	"github.com/endophage/go-tuf/data"
)

// TestDBStore just ensures we can initialize an empty store.
// Nothing to test, just ensure no crashes :-)
func TestDBStore(t *testing.T) {
	_ = DBStore(
		make(map[string]json.RawMessage),
	)
}

//func TestGetMeta(t *testing.T) {
//	store := DBStore(
//		make(map[string]json.RawMessage),
//		map[string]data.FileMeta{
//			"test/path": data.FileMeta{
//				Length: 1,
//				Hashes: data.Hashes{"fake": data.HexBytes{0x01, 0x02}},
//			},
//		},
//	)
//
//	called := false
//	check := func(path string, meta data.FileMeta) error {
//		if called {
//			t.Fatal("Store only has one item but check called > once.")
//		} else {
//			called = true
//		}
//
//		if path != "test/path" {
//			t.Fatal("Path is incorrect")
//		}
//
//		if meta.Length != 1 {
//			t.Fatal("Length is incorrect")
//		}
//
//		fake, ok := meta.Hashes["fake"]
//		if len(meta.Hashes) != 1 || !ok {
//			t.Fatal("Hashes map has been modified")
//		}
//
//		hash := data.HexBytes{0x01, 0x02}
//		if fake[0] != hash[0] || fake[1] != hash[1] {
//			t.Fatal("Hash has been modified")
//		}
//		return nil
//	}
//
//	store.WalkStagedTargets([]string{}, check)
//}

func TestLoadFiles(t *testing.T) {
	store := DBStore(make(map[string]json.RawMessage))
	defer store.db.Exec("DELETE FROM `filemeta`;")

	store.db.Exec("INSERT INTO `filemeta` VALUES (\"/foo.txt\", \"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855\", 0, \"\")")

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

		_, ok := meta.Hashes["sha256"]
		if len(meta.Hashes) != 1 || !ok {
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
	store := DBStore(make(map[string]json.RawMessage))
	defer store.db.Exec("DELETE FROM `filemeta`;")
	meta := data.FileMeta{
		Length: 1,
		Hashes: data.Hashes{"sha256": data.HexBytes{0x01, 0x02}},
		Custom: &json.RawMessage{},
	}

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

		sha, ok := meta.Hashes["sha256"]
		if len(meta.Hashes) != 1 || !ok {
			t.Fatal("Hashes map has been modified")
		}

		hash := data.HexBytes{0x01, 0x02}
		if sha[0] != hash[0] || sha[1] != hash[1] {
			t.Fatal("Hash has been modified")
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
	store := DBStore(make(map[string]json.RawMessage))
	defer store.db.Exec("DELETE FROM `filemeta`;")
	meta := data.FileMeta{
		Length: 1,
		Hashes: data.Hashes{"sha256": data.HexBytes{0x01, 0x02}},
		Custom: &json.RawMessage{},
	}

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
	store := DBStore(make(map[string]json.RawMessage))
	defer store.db.Exec("DELETE FROM `filemeta`;")
	meta := data.FileMeta{
		Length: 1,
		Hashes: data.Hashes{"sha256": data.HexBytes{0x01, 0x02}},
		Custom: &json.RawMessage{},
	}

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

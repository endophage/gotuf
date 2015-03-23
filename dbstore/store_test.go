package dbstore

import (
	"encoding/json"
	"testing"

	"github.com/endophage/go-tuf/data"
)

// TestDBStore just ensures we can initialize an empty store.
// Nothing to test, just ensure no crashes :-)
func TestDBStore(t *testing.T) {
	_ = DBStore(
		make(map[string]json.RawMessage),
		make(map[string]data.FileMeta),
	)
}

func TestGetMeta(t *testing.T) {
	store := DBStore(
		make(map[string]json.RawMessage),
		map[string]data.FileMeta{
			"test/path": data.FileMeta{
				Length: 1,
				Hashes: data.Hashes{"fake": data.HexBytes{0x01, 0x02}},
			},
		},
	)

	called := false
	check := func(path string, meta data.FileMeta) error {
		if called {
			t.Fatal("Store only has one item but check called > once.")
		} else {
			called = true
		}

		if path != "test/path" {
			t.Fatal("Path is incorrect")
		}

		if meta.Length != 1 {
			t.Fatal("Length is incorrect")
		}

		fake, ok := meta.Hashes["fake"]
		if len(meta.Hashes) != 1 || !ok {
			t.Fatal("Hashes map has been modified")
		}

		hash := data.HexBytes{0x01, 0x02}
		if fake[0] != hash[0] || fake[1] != hash[1] {
			t.Fatal("Hash has been modified")
		}
		return nil
	}

	store.WalkStagedTargets([]string{}, check)
}
